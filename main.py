"""
Hệ thống Trình ký văn bản và Phê duyệt điện tử  (M15 + M20 + M21)
Chạy:  uvicorn main:app --reload
"""
import os, json, hashlib, hmac, secrets, sqlite3, random, base64, re, zipfile
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Request
from fastapi.responses import Response, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
UPLOADS = os.path.join(DATA, "uploads")
DB_PATH = os.path.join(DATA, "esign.db")
BACKUPS = os.path.join(DATA, "backups")
os.makedirs(UPLOADS, exist_ok=True)
os.makedirs(BACKUPS, exist_ok=True)

# Bật để hiện mã OTP ngay trên màn hình khi demo (thật thì gửi email/SMS). Đặt SHOW_OTP=0 để tắt.
SHOW_OTP = os.environ.get("SHOW_OTP", "1") == "1"


def load_key(name: str, size: int) -> bytes:
    """Khóa bí mật được tạo ngẫu nhiên lần chạy đầu và lưu vào data/."""
    path = os.path.join(DATA, name)
    if not os.path.exists(path):
        with open(path, "wb") as f:
            f.write(secrets.token_bytes(size))
    return open(path, "rb").read()


JWT_SECRET = load_key("jwt.key", 32).hex()
AES_KEY = load_key("aes.key", 32)  # 32 byte = AES-256

# ---------------------------------------------------------------- Cơ sở dữ liệu
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
  full_name TEXT NOT NULL, email TEXT, role TEXT NOT NULL,      -- user | manager | admin
  level INTEGER DEFAULT 0,                                      -- cấp duyệt: 1 Trưởng phòng, 2 Giám đốc
  active INTEGER DEFAULT 1,
  public_key TEXT, private_key_enc TEXT);                       -- khóa RSA (khóa riêng được mã hóa bằng mật khẩu)
CREATE TABLE IF NOT EXISTS documents(
  id INTEGER PRIMARY KEY, title TEXT NOT NULL, doc_type TEXT NOT NULL, owner_id INTEGER NOT NULL,
  filename TEXT NOT NULL, stored_path TEXT NOT NULL, confidential INTEGER DEFAULT 0,
  status TEXT NOT NULL,                                         -- draft|pending|signed|rejected|cancelled
  sha256 TEXT NOT NULL, current_step INTEGER DEFAULT 0, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS workflow_steps(
  id INTEGER PRIMARY KEY, doc_id INTEGER NOT NULL, step_order INTEGER NOT NULL, approver_id INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'waiting',                       -- waiting|signed|rejected
  signed_at TEXT, comment TEXT, hash_at_sign TEXT, method TEXT,
  signature TEXT, sig_payload TEXT, key_fingerprint TEXT);
CREATE TABLE IF NOT EXISTS workflow_templates(doc_type TEXT PRIMARY KEY, approver_ids TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS otps(id INTEGER PRIMARY KEY, user_id INTEGER, doc_id INTEGER,
  code_hash TEXT, expires TEXT, used INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY, user_id INTEGER, doc_id INTEGER,
  message TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS shares(
  id INTEGER PRIMARY KEY, sender_id INTEGER NOT NULL, title TEXT NOT NULL, message TEXT,
  filename TEXT NOT NULL, stored_path TEXT NOT NULL, confidential INTEGER DEFAULT 0,
  sha256 TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS share_recipients(
  share_id INTEGER NOT NULL, user_id INTEGER NOT NULL, read_at TEXT, PRIMARY KEY(share_id, user_id));
CREATE TABLE IF NOT EXISTS audit_logs(
  id INTEGER PRIMARY KEY, ts TEXT, user_id INTEGER, action TEXT, doc_id INTEGER, ip TEXT, detail TEXT,
  prev_hash TEXT, hash TEXT);
-- Audit log chỉ được thêm, không được sửa/xóa (ở tầng CSDL)
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_logs
  BEGIN SELECT RAISE(ABORT, 'Audit log chi duoc them, khong duoc sua'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_logs
  BEGIN SELECT RAISE(ABORT, 'Audit log chi duoc them, khong duoc xoa'); END;
"""


def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def hash_pw(pw: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(8)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()
    return f"{salt}${h}"


def check_pw(pw: str, stored: str) -> bool:
    salt, _ = stored.split("$")
    return hmac.compare_digest(hash_pw(pw, salt), stored)


def init_db():
    c = db()
    c.executescript(SCHEMA)
    for table, col in [("users", "position"), ("users", "public_key"), ("users", "private_key_enc"), ("workflow_steps", "signature"),
                       ("workflow_steps", "sig_payload"), ("workflow_steps", "key_fingerprint")]:  # nâng cấp CSDL cũ
        if col not in [r[1] for r in c.execute(f"PRAGMA table_info({table})")]:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {col} TEXT")
    if not c.execute("SELECT 1 FROM users").fetchone():
        seed = [("admin", "admin123", "Quản trị viên", "admin", 0),
                ("nhanvien", "123456", "Nguyễn Văn An", "user", 0),
                ("truongphong", "123456", "Trần Thị Bình", "manager", 1),
                ("giamdoc", "123456", "Lê Văn Cường", "manager", 2)]
        for u, p, n, r, lv in seed:
            c.execute("INSERT INTO users(username,password,full_name,email,role,level) VALUES(?,?,?,?,?,?)",
                      (u, hash_pw(p), n, f"{u}@example.com", r, lv))
        c.execute("INSERT INTO workflow_templates VALUES('Đơn từ','[3]')")
        c.execute("INSERT INTO workflow_templates VALUES('Quyết định','[3,4]')")
        c.execute("INSERT INTO workflow_templates VALUES('Công văn','[3,4]')")
    # tên cũ có kèm chức vụ trong ngoặc -> bỏ đi vì đã có cột chức vụ riêng
    for uname, old, new in [("nhanvien", "Nguyễn Văn An (Nhân viên)", "Nguyễn Văn An"),
                            ("truongphong", "Trần Thị Bình (Trưởng phòng)", "Trần Thị Bình"),
                            ("giamdoc", "Lê Văn Cường (Giám đốc)", "Lê Văn Cường")]:
        c.execute("UPDATE users SET full_name=? WHERE username=? AND full_name=?", (new, uname, old))
    c.execute("""UPDATE users SET position = CASE WHEN role='admin' THEN 'Quản trị viên'
                 WHEN role='manager' AND level=1 THEN 'Trưởng phòng' WHEN role='manager' AND level=2 THEN 'Giám đốc'
                 WHEN role='manager' THEN 'Người duyệt' ELSE 'Nhân viên' END
                 WHERE position IS NULL OR position=''""")
    c.commit(); c.close()


init_db()

# ---------------------------------------------------------------- M21: hash, mã hóa, audit log
# [M21] Hash SHA-256
def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# [M21] Mã hóa AES-256 khi lưu
def save_file(data: bytes, confidential: bool) -> str:
    """Tài liệu mật được mã hóa AES-256-GCM trước khi ghi xuống đĩa."""
    path = os.path.join(UPLOADS, secrets.token_hex(12))
    if confidential:
        nonce = os.urandom(12)
        data = nonce + AESGCM(AES_KEY).encrypt(nonce, data, None)
        path += ".enc"
    with open(path, "wb") as f:
        f.write(data)
    return path


def load_file(doc) -> bytes:
    raw = open(doc["stored_path"], "rb").read()
    if doc["confidential"]:
        return AESGCM(AES_KEY).decrypt(raw[:12], raw[12:], None)  # file bị sửa -> báo lỗi
    return raw


def read_verified(doc):
    """Đọc file và so hash với hash lúc upload. Trả về (ok, bytes|None)."""
    try:
        data = load_file(doc)
    except Exception:
        return False, None
    return sha256(data) == doc["sha256"], data


# [M21] Audit log nối chuỗi hash
def log(c, user_id, action, doc_id, ip, detail=""):
    """Mỗi dòng log chứa hash của dòng trước -> sửa 1 dòng là đứt chuỗi."""
    last = c.execute("SELECT hash FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
    prev, ts = (last["hash"] if last else "0" * 64), now()
    h = sha256(f"{prev}|{ts}|{user_id}|{action}|{doc_id}|{ip}|{detail}".encode())
    c.execute("INSERT INTO audit_logs(ts,user_id,action,doc_id,ip,detail,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?)",
              (ts, user_id, action, doc_id, ip, detail, prev, h))


def verify_chain(c) -> bool:
    prev = "0" * 64
    for r in c.execute("SELECT * FROM audit_logs ORDER BY id"):
        h = sha256(f"{prev}|{r['ts']}|{r['user_id']}|{r['action']}|{r['doc_id']}|{r['ip']}|{r['detail']}".encode())
        if r["prev_hash"] != prev or r["hash"] != h:
            return False
        prev = r["hash"]
    return True


# ---------------------------------------------------------------- M20: xác thực & phân quyền
app = FastAPI(title="E-Sign")


def current_user(request: Request):
    auth = request.headers.get("Authorization", "")
    try:
        uid = int(jwt.decode(auth.removeprefix("Bearer "), JWT_SECRET, algorithms=["HS256"])["sub"])
    except Exception:
        raise HTTPException(401, "Chưa đăng nhập hoặc phiên đã hết hạn")
    c = db()
    u = c.execute("SELECT * FROM users WHERE id=? AND active=1", (uid,)).fetchone()
    c.close()
    if not u:
        raise HTTPException(401, "Tài khoản không hợp lệ")
    return dict(u)


def require(*roles):
    def dep(u=Depends(current_user)):
        if u["role"] not in roles:
            raise HTTPException(403, "Bạn không có quyền thực hiện thao tác này")
        return u
    return dep


def ip_of(r: Request):
    return r.client.host if r.client else "?"


class LoginIn(BaseModel):
    username: str
    password: str


# [M20] Xác thực: đăng nhập, cấp JWT
@app.post("/api/login")
def login(b: LoginIn, request: Request):
    c = db()
    u = c.execute("SELECT * FROM users WHERE username=? AND active=1", (b.username,)).fetchone()
    if not u or not check_pw(b.password, u["password"]):
        log(c, u["id"] if u else None, "DANG_NHAP_SAI", None, ip_of(request), b.username)
        c.commit(); c.close()
        raise HTTPException(401, "Sai tên đăng nhập hoặc mật khẩu")
    log(c, u["id"], "DANG_NHAP", None, ip_of(request))
    c.commit(); c.close()
    token = jwt.encode({"sub": str(u["id"]), "exp": datetime.now(timezone.utc) + timedelta(hours=8)},
                       JWT_SECRET, algorithm="HS256")
    return {"token": token, "user": {k: u[k] for k in ("id", "username", "full_name", "role", "level")}}


# [M20] Xác thực: thông tin người đang đăng nhập
@app.get("/api/me")
def me(u=Depends(current_user)):
    return {k: u[k] for k in ("id", "username", "full_name", "role", "level")}


# [M20] Phân quyền: danh sách người duyệt
@app.get("/api/managers")
def managers(u=Depends(current_user)):
    c = db()
    rows = c.execute("SELECT id,full_name,position,level FROM users WHERE role='manager' AND active=1 ORDER BY level").fetchall()
    c.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------- Quản trị (Admin)
class UserIn(BaseModel):
    username: str
    password: str
    full_name: str
    role: str
    level: int = 0
    position: str = ""


class UserEdit(BaseModel):
    role: str
    level: int = 0
    active: bool = True
    position: str = ""


# [M20] Phân quyền: quản lý tài khoản (Admin)
@app.get("/api/admin/users")
def list_users(u=Depends(require("admin"))):
    c = db()
    rows = c.execute("SELECT id,username,full_name,position,role,level,active FROM users ORDER BY id").fetchall()
    c.close()
    return [dict(r) for r in rows]


# [M20] Phân quyền: quản lý tài khoản (Admin)
@app.post("/api/admin/users")
def create_user(b: UserIn, request: Request, u=Depends(require("admin"))):
    if b.role not in ("user", "manager", "admin") or len(b.password) < 6:
        raise HTTPException(400, "Vai trò không hợp lệ hoặc mật khẩu dưới 6 ký tự")
    c = db()
    try:
        pos = b.position.strip() or {"user": "Nhân viên", "manager": "Người duyệt", "admin": "Quản trị viên"}[b.role]
        c.execute("INSERT INTO users(username,password,full_name,email,role,level,position) VALUES(?,?,?,?,?,?,?)",
                  (b.username, hash_pw(b.password), b.full_name, f"{b.username}@example.com", b.role, b.level, pos))
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Tên đăng nhập đã tồn tại")
    log(c, u["id"], "TAO_TAI_KHOAN", None, ip_of(request), f"{b.username}/{b.role}")
    c.commit(); c.close()
    return {"ok": True}


# [M20] Phân quyền: đổi vai trò / khóa tài khoản (Admin)
@app.put("/api/admin/users/{uid}")
def edit_user(uid: int, b: UserEdit, request: Request, u=Depends(require("admin"))):
    if uid == u["id"] and (b.role != "admin" or not b.active):
        raise HTTPException(400, "Không thể tự hạ quyền hoặc khóa chính mình")
    c = db()
    c.execute("UPDATE users SET role=?, level=?, active=?, position=COALESCE(NULLIF(?, ''), position) WHERE id=?",
              (b.role, b.level, int(b.active), b.position.strip(), uid))
    log(c, u["id"], "SUA_TAI_KHOAN", None, ip_of(request), f"user {uid} -> {b.role}/L{b.level}/active={b.active}")
    c.commit(); c.close()
    return {"ok": True}


# [M15] Luồng ký: xem luồng mẫu
@app.get("/api/templates")
def templates(u=Depends(current_user)):
    c = db()
    rows = c.execute("SELECT * FROM workflow_templates").fetchall()
    c.close()
    return {r["doc_type"]: json.loads(r["approver_ids"]) for r in rows}


class TemplateIn(BaseModel):
    approver_ids: list[int]


# [M15] Luồng ký: cấu hình luồng mẫu (Admin)
@app.put("/api/admin/templates/{doc_type}")
def set_template(doc_type: str, b: TemplateIn, request: Request, u=Depends(require("admin"))):
    c = db()
    check_approvers(c, b.approver_ids)
    c.execute("INSERT OR REPLACE INTO workflow_templates VALUES(?,?)", (doc_type, json.dumps(b.approver_ids)))
    log(c, u["id"], "SUA_LUONG_MAU", None, ip_of(request), f"{doc_type}: {b.approver_ids}")
    c.commit(); c.close()
    return {"ok": True}


# [M21] Bảo mật: xem nhật ký và kiểm tra chuỗi hash (Admin)
@app.get("/api/admin/audit")
def audit(limit: int = 200, u=Depends(require("admin"))):
    c = db()
    rows = c.execute("""SELECT a.*, u.full_name FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id
                        ORDER BY a.id DESC LIMIT ?""", (limit,)).fetchall()
    ok = verify_chain(c)
    c.close()
    return {"chain_ok": ok, "rows": [dict(r) for r in rows]}


# ---------------------------------------------------------------- M15: văn bản & luồng trình ký
LABEL = {"draft": "Nháp", "pending": "Đang chờ ký", "signed": "Đã ký", "rejected": "Từ chối", "cancelled": "Hủy"}


def check_approvers(c, ids):
    if not ids:
        raise HTTPException(400, "Cần ít nhất 1 người duyệt")
    for i in ids:
        r = c.execute("SELECT role FROM users WHERE id=? AND active=1", (i,)).fetchone()
        if not r or r["role"] != "manager":
            raise HTTPException(400, f"Người duyệt id={i} không hợp lệ (phải là Manager)")


def notify(c, user_id, doc_id, msg):
    c.execute("INSERT INTO notifications(user_id,doc_id,message,created_at) VALUES(?,?,?,?)",
              (user_id, doc_id, msg, now()))


def get_doc(c, doc_id):
    d = c.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    if not d:
        raise HTTPException(404, "Không tìm thấy văn bản")
    return d


def get_steps(c, doc_id):
    return c.execute("""SELECT s.*, u.full_name, u.position FROM workflow_steps s JOIN users u ON u.id=s.approver_id
                        WHERE doc_id=? ORDER BY step_order""", (doc_id,)).fetchall()


def can_view(c, d, u):
    if u["role"] == "admin" or d["owner_id"] == u["id"]:
        return True
    return bool(c.execute("SELECT 1 FROM workflow_steps WHERE doc_id=? AND approver_id=?", (d["id"], u["id"])).fetchone()) \
        and d["status"] != "draft"


def current_approver(c, d):
    if d["status"] != "pending":
        return None
    r = c.execute("SELECT approver_id FROM workflow_steps WHERE doc_id=? AND step_order=?",
                  (d["id"], d["current_step"])).fetchone()
    return r["approver_id"] if r else None


def doc_json(c, d, u, with_steps=False):
    owner = c.execute("SELECT full_name FROM users WHERE id=?", (d["owner_id"],)).fetchone()
    out = {k: d[k] for k in ("id", "title", "doc_type", "filename", "status", "sha256", "current_step", "created_at")}
    out.update(confidential=bool(d["confidential"]), status_label=LABEL[d["status"]], owner=owner["full_name"],
               is_owner=d["owner_id"] == u["id"], can_sign=current_approver(c, d) == u["id"])
    if with_steps:
        out["steps"] = [dict(s) for s in get_steps(c, d["id"])]
    return out


# [M15] Văn bản: tạo mới / danh sách (có tính hash + mã hóa của M21)
@app.post("/api/docs")
async def create_doc(request: Request, title: str = Form(...), doc_type: str = Form(...),
                     confidential: str = Form("false"), approvers: str = Form(""),
                     file: UploadFile = File(...), u=Depends(current_user)):
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in (".pdf", ".doc", ".docx"):
        raise HTTPException(400, "Chỉ nhận file PDF hoặc Word")
    data = await file.read()
    if not data or len(data) > 10 * 1024 * 1024:
        raise HTTPException(400, "File rỗng hoặc lớn hơn 10MB")
    c = db()
    ids = [int(x) for x in approvers.split(",") if x.strip()]
    if not ids:  # dùng luồng mẫu theo loại văn bản
        t = c.execute("SELECT approver_ids FROM workflow_templates WHERE doc_type=?", (doc_type,)).fetchone()
        ids = json.loads(t["approver_ids"]) if t else []
    check_approvers(c, ids)
    conf = confidential.lower() == "true"
    h = sha256(data)
    cur = c.execute("""INSERT INTO documents(title,doc_type,owner_id,filename,stored_path,confidential,status,sha256,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (title, doc_type, u["id"], file.filename, save_file(data, conf), int(conf), "draft", h, now()))
    doc_id = cur.lastrowid
    for i, a in enumerate(ids, 1):
        c.execute("INSERT INTO workflow_steps(doc_id,step_order,approver_id) VALUES(?,?,?)", (doc_id, i, a))
    log(c, u["id"], "TAO_VAN_BAN", doc_id, ip_of(request), f"sha256={h}; mat={conf}")
    c.commit(); c.close()
    return {"id": doc_id, "sha256": h}


# [M15] Văn bản: tạo mới / danh sách (có tính hash + mã hóa của M21)
@app.get("/api/docs")
def list_docs(scope: str = "mine", u=Depends(current_user)):
    c = db()
    if scope == "mine":
        rows = c.execute("SELECT * FROM documents WHERE owner_id=? ORDER BY id DESC", (u["id"],)).fetchall()
    elif scope == "inbox":
        rows = c.execute("""SELECT d.* FROM documents d JOIN workflow_steps s ON s.doc_id=d.id
                            WHERE d.status='pending' AND s.step_order=d.current_step AND s.approver_id=?
                            ORDER BY d.id DESC""", (u["id"],)).fetchall()
    elif scope == "handled":
        rows = c.execute("""SELECT DISTINCT d.* FROM documents d JOIN workflow_steps s ON s.doc_id=d.id
                            WHERE s.approver_id=? AND s.status!='waiting' ORDER BY d.id DESC""", (u["id"],)).fetchall()
    elif scope == "all" and u["role"] == "admin":
        rows = c.execute("SELECT * FROM documents ORDER BY id DESC").fetchall()
    else:
        raise HTTPException(403, "Không có quyền xem danh sách này")
    out = [doc_json(c, d, u) for d in rows]
    c.close()
    return out


# [M15] Văn bản: chi tiết và tiến độ ký
@app.get("/api/docs/{doc_id}")
def doc_detail(doc_id: int, u=Depends(current_user)):
    c = db()
    d = get_doc(c, doc_id)
    if not can_view(c, d, u):
        raise HTTPException(403, "Bạn không có quyền xem văn bản này")
    out = doc_json(c, d, u, True)
    c.close()
    return out


# [M21] Toàn vẹn: xem file, so hash trước khi trả về
@app.get("/api/docs/{doc_id}/file")
def doc_file(doc_id: int, request: Request, u=Depends(current_user)):
    c = db()
    d = get_doc(c, doc_id)
    if not can_view(c, d, u):
        raise HTTPException(403, "Bạn không có quyền xem văn bản này")
    ok, data = read_verified(d)
    log(c, u["id"], "XEM_FILE" if ok else "LOI_TOAN_VEN", doc_id, ip_of(request))
    c.commit(); c.close()
    if not ok:
        raise HTTPException(409, "CẢNH BÁO: file đã bị thay đổi, hash không khớp với lúc upload")
    ctype = "application/pdf" if d["filename"].lower().endswith(".pdf") else "application/octet-stream"
    return Response(data, media_type=ctype)


# [M21] Toàn vẹn: kiểm tra hash theo yêu cầu
@app.get("/api/docs/{doc_id}/verify")
def verify(doc_id: int, u=Depends(current_user)):
    c = db()
    d = get_doc(c, doc_id)
    if not can_view(c, d, u):
        raise HTTPException(403, "Bạn không có quyền xem văn bản này")
    ok, data = read_verified(d)
    c.close()
    return {"ok": ok, "stored_hash": d["sha256"], "current_hash": sha256(data) if data else None}


def owner_action(doc_id, u, allowed):
    c = db()
    d = get_doc(c, doc_id)
    if d["owner_id"] != u["id"]:
        raise HTTPException(403, "Chỉ người tạo mới được thao tác")
    if d["status"] not in allowed:
        raise HTTPException(409, f"Không thể thực hiện khi văn bản đang ở trạng thái '{LABEL[d['status']]}'")
    return c, d


# [M15] Luồng ký: gửi trình ký
@app.post("/api/docs/{doc_id}/submit")
def submit(doc_id: int, request: Request, u=Depends(current_user)):
    c, d = owner_action(doc_id, u, ("draft",))
    ok, _ = read_verified(d)
    if not ok:
        raise HTTPException(409, "File không toàn vẹn, không thể trình ký")
    c.execute("UPDATE documents SET status='pending', current_step=1 WHERE id=?", (doc_id,))
    first = c.execute("SELECT approver_id FROM workflow_steps WHERE doc_id=? AND step_order=1", (doc_id,)).fetchone()
    notify(c, first["approver_id"], doc_id, f"Có văn bản cần duyệt: {d['title']}")
    log(c, u["id"], "TRINH_KY", doc_id, ip_of(request))
    c.commit(); c.close()
    return {"ok": True}


# [M15] Luồng ký: hủy văn bản
@app.post("/api/docs/{doc_id}/cancel")
def cancel(doc_id: int, request: Request, u=Depends(current_user)):
    c, d = owner_action(doc_id, u, ("draft", "pending"))
    c.execute("UPDATE documents SET status='cancelled' WHERE id=?", (doc_id,))
    log(c, u["id"], "HUY_VAN_BAN", doc_id, ip_of(request))
    c.commit(); c.close()
    return {"ok": True}


def approver_context(doc_id, u):
    c = db()
    d = get_doc(c, doc_id)
    if current_approver(c, d) != u["id"]:
        raise HTTPException(403, "Chưa đến lượt bạn duyệt văn bản này")
    return c, d


# [M20] Xác thực nâng cao: cấp mã OTP để ký
@app.post("/api/docs/{doc_id}/otp")
def request_otp(doc_id: int, request: Request, u=Depends(current_user)):
    c, d = approver_context(doc_id, u)
    code = f"{random.SystemRandom().randint(0, 999999):06d}"
    c.execute("UPDATE otps SET used=1 WHERE user_id=? AND doc_id=?", (u["id"], doc_id))  # OTP cũ hết hiệu lực
    c.execute("INSERT INTO otps(user_id,doc_id,code_hash,expires) VALUES(?,?,?,?)",
              (u["id"], doc_id, sha256(code.encode()), (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")))
    log(c, u["id"], "YEU_CAU_OTP", doc_id, ip_of(request))
    c.commit(); c.close()
    print(f"[OTP] gửi tới {u['username']}: {code} (hết hạn sau 5 phút)")  # thay bằng gửi email/SMS khi triển khai thật
    return {"message": "Đã gửi mã OTP, hiệu lực 5 phút", **({"dev_otp": code} if SHOW_OTP else {})}


class SignIn(BaseModel):
    otp: str
    password: str = ""
    comment: str = ""


def PSS():
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def fingerprint(pub_pem: str) -> str:
    return sha256(pub_pem.encode())[:16]


# [M15] Chữ ký số RSA-2048: khóa riêng được mã hóa bằng mật khẩu người dùng, cần mật khẩu mới ký được
def get_signing_key(c, user, password):
    if not user["private_key_enc"]:  # lần ký đầu tiên: tạo cặp khóa
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.BestAvailableEncryption(password.encode())).decode()
        pub = key.public_key().public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        c.execute("UPDATE users SET public_key=?, private_key_enc=? WHERE id=?", (pub, priv, user["id"]))
        return key, pub
    key = serialization.load_pem_private_key(user["private_key_enc"].encode(), password=password.encode())
    return key, user["public_key"]


# [M15] Ký duyệt (kiểm tra [M21] hash + mật khẩu + [M20] OTP, rồi ký số lên hash của văn bản)
@app.post("/api/docs/{doc_id}/sign")
def sign(doc_id: int, b: SignIn, request: Request, u=Depends(current_user)):
    c, d = approver_context(doc_id, u)
    ip = ip_of(request)
    ok, _ = read_verified(d)  # kiểm tra toàn vẹn TRƯỚC khi ký
    if not ok:
        log(c, u["id"], "LOI_TOAN_VEN", doc_id, ip, "chan ky vi hash khong khop")
        c.commit(); c.close()
        raise HTTPException(409, "CẢNH BÁO: file đã bị thay đổi, hệ thống từ chối cho ký")
    if not check_pw(b.password, u["password"]):
        log(c, u["id"], "KY_SAI_MAT_KHAU", doc_id, ip)
        c.commit(); c.close()
        raise HTTPException(400, "Mật khẩu xác nhận không đúng")
    o = c.execute("SELECT * FROM otps WHERE user_id=? AND doc_id=? AND used=0 ORDER BY id DESC LIMIT 1",
                  (u["id"], doc_id)).fetchone()
    if not o or o["expires"] < now() or not hmac.compare_digest(o["code_hash"], sha256(b.otp.strip().encode())):
        log(c, u["id"], "OTP_SAI", doc_id, ip)
        c.commit(); c.close()
        raise HTTPException(400, "Mã OTP sai hoặc đã hết hạn")
    ts = now()
    key, pub = get_signing_key(c, u, b.password)
    payload = json.dumps({"doc_id": doc_id, "sha256": d["sha256"], "step": d["current_step"],
                          "signer_id": u["id"], "time": ts}, sort_keys=True, separators=(",", ":"))
    sig = base64.b64encode(key.sign(payload.encode(), PSS(), hashes.SHA256())).decode()
    c.execute("UPDATE otps SET used=1 WHERE id=?", (o["id"],))
    c.execute("""UPDATE workflow_steps SET status='signed', signed_at=?, comment=?, hash_at_sign=?, method=?,
                 signature=?, sig_payload=?, key_fingerprint=? WHERE doc_id=? AND step_order=?""",
              (ts, b.comment, d["sha256"], "OTP + Chữ ký số RSA", sig, payload, fingerprint(pub), doc_id, d["current_step"]))
    nxt = c.execute("SELECT approver_id FROM workflow_steps WHERE doc_id=? AND step_order=?",
                    (doc_id, d["current_step"] + 1)).fetchone()
    if nxt:
        c.execute("UPDATE documents SET current_step=current_step+1 WHERE id=?", (doc_id,))
        notify(c, nxt["approver_id"], doc_id, f"Có văn bản cần duyệt: {d['title']}")
    else:
        c.execute("UPDATE documents SET status='signed' WHERE id=?", (doc_id,))
        notify(c, d["owner_id"], doc_id, f"Văn bản '{d['title']}' đã được ký duyệt hoàn tất")
    log(c, u["id"], "KY_DUYET", doc_id, ip, f"buoc {d['current_step']}; sha256={d['sha256']}; khoa={fingerprint(pub)}")
    c.commit(); c.close()
    return {"ok": True, "completed": nxt is None}


# [M15] Chữ ký số: kiểm tra lại từng chữ ký bằng khóa công khai của người ký
@app.get("/api/docs/{doc_id}/signatures")
def signatures(doc_id: int, u=Depends(current_user)):
    c = db()
    d = get_doc(c, doc_id)
    if not can_view(c, d, u):
        raise HTTPException(403, "Bạn không có quyền xem văn bản này")
    file_ok, _ = read_verified(d)
    out = []
    for s in get_steps(c, doc_id):
        if s["status"] != "signed":
            continue
        r = {"step": s["step_order"], "signer": s["full_name"], "signed_at": s["signed_at"],
             "fingerprint": s["key_fingerprint"], "valid": False}
        if not s["signature"]:
            r["reason"] = "Bước này chỉ ký bằng OTP, không có chữ ký số"
        else:
            pem = c.execute("SELECT public_key FROM users WHERE id=?", (s["approver_id"],)).fetchone()["public_key"]
            try:
                serialization.load_pem_public_key(pem.encode()).verify(
                    base64.b64decode(s["signature"]), s["sig_payload"].encode(), PSS(), hashes.SHA256())
                if not file_ok or json.loads(s["sig_payload"])["sha256"] != d["sha256"]:
                    r["reason"] = "Chữ ký đúng nhưng file đã bị thay đổi sau khi ký"
                else:
                    r["valid"] = True
            except (InvalidSignature, ValueError, TypeError, AttributeError):
                r["reason"] = "Chữ ký không hợp lệ"
        out.append(r)
    c.close()
    return out


class RejectIn(BaseModel):
    reason: str


# [M15] Luồng ký: từ chối kèm lý do
@app.post("/api/docs/{doc_id}/reject")
def reject(doc_id: int, b: RejectIn, request: Request, u=Depends(current_user)):
    if not b.reason.strip():
        raise HTTPException(400, "Cần nhập lý do từ chối")
    c, d = approver_context(doc_id, u)
    c.execute("UPDATE workflow_steps SET status='rejected', signed_at=?, comment=? WHERE doc_id=? AND step_order=?",
              (now(), b.reason, doc_id, d["current_step"]))
    c.execute("UPDATE documents SET status='rejected' WHERE id=?", (doc_id,))
    notify(c, d["owner_id"], doc_id, f"Văn bản '{d['title']}' bị từ chối: {b.reason}")
    log(c, u["id"], "TU_CHOI", doc_id, ip_of(request), b.reason)
    c.commit(); c.close()
    return {"ok": True}


# [M15] Thông báo cho người duyệt
@app.get("/api/notifications")
def notifications(u=Depends(current_user)):
    c = db()
    rows = c.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 20", (u["id"],)).fetchall()
    c.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------- Danh bạ & gửi file cho đồng nghiệp
# [M20] Danh bạ: tên và chức vụ mọi người trong công ty
@app.get("/api/directory")
def directory(u=Depends(current_user)):
    c = db()
    rows = c.execute("SELECT id, full_name, position FROM users WHERE active=1 ORDER BY full_name COLLATE NOCASE").fetchall()
    c.close()
    return [dict(r, me=(r["id"] == u["id"])) for r in rows]


# [M15] Gửi file: một file đến nhiều người ([M21] có hash, mã hóa AES nếu là tài liệu mật, ghi nhật ký)
@app.post("/api/shares")
async def send_share(request: Request, title: str = Form(...), message: str = Form(""), recipients: str = Form(...),
                     confidential: str = Form("false"), file: UploadFile = File(...), u=Depends(current_user)):
    if not title.strip():
        raise HTTPException(400, "Cần nhập tiêu đề")
    if os.path.splitext(file.filename)[1].lower() not in (".pdf", ".doc", ".docx"):
        raise HTTPException(400, "Chỉ nhận file PDF hoặc Word")
    data = await file.read()
    if not data or len(data) > 10 * 1024 * 1024:
        raise HTTPException(400, "File rỗng hoặc lớn hơn 10MB")
    ids = sorted({int(x) for x in recipients.split(",") if x.strip().isdigit()} - {u["id"]})
    if not ids or len(ids) > 200:
        raise HTTPException(400, "Cần chọn từ 1 đến 200 người nhận (không tính chính bạn)")
    c = db()
    n = c.execute(f"SELECT COUNT(*) n FROM users WHERE active=1 AND id IN ({','.join('?' * len(ids))})", ids).fetchone()["n"]
    if n != len(ids):
        raise HTTPException(400, "Có người nhận không hợp lệ")
    conf = confidential.lower() == "true"
    h = sha256(data)
    cur = c.execute("""INSERT INTO shares(sender_id,title,message,filename,stored_path,confidential,sha256,created_at)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (u["id"], title.strip(), message.strip(), file.filename, save_file(data, conf), int(conf), h, now()))
    sid = cur.lastrowid
    for i in ids:
        c.execute("INSERT INTO share_recipients(share_id,user_id) VALUES(?,?)", (sid, i))
        notify(c, i, None, f"{u['full_name']} đã gửi cho bạn file: {title.strip()}")
    log(c, u["id"], "GUI_FILE", None, ip_of(request), f"share={sid}; nguoi nhan={ids}; sha256={h}; mat={conf}")
    c.commit(); c.close()
    return {"id": sid, "recipients": len(ids)}


# [M15] Hộp thư: file đã nhận / đã gửi (người gửi thấy ai đã xem)
@app.get("/api/shares")
def list_shares(box: str = "inbox", u=Depends(current_user)):
    c = db()
    if box == "inbox":
        rows = c.execute("""SELECT s.id, s.title, s.message, s.filename, s.confidential, s.created_at, r.read_at,
                            us.full_name AS sender, us.position AS sender_position
                            FROM shares s JOIN share_recipients r ON r.share_id=s.id JOIN users us ON us.id=s.sender_id
                            WHERE r.user_id=? ORDER BY s.id DESC""", (u["id"],)).fetchall()
        out = [dict(r, confidential=bool(r["confidential"])) for r in rows]
    elif box == "sent":
        out = []
        for s in c.execute("""SELECT id,title,message,filename,confidential,created_at FROM shares
                              WHERE sender_id=? ORDER BY id DESC""", (u["id"],)).fetchall():
            rc = c.execute("""SELECT us.full_name, us.position, r.read_at FROM share_recipients r
                              JOIN users us ON us.id=r.user_id WHERE r.share_id=? ORDER BY us.full_name""", (s["id"],)).fetchall()
            out.append(dict(s, confidential=bool(s["confidential"]), recipients=[dict(x) for x in rc]))
    else:
        raise HTTPException(400, "box phải là inbox hoặc sent")
    c.close()
    return out


# [M21] Xem file được gửi: so hash trước khi trả về; người nhận mở file thì đánh dấu "đã xem"
@app.get("/api/shares/{sid}/file")
def share_file(sid: int, request: Request, u=Depends(current_user)):
    c = db()
    s = c.execute("SELECT * FROM shares WHERE id=?", (sid,)).fetchone()
    if not s:
        raise HTTPException(404, "Không tìm thấy file")
    is_rec = c.execute("SELECT 1 FROM share_recipients WHERE share_id=? AND user_id=?", (sid, u["id"])).fetchone()
    if s["sender_id"] != u["id"] and not is_rec:
        raise HTTPException(403, "Bạn không có quyền xem file này")
    ok, data = read_verified(s)
    log(c, u["id"], "XEM_FILE_GUI" if ok else "LOI_TOAN_VEN", None, ip_of(request), f"share={sid}")
    if ok and is_rec:
        c.execute("UPDATE share_recipients SET read_at=COALESCE(read_at, ?) WHERE share_id=? AND user_id=?", (now(), sid, u["id"]))
    c.commit(); c.close()
    if not ok:
        raise HTTPException(409, "CẢNH BÁO: file đã bị thay đổi, hash không khớp với lúc gửi")
    ctype = "application/pdf" if s["filename"].lower().endswith(".pdf") else "application/octet-stream"
    return Response(data, media_type=ctype)


# ---------------------------------------------------------------- [M21] Sao lưu & khôi phục (Admin)
BK_NAME = re.compile(r"^backup-[0-9A-Za-z_-]+\.zip$")


def make_backup(tag: str = "backup") -> str:
    """Nén CSDL (ảnh chụp nhất quán) + file upload + manifest chứa hash từng file."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    name, n = f"{tag}-{stamp}.zip", 1
    while os.path.exists(os.path.join(BACKUPS, name)):
        n += 1
        name = f"{tag}-{stamp}-{n}.zip"
    snap = os.path.join(DATA, "snapshot.tmp")
    src, dst = db(), sqlite3.connect(snap)
    src.backup(dst)
    src.close(); dst.close()
    with open(snap, "rb") as f:
        files = {"esign.db": f.read()}
    os.remove(snap)
    for f in sorted(os.listdir(UPLOADS)):
        with open(os.path.join(UPLOADS, f), "rb") as fh:
            files["uploads/" + f] = fh.read()
    manifest = {"created_at": now(), "aes_key_sha256": sha256(AES_KEY), "files": {k: sha256(v) for k, v in files.items()}}
    with zipfile.ZipFile(os.path.join(BACKUPS, name), "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps(manifest, indent=1))
        for k, v in files.items():
            z.writestr(k, v)
    return name


def bk_path(name: str) -> str:
    p = os.path.join(BACKUPS, name)
    if not BK_NAME.match(name) or not os.path.exists(p):
        raise HTTPException(404, "Không tìm thấy bản sao lưu")
    return p


def restore_backup(name: str) -> str:
    """Kiểm tra hash từng file trong bản sao lưu, rồi mới ghi đè dữ liệu hiện tại. Trả về tên bản lưu an toàn."""
    path, files = bk_path(name), {}
    try:
        with zipfile.ZipFile(path) as z:
            manifest = json.loads(z.read("manifest.json"))
            for k, h in manifest["files"].items():
                if not (k == "esign.db" or (k.startswith("uploads/") and k[8:] and os.path.basename(k[8:]) == k[8:])):
                    raise ValueError("tên file lạ: " + k)
                data = z.read(k)
                if sha256(data) != h:
                    raise ValueError("file bị hỏng hoặc bị sửa: " + k)
                files[k] = data
    except Exception as e:
        raise HTTPException(409, f"Bản sao lưu không hợp lệ ({e})")
    if "esign.db" not in files:
        raise HTTPException(409, "Bản sao lưu không có cơ sở dữ liệu")
    if manifest.get("aes_key_sha256") != sha256(AES_KEY):
        raise HTTPException(409, "Bản sao lưu thuộc hệ thống khác (khác khóa AES), không thể khôi phục")
    snap = os.path.join(DATA, "restore.tmp")
    with open(snap, "wb") as f:
        f.write(files["esign.db"])
    src = sqlite3.connect(snap)
    try:
        if src.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise HTTPException(409, "Cơ sở dữ liệu trong bản sao lưu bị hỏng")
        safety = make_backup("backup-truoc-khoi-phuc")  # giữ lại trạng thái hiện tại phòng khi cần quay lại
        dst = db()
        src.backup(dst)
        dst.close()
    finally:
        src.close()
        os.remove(snap)
    for f in os.listdir(UPLOADS):
        os.remove(os.path.join(UPLOADS, f))
    for k, v in files.items():
        if k.startswith("uploads/"):
            with open(os.path.join(UPLOADS, k[8:]), "wb") as fh:
                fh.write(v)
    init_db()
    return safety


# [M21] Sao lưu: danh sách / tạo / tải về / khôi phục (Admin)
@app.get("/api/admin/backups")
def list_backups(u=Depends(require("admin"))):
    out = []
    for f in os.listdir(BACKUPS):
        if BK_NAME.match(f):
            p = os.path.join(BACKUPS, f)
            out.append({"name": f, "size": os.path.getsize(p),
                        "created": datetime.fromtimestamp(os.path.getmtime(p), timezone.utc).strftime("%Y-%m-%d %H:%M:%S")})
    return sorted(out, key=lambda x: x["created"], reverse=True)


@app.post("/api/admin/backups")
def create_backup(request: Request, u=Depends(require("admin"))):
    c = db()
    log(c, u["id"], "SAO_LUU", None, ip_of(request))
    c.commit(); c.close()
    name = make_backup()
    return {"name": name, "size": os.path.getsize(os.path.join(BACKUPS, name))}


@app.get("/api/admin/backups/{name}/download")
def download_backup(name: str, request: Request, u=Depends(require("admin"))):
    p = bk_path(name)
    c = db()
    log(c, u["id"], "TAI_BAN_SAO_LUU", None, ip_of(request), name)
    c.commit(); c.close()
    return FileResponse(p, media_type="application/zip", filename=name)


@app.post("/api/admin/backups/{name}/restore")
def restore(name: str, request: Request, u=Depends(require("admin"))):
    safety = restore_backup(name)
    c = db()
    log(c, u["id"], "KHOI_PHUC", None, ip_of(request), f"tu {name}; ban an toan: {safety}")
    chain = verify_chain(c)
    c.commit(); c.close()
    return {"ok": True, "safety_backup": safety, "chain_ok": chain}


app.mount("/", StaticFiles(directory=os.path.join(BASE, "static"), html=True), name="static")


if __name__ == "__main__":  # cho phép chạy bằng: python main.py
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
