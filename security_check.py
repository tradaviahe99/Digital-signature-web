"""
Kiểm tra bảo mật tự động cho hệ thống trình ký.

Cách dùng (khi server đang chạy ở http://127.0.0.1:8000):
    python security_check.py
    python security_check.py --pha-nhat-ky     # thêm kịch bản "kẻ gian sửa nhật ký" (làm hỏng nhật ký, xem README)

Script chỉ dùng thư viện có sẵn của Python. Nó tạo vài văn bản thử và 1 tài khoản "khach..." trong hệ thống.
Các bước cần OTP sẽ bị bỏ qua nếu server chạy với SHOW_OTP=0.
"""
import base64, json, os, sqlite3, sys, uuid, zipfile
import urllib.error, urllib.request

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

BASE = os.environ.get("BASE", "http://127.0.0.1:8000")
HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "data", "esign.db")
BACKUPS = os.path.join(HERE, "data", "backups")
PDF = b"%PDF-1.4 noi dung kiem tra bao mat"
results = []


def check(name, ok):
    ok = bool(ok)
    results.append(ok)
    print(("  [DAT]  " if ok else "  [LOI]  ") + name)


def skip(name):
    print("  [BO QUA] " + name + " (server đang tắt hiển thị OTP)")


def call(method, path, token=None, body=None, raw=None, ctype=None):
    req = urllib.request.Request(BASE + path, method=method)
    data = None
    if token:
        req.add_header("Authorization", "Bearer " + token)
    if body is not None:
        data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    if raw is not None:
        data = raw
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, data) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def js(b):
    try:
        return json.loads(b)
    except Exception:
        return {}


def multipart(fields, filename, content):
    b = uuid.uuid4().hex
    parts = [f'--{b}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode() for k, v in fields.items()]
    parts.append(f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                 f'Content-Type: application/octet-stream\r\n\r\n'.encode() + content + b"\r\n")
    parts.append(f"--{b}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={b}"


def login(u, p):
    s, b = call("POST", "/api/login", body={"username": u, "password": p})
    return js(b).get("token") if s == 200 else None


def new_doc(tok, doc_type="Đơn từ", conf=False, filename="a.pdf"):
    raw, ct = multipart({"title": "Kiểm tra bảo mật", "doc_type": doc_type, "confidential": "true" if conf else "false"},
                        filename, PDF)
    s, b = call("POST", "/api/docs", tok, raw=raw, ctype=ct)
    return s, js(b).get("id")


def submit(tok, doc_id):
    return call("POST", f"/api/docs/{doc_id}/submit", tok)[0]


def get_otp(tok, doc_id):
    s, b = call("POST", f"/api/docs/{doc_id}/otp", tok)
    return s, js(b).get("dev_otp")


def stored_path(doc_id, table="documents"):
    c = sqlite3.connect(DB)
    p = c.execute(f"SELECT stored_path FROM {table} WHERE id=?", (doc_id,)).fetchone()[0]
    c.close()
    return p


def tamper(path):
    with open(path, "ab") as f:  # thêm 1 byte vào cuối file
        f.write(b"x")


def sign(tok, doc_id, otp, pw):
    return call("POST", f"/api/docs/{doc_id}/sign", tok, body={"otp": otp, "password": pw, "comment": "kiem tra"})[0]


def main():
    try:
        nv, tp, gd, ad = (login(*x) for x in [("nhanvien", "123456"), ("truongphong", "123456"),
                                               ("giamdoc", "123456"), ("admin", "admin123")])
    except urllib.error.URLError:
        print(f"Không kết nối được tới {BASE}. Hãy chạy server trước (python main.py).")
        sys.exit(1)
    if not all([nv, tp, gd, ad]):
        print("Không đăng nhập được bằng 4 tài khoản mẫu. Nếu bạn đã đổi mật khẩu, hãy xóa thư mục data/ rồi chạy lại server.")
        sys.exit(1)

    print("\n== M20: xác thực và phân quyền ==")
    check("Không có token thì bị từ chối (401)", call("GET", "/api/me")[0] == 401)
    check("Token bị sửa 1 ký tự thì bị từ chối (401)", call("GET", "/api/me", nv[:-1] + ("A" if nv[-1] != "A" else "B"))[0] == 401)
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    fake = enc({"alg": "none", "typ": "JWT"}) + "." + enc({"sub": "1"}) + "."
    check("Token giả không có chữ ký (alg=none) bị từ chối (401)", call("GET", "/api/me", fake)[0] == 401)
    check("Sai mật khẩu thì không đăng nhập được (401)", call("POST", "/api/login", body={"username": "nhanvien", "password": "sai"})[0] == 401)
    check("Thử SQL injection ở ô đăng nhập không có tác dụng (401)",
          call("POST", "/api/login", body={"username": "' OR '1'='1' --", "password": "x"})[0] == 401)
    check("Nhân viên gọi API của Admin bị chặn (403)", call("GET", "/api/admin/users", nv)[0] == 403)
    check("Nhân viên không xem được nhật ký bảo mật (403)", call("GET", "/api/admin/audit", nv)[0] == 403)
    check("Người duyệt (Manager) gọi API của Admin bị chặn (403)", call("GET", "/api/admin/users", tp)[0] == 403)
    check("Nhân viên không tạo được bản sao lưu (403)", call("POST", "/api/admin/backups", nv)[0] == 403)
    name = "khach" + uuid.uuid4().hex[:4]
    call("POST", "/api/admin/users", ad, body={"username": name, "password": "abcdef", "full_name": "Khách thử", "role": "user"})
    guest = login(name, "abcdef")
    s, doc_a = new_doc(nv)
    check("Người ngoài không xem được văn bản của người khác (403)", call("GET", f"/api/docs/{doc_a}", guest)[0] == 403)
    check("Người duyệt không xem được văn bản còn ở trạng thái Nháp (403)", call("GET", f"/api/docs/{doc_a}", tp)[0] == 403)
    submit(nv, doc_a)
    check("Giám đốc chưa đến lượt thì không xin được OTP (403)", call("POST", f"/api/docs/{doc_a}/otp", gd)[0] == 403)
    check("Nhân viên không ký được văn bản của chính mình (403)", call("POST", f"/api/docs/{doc_a}/otp", nv)[0] == 403)
    s, otp = get_otp(tp, doc_a)
    if otp:
        check("Ký với mật khẩu sai bị từ chối (400)", sign(tp, doc_a, otp, "saimatkhau") == 400)
        check("Ký với OTP sai bị từ chối (400)", sign(tp, doc_a, "000000" if otp != "000000" else "111111", "123456") == 400)
    else:
        skip("Ký với mật khẩu sai / OTP sai")

    print("\n== M21: toàn vẹn và mã hóa ==")
    s, bad = new_doc(nv, filename="virus.exe")
    check("File không phải PDF/Word bị từ chối (400)", s == 400)
    p = stored_path(doc_a)
    tamper(p)
    check("Sửa file trên server: hệ thống phát hiện khi kiểm tra toàn vẹn",
          js(call("GET", f"/api/docs/{doc_a}/verify", nv)[1]).get("ok") is False)
    check("Sửa file trên server: không cho xem file (409)", call("GET", f"/api/docs/{doc_a}/file", tp)[0] == 409)
    if otp:
        check("Sửa file trên server: chặn không cho ký (409)", sign(tp, doc_a, otp, "123456") == 409)
    else:
        skip("Chặn ký khi file bị sửa")
    s, doc_b = new_doc(nv, "Quyết định", conf=True)
    submit(nv, doc_b)
    pb = stored_path(doc_b)
    check("Tài liệu mật được lưu dạng mã hóa AES (không thấy chữ %PDF trên đĩa)", pb.endswith(".enc") and b"%PDF" not in open(pb, "rb").read())
    check("Tài liệu mật vẫn xem được bình thường khi chưa bị sửa", call("GET", f"/api/docs/{doc_b}/file", tp)[1] == PDF)
    tamper(pb)
    check("Sửa file mật (AES-GCM): không giải mã được, bị chặn (409)", call("GET", f"/api/docs/{doc_b}/file", tp)[0] == 409)

    print("\n== M15: chữ ký số ==")
    s, doc_c = new_doc(nv)
    submit(nv, doc_c)
    s, otp = get_otp(tp, doc_c)
    if otp:
        check("Ký hợp lệ (OTP + mật khẩu) thành công", sign(tp, doc_c, otp, "123456") == 200)
        sg = js(call("GET", f"/api/docs/{doc_c}/signatures", nv)[1])
        check("Chữ ký số kiểm tra lại hợp lệ", isinstance(sg, list) and len(sg) == 1 and sg[0]["valid"] is True)
        c = sqlite3.connect(DB)
        c.execute("UPDATE workflow_steps SET signature=substr(signature,2)||substr(signature,1,1) WHERE doc_id=?", (doc_c,))
        c.commit(); c.close()
        sg = js(call("GET", f"/api/docs/{doc_c}/signatures", nv)[1])
        check("Sửa chữ ký trong CSDL: hệ thống báo chữ ký không hợp lệ", sg[0]["valid"] is False)
    else:
        skip("Chữ ký số")

    print("\n== Gửi văn bản ==")
    raw, ct = multipart({"title": "Thử", "message": "", "recipients": "3", "confidential": "false"}, "a.pdf", PDF)
    s, b = call("POST", "/api/shares", nv, raw=raw, ctype=ct)
    sid = js(b).get("id")
    check("Gửi văn bản cho người trong danh bạ thành công", s == 200 and sid)
    check("Người không phải người nhận không mở được file (403)", call("GET", f"/api/shares/{sid}/file", gd)[0] == 403)
    check("Admin cũng không mở được file gửi riêng giữa người khác (403)", call("GET", f"/api/shares/{sid}/file", ad)[0] == 403)
    check("Người nhận mở được file", call("GET", f"/api/shares/{sid}/file", tp)[1] == PDF)

    print("\n== Nhật ký bảo mật ==")
    for sql, label in [("UPDATE audit_logs SET detail='x' WHERE id=1", "Sửa dòng nhật ký bị CSDL chặn"),
                       ("DELETE FROM audit_logs WHERE id=1", "Xóa dòng nhật ký bị CSDL chặn")]:
        c = sqlite3.connect(DB)
        try:
            c.execute(sql); blocked = False
        except sqlite3.Error:
            blocked = True
        c.close()
        check(label, blocked)
    a = js(call("GET", "/api/admin/audit", ad)[1])
    check("Chuỗi hash của nhật ký còn nguyên vẹn", a.get("chain_ok") is True)

    print("\n== Sao lưu ==")
    s, b = call("POST", "/api/admin/backups", ad)
    bk = js(b).get("name")
    check("Tạo bản sao lưu thành công", s == 200 and bk)
    zin = zipfile.ZipFile(os.path.join(BACKUPS, bk)); items = {n: zin.read(n) for n in zin.namelist()}; zin.close()
    victim = [n for n in items if n.startswith("uploads/")][0]
    items[victim] += b"x"
    bad = "backup-hong-" + uuid.uuid4().hex[:6] + ".zip"
    with zipfile.ZipFile(os.path.join(BACKUPS, bad), "w") as z:
        for n, v in items.items():
            z.writestr(n, v)
    check("Bản sao lưu bị sửa: hệ thống từ chối khôi phục (409)", call("POST", f"/api/admin/backups/{bad}/restore", ad)[0] == 409)
    os.remove(os.path.join(BACKUPS, bad))
    check("Tên bản sao lưu kiểu đường dẫn (../) bị từ chối", call("GET", "/api/admin/backups/..%2f..%2fmain.py/download", ad)[0] in (404, 422))

    if "--pha-nhat-ky" in sys.argv:
        print("\n== Kịch bản kẻ gian sửa nhật ký (làm hỏng nhật ký) ==")
        c = sqlite3.connect(DB)
        c.execute("DROP TRIGGER audit_no_update")
        c.execute("UPDATE audit_logs SET detail='bi sua' WHERE id=3")
        c.commit(); c.close()
        check("Gỡ trigger rồi sửa 1 dòng: chuỗi hash phát hiện nhật ký bị can thiệp",
              js(call("GET", "/api/admin/audit", ad)[1]).get("chain_ok") is False)
        print("  Nhật ký đã bị làm hỏng. Muốn dùng lại: tắt server, xóa thư mục data/ rồi chạy lại.")

    print(f"\nKẾT QUẢ: {sum(results)}/{len(results)} mục đạt")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
