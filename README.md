# Hệ thống Trình ký văn bản và Phê duyệt điện tử

Đồ án đề tài 3, kết hợp 3 module:

| Module | Vai trò trong hệ thống |
|---|---|
| **M20** | Xác thực danh tính và phân quyền (ai được làm gì) |
| **M15** | Tạo văn bản, luồng trình ký nhiều cấp, ký xác nhận (OTP + chữ ký số) |
| **M21** | Bảo mật: hash kiểm tra toàn vẹn, mã hóa tài liệu mật, nhật ký không sửa được, sao lưu |

**Công nghệ:** Python (FastAPI), SQLite, giao diện HTML/CSS/JavaScript thuần (1 file). Thư viện: `fastapi`, `uvicorn`, `python-multipart`, `pyjwt`, `cryptography`.

---

## 1. Cài đặt và chạy

```
pip install -r requirements.txt
python main.py
```

Mở trình duyệt: http://127.0.0.1:8000 (cũng có thể chạy `uvicorn main:app --reload`; trên Windows dùng `py main.py` nếu lệnh `python` không chạy).

**Tài khoản mẫu**

| Tên đăng nhập | Mật khẩu | Vai trò | Chức vụ |
|---|---|---|---|
| `nhanvien` | `123456` | User (Nhân viên) | Nhân viên |
| `truongphong` | `123456` | Manager (người duyệt cấp 1) | Trưởng phòng |
| `giamdoc` | `123456` | Manager (người duyệt cấp 2) | Giám đốc |
| `admin` | `admin123` | Admin | Quản trị viên |

**Ghi chú**
- Muốn làm lại từ đầu: tắt server, xóa thư mục `data/`, chạy lại.
- Mã OTP được in ra màn hình dòng lệnh và **hiện luôn trên giao diện** để demo. Muốn tắt phần hiện trên giao diện: `SHOW_OTP=0 python main.py` (Windows PowerShell: `$env:SHOW_OTP=0; python main.py`).

---

## 2. Cấu trúc dự án

```
esign/
├── main.py              Toàn bộ backend (API, phân quyền, luồng ký, hash, mã hóa, nhật ký, sao lưu)
├── security_check.py    Script kiểm tra bảo mật tự động (xem mục 5)
├── requirements.txt     Danh sách thư viện cần cài
├── README.md            Tài liệu này
├── static/
│   └── index.html       Toàn bộ giao diện (3 vai trò), gọi API của main.py
└── data/                Tự tạo khi chạy lần đầu. KHÔNG nộp kèm, KHÔNG chia sẻ
    ├── esign.db         Cơ sở dữ liệu SQLite
    ├── jwt.key          Khóa bí mật ký token đăng nhập (tự sinh ngẫu nhiên)
    ├── aes.key          Khóa AES-256 mã hóa tài liệu mật (tự sinh ngẫu nhiên)
    ├── uploads/         File văn bản đã upload (file mật có đuôi .enc, đã mã hóa)
    └── backups/         Các bản sao lưu (.zip)
```

**`main.py` chia thành các phần theo thứ tự trong file** (tìm nhanh bằng nhãn `[M20]`, `[M15]`, `[M21]`):

| Phần | Nội dung chính | Hàm / API tiêu biểu |
|---|---|---|
| Cơ sở dữ liệu | Tạo bảng, nâng cấp bảng cũ, tài khoản mẫu | `SCHEMA`, `init_db` |
| M21: hash, mã hóa, nhật ký | SHA-256, AES-256-GCM, nhật ký nối chuỗi hash | `sha256`, `save_file`, `load_file`, `read_verified`, `log`, `verify_chain` |
| M20: xác thực, phân quyền | Đăng nhập JWT, kiểm tra vai trò | `current_user`, `require`, `/api/login`, `/api/me` |
| Quản trị (Admin) | Tài khoản, luồng ký mẫu, nhật ký | `/api/admin/users`, `/api/admin/templates`, `/api/admin/audit` |
| M15: văn bản và luồng ký | Tạo văn bản, trình ký, hủy, từ chối, OTP | `create_doc`, `submit`, `cancel`, `request_otp`, `reject` |
| M15: ký duyệt, chữ ký số | Ký bằng OTP + mật khẩu + RSA, kiểm tra chữ ký | `sign`, `get_signing_key`, `signatures` |
| Danh bạ và gửi văn bản | Danh bạ, gửi file cho đồng nghiệp, hộp thư | `directory`, `send_share`, `list_shares`, `share_file` |
| M21: sao lưu, khôi phục | Nén dữ liệu kèm hash, kiểm tra trước khi khôi phục | `make_backup`, `restore_backup`, `/api/admin/backups` |

**`static/index.html`** chia theo các hàm JavaScript: đăng nhập, `docs` (danh sách văn bản), `detail` (chi tiết, ký, từ chối), `users`, `tpl`, `audit` (Admin), `dirView` (danh bạ), `sendDialog` (cửa sổ gửi văn bản), `boxView` (hộp thư), `backup` (sao lưu).

### Cơ sở dữ liệu

| Bảng | Lưu gì | Cột chính |
|---|---|---|
| `users` | Tài khoản | `username`, `password` (dạng `salt$hash`, không lưu mật khẩu thật), `full_name`, `position` (chức vụ), `role`, `level`, `active`, `public_key`, `private_key_enc` |
| `documents` | Văn bản cần ký | `title`, `doc_type`, `owner_id`, `status`, `sha256`, `stored_path`, `confidential`, `current_step` |
| `workflow_steps` | Từng bước ký của mỗi văn bản | `doc_id`, `step_order`, `approver_id`, `status`, `signed_at`, `comment`, `hash_at_sign`, `signature`, `sig_payload`, `key_fingerprint` |
| `workflow_templates` | Luồng ký mẫu theo loại văn bản | `doc_type`, `approver_ids` |
| `otps` | Mã OTP | `code_hash` (chỉ lưu hash), `expires`, `used` |
| `notifications` | Thông báo | `user_id`, `message`, `created_at` |
| `audit_logs` | Nhật ký bảo mật | `ts`, `user_id`, `action`, `doc_id`, `ip`, `detail`, `prev_hash`, `hash` |
| `shares` | File được gửi cho đồng nghiệp | `sender_id`, `title`, `message`, `sha256`, `stored_path`, `confidential` |
| `share_recipients` | Ai nhận file nào | `share_id`, `user_id`, `read_at` (lúc mở xem) |

---

## 3. Chức năng chi tiết

### 3.1. Theo vai trò

**User (Nhân viên)**
- Tạo văn bản: nhập tiêu đề, chọn loại (Đơn từ, Quyết định, Công văn), upload file PDF/Word (tối đa 10MB), tick "Tài liệu mật" nếu cần mã hóa. Luồng ký tự lấy từ luồng mẫu của loại văn bản.
- Lưu nháp, gửi trình ký, hủy văn bản.
- Theo dõi tiến độ: văn bản đang ở bước nào, ai đã ký, ai chưa, kèm ý kiến.
- Xem trước PDF, bấm "Kiểm tra toàn vẹn" và "Kiểm tra chữ ký số".
- Nhận thông báo khi văn bản được ký xong hoặc bị từ chối.
- Xem danh bạ, **gửi văn bản** cho một hoặc nhiều người, xem hộp thư (đã nhận, đã gửi, ai đã xem).

**Manager (Người duyệt)**
- Tab "Chờ tôi duyệt": các văn bản đang đến lượt mình. Tab "Đã xử lý": văn bản mình đã ký hoặc từ chối.
- Nhận thông báo khi có văn bản mới cần duyệt.
- Xem trước văn bản, rồi **ký** (xin OTP, nhập OTP và mật khẩu) hoặc **từ chối** (bắt buộc ghi lý do).
- Có đủ chức năng của User (Manager cũng tạo được văn bản và dùng danh bạ, hộp thư).

**Admin**
- "Tất cả văn bản": xem toàn bộ văn bản trong hệ thống.
- "Người dùng": thêm tài khoản, đổi vai trò, cấp duyệt, chức vụ; khóa hoặc mở khóa tài khoản.
- "Luồng ký mẫu": chọn người duyệt (tối đa 2 bước trên giao diện) cho từng loại văn bản.
- "Nhật ký bảo mật": xem mọi thao tác (ai, lúc nào, IP nào, làm gì) và kết quả kiểm tra chuỗi hash của nhật ký.
- "Sao lưu": tạo, tải về, khôi phục bản sao lưu.

### 3.2. Trạng thái văn bản (M15)

```
Nháp ──(gửi trình ký)──> Đang chờ ký ──(người duyệt cuối ký xong)──> Đã ký
                              │
                              └──(một người duyệt từ chối)──> Từ chối

Nháp hoặc Đang chờ ký ──(người tạo hủy)──> Hủy
```

### 3.3. Luồng ký (M15 + M20 + M21 phối hợp)

1. Nhân viên upload: hệ thống tính **hash SHA-256** (M21), nếu là tài liệu mật thì **mã hóa AES-256** trước khi lưu.
2. Nhân viên bấm "Gửi trình ký": người duyệt bước 1 nhận thông báo.
3. Người duyệt xin **OTP** (M20), nhập OTP và mật khẩu rồi bấm "Ký duyệt". Hệ thống kiểm tra theo thứ tự:
   1. File còn nguyên vẹn không (so hash). Nếu bị sửa, chặn ký.
   2. Mật khẩu đúng không.
   3. OTP đúng, còn hạn (5 phút), chưa dùng không.
4. Hệ thống ký số **RSA** lên hash của văn bản bằng khóa riêng của người duyệt (khóa này được mã hóa bằng chính mật khẩu của họ).
5. Chuyển sang người duyệt kế tiếp. Người cuối ký xong thì văn bản thành "Đã ký" và người tạo nhận thông báo.
6. Mọi bước đều ghi vào **nhật ký** kèm IP và thời gian.

### 3.4. Gửi văn bản (danh bạ, hộp thư)

- **Danh bạ:** liệt kê tên và chức vụ mọi người đang hoạt động trong công ty, có ô tìm kiếm. Chức vụ do Admin nhập.
- **Gửi văn bản:** bấm nút "Gửi văn bản" (cạnh từng người, đầu trang Danh bạ hoặc đầu trang Hộp thư) để mở cửa sổ: nhập tiêu đề, lời nhắn, chọn file, tick "Tài liệu mật" nếu cần, tích chọn người nhận.
- **Hộp thư:** bảng "Đã nhận" (file mới in đậm) và "Đã gửi" (người gửi thấy ai đã xem, lúc nào).
- Khác với "Văn bản của tôi": gửi văn bản chỉ **chuyển file để xem**, không có bước ký.
- Chỉ người gửi và người nhận mở được file. Admin cũng không mở được nếu không phải người nhận.

### 3.5. Sao lưu và khôi phục (Admin)

- Mỗi bản sao lưu là 1 file `.zip` gồm: cơ sở dữ liệu (cả nhật ký, chữ ký), toàn bộ file đã upload, và `manifest.json` ghi hash của từng file.
- Khôi phục: hệ thống kiểm tra hash từng file trước. Nếu có file bị sửa hoặc hỏng thì từ chối. Trước khi ghi đè, hệ thống tự lưu trạng thái hiện tại thành bản `backup-truoc-khoi-phuc-...` để có thể quay lại.
- **Bản sao lưu không chứa khóa AES** (`data/aes.key`). Hãy giữ file này riêng, mất khóa thì không đọc được tài liệu mật.

### 3.6. Danh sách API

| Phương thức, đường dẫn | Ai gọi được | Module |
|---|---|---|
| `POST /api/login` | Mọi người | M20 |
| `GET /api/me`, `GET /api/managers`, `GET /api/templates`, `GET /api/notifications` | Đã đăng nhập | M20, M15 |
| `GET/POST /api/admin/users`, `PUT /api/admin/users/{id}` | Admin | M20 |
| `PUT /api/admin/templates/{loại}` | Admin | M15 |
| `GET /api/admin/audit` | Admin | M21 |
| `POST /api/docs`, `GET /api/docs?scope=mine/inbox/handled/all` | Đã đăng nhập (`all` chỉ Admin) | M15 |
| `GET /api/docs/{id}`, `/file`, `/verify`, `/signatures` | Người tạo, người duyệt của văn bản đó, Admin | M15, M21 |
| `POST /api/docs/{id}/submit`, `/cancel` | Người tạo | M15 |
| `POST /api/docs/{id}/otp`, `/sign`, `/reject` | Người duyệt đang đến lượt | M20, M15 |
| `GET /api/directory` | Đã đăng nhập | M20 |
| `POST /api/shares`, `GET /api/shares?box=inbox/sent`, `GET /api/shares/{id}/file` | Đã đăng nhập (file: chỉ người gửi/nhận) | M15, M21 |
| `GET/POST /api/admin/backups`, `GET .../{tên}/download`, `POST .../{tên}/restore` | Admin | M21 |

### 3.7. Các hành động được ghi vào nhật ký

`DANG_NHAP`, `DANG_NHAP_SAI`, `TAO_TAI_KHOAN`, `SUA_TAI_KHOAN`, `SUA_LUONG_MAU`, `TAO_VAN_BAN`, `XEM_FILE`, `LOI_TOAN_VEN`, `TRINH_KY`, `HUY_VAN_BAN`, `YEU_CAU_OTP`, `OTP_SAI`, `KY_SAI_MAT_KHAU`, `KY_DUYET`, `TU_CHOI`, `GUI_FILE`, `XEM_FILE_GUI`, `SAO_LUU`, `TAI_BAN_SAO_LUU`, `KHOI_PHUC`.

---

## 4. Các cơ chế bảo mật

| # | Cơ chế | Chống lại điều gì | Nằm ở đâu |
|---|---|---|---|
| 1 | Mật khẩu băm PBKDF2-SHA256, 200.000 vòng, mỗi người một "salt" riêng | Lộ cơ sở dữ liệu thì cũng không đọc được mật khẩu | `hash_pw`, `check_pw` |
| 2 | Token JWT (HS256) hết hạn sau 8 giờ, khóa ký sinh ngẫu nhiên | Giả mạo phiên đăng nhập | `login`, `current_user`, `data/jwt.key` |
| 3 | Phân quyền theo vai trò, kiểm tra ở **server** (không chỉ ẩn nút trên giao diện) | Gọi API trái quyền | `require`, `can_view`, `current_approver` |
| 4 | OTP 6 số: lưu dạng hash, hiệu lực 5 phút, dùng 1 lần, OTP cũ mất hiệu lực khi xin mã mới | Ký thay, đoán mã | `request_otp`, `sign` |
| 5 | Ký phải nhập lại mật khẩu; khóa riêng RSA được mã hóa bằng mật khẩu | Người khác ngồi máy đang đăng nhập rồi ký thay | `get_signing_key`, `sign` |
| 6 | Chữ ký số RSA-2048 (PSS, SHA-256) lên hash văn bản | Chối bỏ chữ ký, giả mạo chữ ký, sửa văn bản sau khi ký | `sign`, `signatures` |
| 7 | Hash SHA-256 khi upload, so lại khi xem, trình ký, ký | Sửa lén nội dung file trên server | `sha256`, `read_verified` |
| 8 | Mã hóa AES-256-GCM cho tài liệu mật | Lộ nội dung khi bị lấy file trên đĩa; GCM còn phát hiện file bị sửa | `save_file`, `load_file`, `data/aes.key` |
| 9 | Nhật ký nối chuỗi hash (mỗi dòng chứa hash dòng trước) và trigger CSDL cấm sửa/xóa | Xóa hoặc sửa dấu vết | `log`, `verify_chain`, `audit_no_update/delete` |
| 10 | Mọi câu lệnh SQL dùng tham số | SQL injection | Toàn bộ `main.py` |
| 11 | Giao diện thoát ký tự HTML (`esc`) | XSS (chèn mã script qua tiêu đề, lời nhắn) | `static/index.html` |
| 12 | Chỉ nhận PDF/Word, tối đa 10MB | Upload file lạ | `create_doc`, `send_share` |
| 13 | Tên bản sao lưu kiểm tra bằng mẫu cố định, tên file trong zip được kiểm tra | Đọc hoặc ghi file ngoài thư mục (path traversal) | `BK_NAME`, `restore_backup` |
| 14 | Bản sao lưu có hash từng file, kiểm tra trước khi khôi phục | Khôi phục từ bản đã bị sửa | `make_backup`, `restore_backup` |
| 15 | Tài khoản bị khóa không đăng nhập được, không còn trong danh bạ | Nhân viên đã nghỉ | cột `users.active` |
| 16 | File gửi riêng chỉ người gửi/nhận mở được (Admin cũng không) | Lộ file riêng | `share_file` |

---

## 5. Hướng dẫn kiểm tra bảo mật

Mỗi bài thử nói rõ làm gì và kết quả đúng là gì. Nếu kết quả khác, hệ thống đang có vấn đề.

### Cách A: chạy tự động (nhanh nhất)

Bật server ở một cửa sổ, mở cửa sổ khác trong thư mục `esign` và chạy:

```
python security_check.py
```

Script thử 35 tình huống tấn công và in `[DAT]` hoặc `[LOI]` cho từng mục, cuối cùng in tổng số mục đạt (đúng là `35/35`). Nó gồm:

| Nhóm | Các mục được thử |
|---|---|
| M20 | Không token, token bị sửa, token giả không chữ ký, sai mật khẩu, SQL injection, User/Manager gọi API Admin, người ngoài xem văn bản người khác, Manager chưa đến lượt, ký sai mật khẩu, ký sai OTP |
| M21 | Upload file lạ, sửa file thường, sửa file mật, file mật có thật sự được mã hóa trên đĩa không, chặn xem và chặn ký khi file bị sửa |
| M15 | Ký hợp lệ, kiểm tra chữ ký số, sửa chữ ký trong CSDL |
| Gửi văn bản | Chỉ người nhận mở được file (người khác và cả Admin đều bị 403) |
| Nhật ký | CSDL chặn sửa/xóa dòng nhật ký, chuỗi hash còn nguyên |
| Sao lưu | Từ chối khôi phục bản bị sửa, từ chối tên kiểu đường dẫn `../` |

Thêm `--pha-nhat-ky` để thử kịch bản kẻ gian gỡ trigger và sửa nhật ký. **Lệnh này làm hỏng nhật ký** (để xem hệ thống cảnh báo), sau đó bạn cần xóa `data/` để dùng lại.

Script tạo vài văn bản thử và 1 tài khoản `khach...` mỗi lần chạy, nên nên chạy trên dữ liệu thử.

### Cách B: thử thủ công (để quay màn hình, chụp hình báo cáo)

Các lệnh bên dưới chạy trong thư mục `esign`, lúc server đang chạy. Chúng dùng `python -c` nên chạy được cả Windows, macOS, Linux.

#### Thử 1: mật khẩu không bị lưu thô (cơ chế 1)

```
python -c "import sqlite3;print(sqlite3.connect('data/esign.db').execute('select username,password from users').fetchall())"
```
**Kết quả đúng:** cột mật khẩu là chuỗi dạng `be3f77...$e0068b...` (salt, dấu `$`, rồi hash), không thấy `123456`.

#### Thử 2: phân quyền (cơ chế 3)

1. Đăng nhập `nhanvien`. Menu chỉ có: Văn bản của tôi, Hộp thư, Danh bạ (không có Người dùng, Nhật ký bảo mật, Sao lưu).
2. Đăng nhập `truongphong`: có thêm Chờ tôi duyệt, Đã xử lý nhưng vẫn không có mục của Admin.
3. Thử ở mức API (chặn thật ở server): chạy `python security_check.py`, các mục "gọi API của Admin bị chặn (403)" phải `[DAT]`.

#### Thử 3: sửa file trên server, hash phát hiện (cơ chế 7)

1. Đăng nhập `nhanvien` → "Văn bản của tôi" → "Tạo văn bản", chọn một file PDF, "Lưu nháp".
2. Bấm vào văn bản vừa tạo → "Gửi trình ký".
3. Mở cửa sổ dòng lệnh khác, chạy lệnh thêm 1 ký tự vào file vừa upload (giả lập kẻ gian sửa file):
   ```
   python -c "import glob,os;f=max(glob.glob('data/uploads/*'),key=os.path.getmtime);open(f,'ab').write(b'x');print('da sua',f)"
   ```
4. Đăng nhập `truongphong` → "Chờ tôi duyệt" → mở văn bản:
   - Bấm "Kiểm tra toàn vẹn": **chữ đỏ** "File đã bị thay đổi. Hash lúc upload ≠ hash hiện tại."
   - Bấm "Xem file": báo "CẢNH BÁO: file đã bị thay đổi...".
   - Bấm "Lấy mã OTP để ký", nhập OTP và mật khẩu `123456`, bấm "Ký duyệt": **bị từ chối**, báo file đã bị thay đổi.
5. Đăng nhập `admin` → "Nhật ký bảo mật": có dòng `LOI_TOAN_VEN`.

**Chứng minh:** file bị sửa thì không thể trình ký hay ký, và có dấu vết trong nhật ký.

#### Thử 4: tài liệu mật được mã hóa AES (cơ chế 8)

1. Đăng nhập `nhanvien`, tạo văn bản mới, **tick "Tài liệu mật"**, "Lưu nháp".
2. Xem nội dung file trên đĩa:
   ```
   python -c "import glob;print([open(f,'rb').read(40) for f in glob.glob('data/uploads/*.enc')][:1])"
   ```
   **Kết quả đúng:** ra các byte lộn xộn, không thấy chữ `%PDF`. Trong khi đó bấm "Xem file" trên giao diện vẫn xem được bình thường.
3. Sửa file mật bằng lệnh ở Thử 3 (lệnh lấy file mới nhất), rồi bấm "Xem file": báo file đã bị thay đổi (AES-GCM không giải mã được file bị sửa).

#### Thử 5: ký phải đủ mật khẩu và OTP (cơ chế 4, 5)

1. Tạo văn bản mới bằng `nhanvien` rồi "Gửi trình ký".
2. Đăng nhập `truongphong`, mở văn bản, bấm "Lấy mã OTP để ký".
3. Nhập **OTP đúng + mật khẩu sai**, bấm "Ký duyệt": báo "Mật khẩu xác nhận không đúng".
4. Nhập **OTP sai + mật khẩu đúng**: báo "Mã OTP sai hoặc đã hết hạn".
5. Nhập đúng cả hai: ký thành công.
6. Đăng nhập `admin` → "Nhật ký bảo mật": thấy `KY_SAI_MAT_KHAU`, `OTP_SAI`, `KY_DUYET`.

#### Thử 6: chữ ký số và giả mạo chữ ký (cơ chế 6)

1. Ký xong một văn bản (như Thử 5, nếu cần thì ký thêm bước giám đốc).
2. Mở văn bản bằng bất kỳ tài khoản nào có quyền xem, bấm "Kiểm tra chữ ký số": **chữ xanh** "chữ ký số hợp lệ", kèm mã khóa công khai.
3. Giả lập kẻ gian sửa chữ ký trong cơ sở dữ liệu:
   ```
   python -c "import sqlite3;c=sqlite3.connect('data/esign.db');c.execute('UPDATE workflow_steps SET signature=substr(signature,2)||substr(signature,1,1) WHERE signature IS NOT NULL');c.commit()"
   ```
4. Đóng cửa sổ chi tiết, mở lại, bấm "Kiểm tra chữ ký số": **chữ đỏ** "Chữ ký không hợp lệ".

#### Thử 7: nhật ký không sửa được (cơ chế 9)

1. Thử sửa một dòng nhật ký:
   ```
   python -c "import sqlite3;sqlite3.connect('data/esign.db').execute('UPDATE audit_logs SET detail=1 WHERE id=1')"
   ```
   **Kết quả đúng:** báo lỗi `Audit log chi duoc them, khong duoc sua`. Thử với `DELETE FROM audit_logs` cũng bị chặn tương tự.

2. Kịch bản mạnh hơn: kẻ gian có quyền cao, gỡ trigger rồi sửa nhật ký. **Làm hỏng nhật ký thật**, chỉ làm khi đã sẵn sàng xóa `data/`:
   ```
   python -c "import sqlite3;c=sqlite3.connect('data/esign.db');c.execute('DROP TRIGGER audit_no_update');c.execute('UPDATE audit_logs SET detail=1 WHERE id=3');c.commit()"
   ```
3. Đăng nhập `admin` → "Nhật ký bảo mật": dòng trên cùng chuyển **đỏ**: "CẢNH BÁO: nhật ký đã bị can thiệp, chuỗi hash bị đứt."

**Chứng minh:** dù kẻ gian vượt được lớp chặn của CSDL, chuỗi hash vẫn lộ ra việc sửa.

#### Thử 8: gửi văn bản riêng tư (cơ chế 16)

1. Đăng nhập `truongphong` → "Danh bạ" → "Gửi văn bản" cạnh Lê Văn Cường, chọn file, "Gửi".
2. Đăng nhập `giamdoc` → "Hộp thư": thấy file ở "Đã nhận" (in đậm "Mới"). Mở file, quay lại: trạng thái thành "Đã xem".
3. Đăng nhập `truongphong` → "Hộp thư" → "Đã gửi": thấy "(đã xem)" cạnh tên giám đốc.
4. Đăng nhập `admin` → "Hộp thư": **không có** file này. Admin cũng không mở được file giữa hai người khác (kiểm tra API bằng `security_check.py`).

#### Thử 9: chống chèn mã script, XSS (cơ chế 11)

1. Đăng nhập `nhanvien`, tạo văn bản có tiêu đề `<b>thu</b><img src=x onerror=alert(1)>`.
2. **Kết quả đúng:** danh sách hiện nguyên chữ `<b>thu</b>...` như văn bản thường, không in đậm, không hiện hộp thoại.

#### Thử 10: sao lưu và khôi phục (cơ chế 14)

1. Đăng nhập `admin` → "Sao lưu" → "Tạo bản sao lưu".
2. Tạo thêm 1 văn bản mới bằng `nhanvien`.
3. Quay lại "Sao lưu", bấm "Khôi phục" ở bản vừa tạo, xác nhận. Văn bản mới tạo ở bước 2 **biến mất** (đã quay về lúc sao lưu), và xuất hiện thêm bản `backup-truoc-khoi-phuc-...` để quay lại nếu cần.
4. Kiểm tra bản sao lưu bị sửa sẽ bị từ chối: chạy `python security_check.py`, mục "Bản sao lưu bị sửa: hệ thống từ chối khôi phục (409)" phải `[DAT]`.

### Bảng tóm tắt để đưa vào báo cáo

| Thử nghiệm | Tấn công giả lập | Kết quả hệ thống |
|---|---|---|
| Thử 3 | Sửa file văn bản trên server | Phát hiện bằng hash, chặn xem và chặn ký, ghi nhật ký `LOI_TOAN_VEN` |
| Thử 4 | Sửa hoặc đọc file mật trên đĩa | Không đọc được (AES), file bị sửa thì không giải mã được |
| Thử 5 | Ký với OTP hoặc mật khẩu sai | Từ chối, ghi nhật ký |
| Thử 6 | Sửa chữ ký trong CSDL | Báo "Chữ ký không hợp lệ" |
| Thử 7 | Sửa hoặc xóa nhật ký | CSDL chặn; nếu gỡ chặn thì chuỗi hash báo bị can thiệp |
| Thử 8 | Người ngoài (kể cả Admin) mở file riêng | Bị 403 |
| Thử 9 | Chèn mã script vào tiêu đề | Hiện thành chữ thường, không chạy |
| Thử 10 | Khôi phục từ bản sao lưu bị sửa | Từ chối (409) |

---

## 6. Hạn chế và hướng phát triển

- OTP chưa gửi qua email/SMS thật (đang hiện trên màn hình để demo).
- Chữ ký số dùng khóa RSA tự tạo trong hệ thống, chưa có chứng thư số do cơ quan chứng thực (CA) cấp. Cặp khóa được tạo ở lần ký đầu tiên của mỗi người.
- Chưa giới hạn số lần đăng nhập sai (khóa tạm khi đoán mật khẩu).
- Chưa có HTTPS (khi triển khai thật cần đặt sau một web server có HTTPS).
- Đăng xuất chỉ xóa token ở trình duyệt, token cũ vẫn dùng được đến khi hết hạn 8 giờ.
- Khóa AES nằm cùng máy chủ (`data/aes.key`); hệ thống thật nên để ở kho khóa riêng.
- Sao lưu chưa tự động theo lịch, chưa mã hóa file sao lưu.
- Luồng ký mẫu trên giao diện cấu hình tối đa 2 bước (backend hỗ trợ nhiều hơn).
