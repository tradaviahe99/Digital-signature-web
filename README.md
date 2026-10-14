# Hệ thống Trình ký văn bản và Phê duyệt điện tử (M15 + M20 + M21)

## Cách chạy
```
pip install -r requirements.txt
uvicorn main:app --reload
```
Mở http://127.0.0.1:8000

## Tài khoản mẫu
| Tài khoản | Mật khẩu | Vai trò |
|---|---|---|
| nhanvien | 123456 | User |
| truongphong | 123456 | Manager (cấp 1) |
| giamdoc | 123456 | Manager (cấp 2) |
| admin | admin123 | Admin |

Mã OTP được in ra console của server, và hiện trên màn hình khi demo. Tắt hiện trên màn hình: `SHOW_OTP=0 uvicorn main:app`.
Muốn làm lại từ đầu: xóa thư mục `data/` rồi chạy lại.

## Các file
- `main.py`: toàn bộ backend (đăng nhập, phân quyền, luồng ký, hash, mã hóa, audit log).
- `static/index.html`: giao diện cho 3 vai trò.
- `data/`: tự tạo khi chạy (CSDL SQLite, khóa JWT, khóa AES, file upload).

## Mỗi module nằm ở đâu trong `main.py`
- M20: `current_user`, `require`, `/api/login`, `/api/admin/users`, `request_otp`.
- M15: phần "văn bản & luồng trình ký", trạng thái `draft → pending → signed / rejected / cancelled`.
- M21: `sha256`, `save_file` (AES-256-GCM), `read_verified`, `log` và `verify_chain` (audit log nối chuỗi hash, có trigger chặn sửa/xóa).

## Luồng demo gợi ý
nhanvien tạo "Quyết định" → Gửi trình ký → truongphong lấy OTP và ký → giamdoc ký → văn bản "Đã ký" → admin xem Nhật ký bảo mật.

## Chưa làm (để triển khai thật)
Gửi OTP qua email/SMS thật, chữ ký số (PKI), giới hạn số lần đăng nhập sai, HTTPS.
