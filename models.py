from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

# Module M20: Bảng Người dùng
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False) # 'employee', 'manager', 'admin'

# Module M15: Bảng Văn bản / Trình ký
class Document(db.Model):
    __tablename__ = 'documents'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    file_path = db.Column(db.String(300), nullable=True)
    status = db.Column(db.String(20), default='Chờ duyệt') # 'Chờ duyệt', 'Đã duyệt', 'Từ chối'
    signature_hash = db.Column(db.String(100), nullable=True) # Mã giả lập ký số
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Module M21: Bảng Nhật ký hệ thống (Audit Log)
class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(200), nullable=False) # Ví dụ: "ĐĂNG NHẬP", "DUYỆT VĂN BẢN #3"
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
