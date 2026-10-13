import os

class Config:
    # Khóa bí mật cho Flask Session
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'sieu-khoa-bi-mat-cho-do-an-nay'
    
    # Cấu hình kết nối PostgreSQL (Thay đổi username, password, db_name của nhóm bạn)
    # Cú pháp: postgresql://username:password@localhost:5432/ten_database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://postgres:123456@localhost:5432/quan_ly_trinh_ky'
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = 'static/uploads' # Thư mục chứa file đính kèm văn bản
