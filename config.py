import os
from datetime import timedelta

class Config:
    # Cấu hình chung
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-here')
    JWT_EXPIRATION_TIME = 3600  # Token hết hạn sau 1 giờ
    
    # Cấu hình email
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = '23520945@gm.uit.edu.vn'  # Giá trị trực tiếp
    MAIL_PASSWORD = 'dwbi kvpp swki gbvh'     # Giá trị trực tiếp
    MAIL_DEFAULT_SENDER = '23520945@gm.uit.edu.vn'
    
    # Cấu hình database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Cấu hình frontend
    FRONTEND_URL = os.environ.get('FRONTEND_URL', 'http://localhost:3000')
    
    # Cấu hình JWT
    JWT_TOKEN_LOCATION = ['headers']
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)