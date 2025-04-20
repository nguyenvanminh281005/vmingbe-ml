import os

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
    USER_DB_FILE = 'users.json'

    @staticmethod
    def ensure_db_file():
        """ Đảm bảo file database tồn tại """
        if not os.path.exists(Config.USER_DB_FILE):
            with open(Config.USER_DB_FILE, 'w') as f:
                f.write('{}')  # Ghi file JSON rỗng
                print(f"Created {Config.USER_DB_FILE}")

    # Cấu hình frontend
    FRONTEND_URL = os.environ.get('FRONTEND_URL', 'http://localhost:3000')