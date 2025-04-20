import json
import os
import time
import jwt
import secrets
from datetime import datetime, timedelta

# Đường dẫn đến file lưu trữ dữ liệu người dùng
USERS_FILE = 'backend/users.json'
# Khóa bí mật để tạo JWT
SECRET_KEY = 'vming1234'  # Nên lưu trong biến môi trường
# Thời gian token hết hạn (tính bằng giây)
TOKEN_EXPIRY = 86400  # 24 giờ

# Dictionary lưu trữ các token đặt lại mật khẩu
reset_tokens = {}

def load_users():
    """Tải dữ liệu người dùng từ file JSON"""
    try:
        os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}
    except Exception as e:
        print(f"Lỗi khi tải users: {e}")
        return {}

def save_users(users):
    """Lưu dữ liệu người dùng vào file JSON"""
    try:
        os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(users, f, ensure_ascii=False, indent=4)
        return True
    except Exception as e:
        print(f"Lỗi khi lưu users: {e}")
        return False

def generate_token(username):
    """Tạo JWT token cho người dùng"""
    payload = {
        'username': username,
        'exp': datetime.utcnow() + timedelta(seconds=TOKEN_EXPIRY)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def decode_token(token):
    """Giải mã JWT token và trả về username"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload['username']
    except jwt.ExpiredSignatureError:
        return "Token đã hết hạn. Vui lòng đăng nhập lại."
    except:
        return "Token không hợp lệ. Vui lòng đăng nhập lại."

def generate_password_reset_token(username):
    """Tạo token đặt lại mật khẩu"""
    token = secrets.token_urlsafe(32)
    expire_time = datetime.utcnow() + timedelta(hours=1)
    reset_tokens[token] = {
        'username': username,
        'expires': expire_time
    }
    return token

def get_username_from_reset_token(token):
    """Lấy username từ token đặt lại mật khẩu nếu token còn hợp lệ"""
    if token not in reset_tokens:
        return None
    
    token_data = reset_tokens[token]
    if datetime.utcnow() > token_data['expires']:
        del reset_tokens[token]
        return None
    
    return token_data['username']

def remove_reset_token(token):
    """Xóa token đặt lại mật khẩu sau khi sử dụng"""
    if token in reset_tokens:
        del reset_tokens[token]
        return True
    return False