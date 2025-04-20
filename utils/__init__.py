import jwt
from datetime import datetime, timedelta
import json
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app

# Lưu trữ token reset password
password_reset_tokens = {}

def load_users():
    try:
        with open(current_app.config['USER_DB_FILE'], 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_users(users):
    with open(current_app.config['USER_DB_FILE'], 'w') as f:
        json.dump(users, f, indent=4)

def generate_token(user_id):
    payload = {
        'exp': datetime.utcnow() + timedelta(seconds=current_app.config['JWT_EXPIRATION_TIME']),
        'iat': datetime.utcnow(),
        'sub': user_id
    }
    return jwt.encode(
        payload,
        current_app.config['SECRET_KEY'],
        algorithm='HS256'
    )

def decode_token(token):
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return 'Token đã hết hạn. Vui lòng đăng nhập lại.'
    except jwt.InvalidTokenError:
        return 'Token không hợp lệ. Vui lòng đăng nhập lại.'

def generate_password_reset_token(username):
    token = secrets.token_urlsafe(32)
    password_reset_tokens[token] = username
    return token

def get_username_from_reset_token(token):
    return password_reset_tokens.get(token)

def remove_reset_token(token):
    if token in password_reset_tokens:
        del password_reset_tokens[token]