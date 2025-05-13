# how to create req file -> pip freeze > requirements.txt
# how to install req file -> pip install -r requirements.txt

from flask import Flask
from flask_cors import CORS
import joblib
import os
import warnings

# Sau đó mới import các routes
from config import Config
from routes.auth_routes import auth_bp
from routes.prediction_routes import prediction_bp
# Bỏ dòng import mail từ extensions vì chúng ta sẽ khởi tạo trực tiếp

# Import extensions trước
from extensions import mail,db

app = Flask(__name__)

CORS(app)

# Cấu hình database
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///yourdatabase.db'  # Thay bằng URI của bạn

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')  # Railway cung cấp biến này
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Cấu hình Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = '23520945@gm.uit.edu.vn'
app.config['MAIL_PASSWORD'] = 'dwbi kvpp swki gbvh'
app.config['MAIL_DEFAULT_SENDER'] = '23520945@gm.uit.edu.vn'
app.config['FRONTEND_URL'] = 'http://localhost:3000'

# Khởi tạo extensions với app
db.init_app(app)
mail.init_app(app)

# Load multiple models and scaler
MODEL_DIR = './model'
SCALER_PATH = os.path.join(MODEL_DIR, 'scaler.pkl')

MODEL_FILES = {
    'xgboost_lib': 'xgboost_lib.pkl',
    'random_forest_lib': 'random_forest_lib.pkl',
    'xgboost_scr': 'xgboost_scr.pkl',
    'random_forest_scr': 'random_forest_scr.pkl',
    'best_model': 'best_model.pkl'  # fallback hoặc mặc định
}

try:
    if not os.path.exists(SCALER_PATH):
        raise FileNotFoundError("Scaler không tồn tại.")

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        scaler = joblib.load(SCALER_PATH)
    
    # Load all models
    models = {}
    for model_name, file_name in MODEL_FILES.items():
        model_path = os.path.join(MODEL_DIR, file_name)
        if os.path.exists(model_path):
            models[model_name] = joblib.load(model_path)
        else:
            print(f"⚠️ Không tìm thấy model: {file_name}")

    app.config['MODELS'] = models
    app.config['SCALER'] = scaler
    print(f"✅ Đã load {len(models)} mô hình và scaler thành công!")

except Exception as e:
    print(f"❌ Lỗi khi tải mô hình hoặc scaler: {str(e)}")
    app.config['MODELS'] = {}
    app.config['SCALER'] = None

# Đăng ký blueprint
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(prediction_bp)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    print(f"Mail username: {app.config['MAIL_USERNAME']}")
    print(f"Mail default sender: {app.config['MAIL_DEFAULT_SENDER']}")
    
    app.run(host='0.0.0.0', port=5000, debug=True)