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

best_model = '/best_model_w_grid.pkl'

MODEL_PATH = f'./model/{best_model}'
SCALER_PATH = './model/scaler.pkl'

# Load model và scaler
try:
    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
        raise FileNotFoundError("Model hoặc Scaler không tồn tại. Kiểm tra lại đường dẫn.")

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
    
    app.config['MODEL'] = model
    app.config['SCALER'] = scaler
    print("✅ Model và Scaler đã load thành công!")

except Exception as e:
    print(f"❌ Lỗi khi tải model: {str(e)}")
    app.config['MODEL'] = None
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