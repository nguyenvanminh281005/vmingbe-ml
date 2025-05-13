from flask import Blueprint, request, jsonify, current_app, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Message
import re
from datetime import datetime
from extensions import mail, db  # db import từ extensions, bạn phải khởi tạo db ở app chính
from utils.auth_ultils import (
    generate_token, decode_token, 
    generate_password_reset_token, get_username_from_reset_token, remove_reset_token
)
import warnings

auth_bp = Blueprint('auth', __name__)

# Model User
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.username}>'

@auth_bp.route('/')
def index():
    return redirect('/auth/')

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    print("📥 Received data:", data)  # Debugging
    # Validate input fields
    if not data or not all(k in data for k in ('username', 'email', 'password')):
        return jsonify({'error': 'Thiếu thông tin đăng ký'}), 400
    
    # Kiểm tra định dạng email hợp lệ
    if not re.match(r"^\S+@\S+\.\S+$", data['email']):
        return jsonify({'error': 'Email không hợp lệ'}), 400
    
    # Kiểm tra độ dài mật khẩu
    if len(data['password']) < 6:
        return jsonify({'error': 'Mật khẩu phải có ít nhất 6 ký tự'}), 400
    
    # Kiểm tra username đã tồn tại chưa
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Tên đăng nhập đã tồn tại'}), 400
    
    # Kiểm tra email đã tồn tại chưa
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email đã được sử dụng'}), 400
    
    # Tạo user mới
    new_user = User(
        username=data['username'],
        email=data['email'],
        password=generate_password_hash(data['password'])
    )

    # Lưu vào database
    db.session.add(new_user)
    db.session.commit()
    
    # Generate authentication token
    token = generate_token(data['username'])
    
    return jsonify({
        'message': 'Đăng ký thành công',
        'token': token,
        'username': data['username']
    }), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    print("📥 Received data:", data)  # Debugging
    
    if not data:
        return jsonify({'error': 'Không nhận được dữ liệu'}), 400

    # Cần ít nhất password và username hoặc email
    if 'password' not in data:
        return jsonify({'error': 'Thiếu thông tin đăng nhập'}), 400

    username_or_email = data.get('username') or data.get('email')
    if not username_or_email:
        return jsonify({'error': 'Thiếu username hoặc email'}), 400

    # Tìm user theo username hoặc email
    user = User.query.filter(
        (User.username == username_or_email) | (User.email == username_or_email)
    ).first()

    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'error': 'Tên đăng nhập hoặc mật khẩu không đúng'}), 401

    token = generate_token(user.username)

    return jsonify({
        'message': 'Đăng nhập thành công',
        'token': token,
        'username': user.username
    }), 200


@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    if not data or 'email' not in data:
        return jsonify({'error': 'Vui lòng cung cấp email'}), 400

    user = User.query.filter_by(email=data['email']).first()
    if user:
        try:
            reset_token = generate_password_reset_token(user.username)
            reset_url = f"{current_app.config['FRONTEND_URL']}/reset-password?token={reset_token}"
            msg = Message('Yêu cầu đặt lại mật khẩu', recipients=[data['email']])
            msg.body = f"Để đặt lại mật khẩu, vui lòng truy cập: {reset_url}\nLiên kết có hiệu lực trong 1 giờ."
            mail.send(msg)
        except Exception as e:
            current_app.logger.error(f"Email error: {str(e)}")
    return jsonify({'message': 'Nếu email tồn tại, hướng dẫn đặt lại mật khẩu đã được gửi'}), 200


@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    if not data or not all(k in data for k in ('token', 'new_password')):
        return jsonify({'error': 'Thiếu thông tin đặt lại mật khẩu'}), 400

    if len(data['new_password']) < 8:
        return jsonify({'error': 'Mật khẩu phải có ít nhất 8 ký tự'}), 400

    username = get_username_from_reset_token(data['token'])
    if not username:
        return jsonify({'error': 'Token không hợp lệ hoặc đã hết hạn'}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'Token không hợp lệ'}), 400

    user.password = generate_password_hash(data['new_password'])
    db.session.commit()

    # Nếu bạn lưu token đã dùng, xóa hoặc đánh dấu token ở đây

    return jsonify({'message': 'Mật khẩu đã được đặt lại thành công'}), 200


@auth_bp.route('/me', methods=['GET'])
def get_user_profile():
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Token không hợp lệ'}), 401
    
    token = auth_header.split(' ')[1]
    username = decode_token(token)
    
    if isinstance(username, str) and (username.endswith('đăng nhập lại.') or username.endswith('Vui lòng đăng nhập lại.')):
        return jsonify({'error': username}), 401
    
    user = User.query.filter_by(username=username).first()
    
    if not user:
        return jsonify({'error': 'Người dùng không tồn tại'}), 404
    
    return jsonify({
        'username': user.username,
        'email': user.email,
        'createdAt': user.created_at.isoformat()  # 👈 thêm dòng này
    }), 200
    

@auth_bp.route('/debug-users', methods=['GET'])
def debug_users():
    users = User.query.all()
    users_data = {user.username: {'email': user.email, 'password': user.password} for user in users}
    print("📜 Debug users:", users_data)
    return jsonify(users_data)


@auth_bp.route('/update-profile', methods=['PUT'])
def update_profile():
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Token không hợp lệ'}), 401

    token = auth_header.split(' ')[1]
    username = decode_token(token)

    if isinstance(username, str) and "Vui lòng đăng nhập lại" in username:
        return jsonify({'error': username}), 401

    user = User.query.filter_by(username=username).first()
    
    if not user:
        return jsonify({'error': 'Người dùng không tồn tại'}), 404

    data = request.get_json()
    
    # Cập nhật thông tin (chỉ cập nhật nếu có trong request)
    if 'email' in data:
        # Kiểm tra email mới có hợp lệ không (nếu cần)
        if not re.match(r"^\S+@\S+\.\S+$", data['email']):
            return jsonify({'error': 'Email không hợp lệ'}), 400
        # Kiểm tra email đã tồn tại chưa (tránh trùng)
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user and existing_user.username != username:
            return jsonify({'error': 'Email đã được sử dụng'}), 400
        user.email = data['email']

    if 'password' in data:
        if len(data['password']) < 6:
            return jsonify({'error': 'Mật khẩu phải có ít nhất 6 ký tự'}), 400
        user.password = generate_password_hash(data['password'])

    db.session.commit()

    return jsonify({'message': 'Cập nhật hồ sơ thành công'}), 200


@auth_bp.route('/delete-account', methods=['DELETE'])
def delete_account():
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Token không hợp lệ'}), 401

    token = auth_header.split(' ')[1]
    username = decode_token(token)

    if isinstance(username, str) and "Vui lòng đăng nhập lại" in username:
        return jsonify({'error': username}), 401

    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({'error': 'Người dùng không tồn tại'}), 404

    # Xóa user khỏi database
    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'Tài khoản đã bị xóa'}), 200

def generate_email_html(doctor_name, message, prediction_results):
    """Tạo nội dung HTML cho email gửi bác sĩ"""
    status = prediction_results.get('status', 'Không xác định')
    features = prediction_results.get('features', [])

    features_html = ""
    for i, val in enumerate(features):
        features_html += f"<tr><td>F{i+1}</td><td>{val}</td></tr>"

    html = f"""
    <html>
    <body>
        <h2>Chào Bác sĩ {doctor_name},</h2>
        <p>Bệnh nhân đã chia sẻ kết quả dự đoán bệnh Alzheimer với bạn.</p>
        <p><strong>Trạng thái dự đoán:</strong> {status}</p>
        {f"<p><strong>Lời nhắn từ bệnh nhân:</strong> {message}</p>" if message else ""}
        <h3>Chi tiết đặc trưng:</h3>
        <table border="1" cellpadding="5" cellspacing="0">
            <tr><th>Đặc trưng</th><th>Giá trị</th></tr>
            {features_html}
        </table>
    </body>
    </html>
    """
    return html

@auth_bp.route('/share-results', methods=['POST'])
def share_results():
    """API endpoint để xử lý yêu cầu chia sẻ kết quả qua email"""
    try:
        data = request.get_json()
        recipient_email = data.get('recipientEmail')
        doctor_name = data.get('doctorName')
        message = data.get('message', '')
        prediction_results = data.get('predictionResults', {})

        print("Dữ liệu nhận được:", data)  # Debug log

        if not recipient_email or not doctor_name or not prediction_results:
            return jsonify({'status': 'error', 'message': 'Thiếu thông tin bắt buộc'}), 400

        # Nếu chưa có status thì tính lại từ model
        if 'status' not in prediction_results and 'features' in prediction_results:
            model = current_app.config.get('MODEL')
            scaler = current_app.config.get('SCALER')

            if model is None or scaler is None:
                return jsonify({'status': 'error', 'message': 'Model hoặc Scaler chưa được cấu hình'}), 500

            features = prediction_results['features']

            if not isinstance(features, list):
                return jsonify({'status': 'error', 'message': 'Dữ liệu features không hợp lệ'}), 400

            features_array = np.array([features])
            if features_array.shape[1] != scaler.n_features_in_:
                return jsonify({'status': 'error', 'message': f'Số lượng đặc trưng không hợp lệ. Mong đợi {scaler.n_features_in_}, nhận {features_array.shape[1]}'}), 400

            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                features_scaled = scaler.transform(features_array)

            prediction = model.predict(features_scaled)[0]
            status = "Disease Detected" if prediction == 1 else "Healthy"
            prediction_results['status'] = status

        # Tạo nội dung HTML email
        html_content = generate_email_html(doctor_name, message, prediction_results)

        msg = Message(
            subject="Kết quả dự đoán bệnh Alzheimer",
            sender=current_app.config['MAIL_DEFAULT_SENDER'],
            recipients=[recipient_email],
            html=html_content
        )

        mail.send(msg)

        return jsonify({'status': 'success', 'message': 'Email đã được gửi thành công'})

    except Exception as e:
        print(f"Lỗi khi gửi email: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Có lỗi xảy ra: {str(e)}'}), 500
        
        
from openai import OpenAI
from dotenv import load_dotenv
import os
import json
from flask import jsonify, request

load_dotenv()
client = OpenAI(
    api_key=os.environ.get("OPENAI_API_KEY")

)

@auth_bp.route('/get_advice', methods=['POST'])
def get_advice():
    data = request.get_json()
    features = data.get('features', [])
    prediction = data.get('prediction', '')
    user_id = data.get('userId')
    
    if prediction != "Disease Detected":  # Thay "Disease Detected" bằng 1 để khớp với frontend
        return jsonify({'advice': []})  # Trả về mảng rỗng thay vì chuỗi
    
    prompt = f"""
    Bạn là chuyên gia y tế về bệnh Alzheimer.
    Một bệnh nhân có các chỉ số về ['ADL', 'MMSE', 'FunctionalAssessment', 'Disorientation',
       'PersonalityChanges', 'Smoking', 'HeadInjury', 'CholesterolTotal'] sau khi xét nghiệm được lần lượt là : {features}.
    Dựa trên kết quả chẩn đoán, hãy đưa ra danh sách gồm 3 lời khuyên cụ thể mà bạn thấy là phù hợp nhất, 
    chi tiết và dễ thực hiện cộng thêm 3 lời khuyên về việc nên sử dụng thuốc gì như thế nào.
    Có thể phân tích chỉ rõ tại sao lại có lời khuyên đó dựa trên chỉ số được cung cấp.
   
    Phản hồi của bạn PHẢI là một danh sách các lời khuyên theo định dạng sau:
    [
        {{
            "title": "Tiêu đề lời khuyên 1",
            "details": "Mô tả chi tiết lời khuyên 1"
        }},
        {{
            "title": "Tiêu đề lời khuyên 2",
            "details": "Mô tả chi tiết lời khuyên 2"
        }}
    ]
    """
    
    try:
        response = client.responses.create(
            model="gpt-4o-mini",
            instructions="Bạn là một bác sĩ chuyên về thần kinh. Chỉ trả lời bằng JSON hợp lệ không có text thừa.",
            input=prompt,
        )
        
        # Lấy đúng text chứa JSON
        raw_text = response.output[0].content[0].text
        
        # Bóc bỏ ```json ... ``` nếu có
        json_str = re.sub(r"```(json)?", "", raw_text).strip()
        
        # Parse JSON
        advice_list = json.loads(json_str)
        
        return jsonify({'advice': advice_list})

    except Exception as e:
        print("GPT Error:", e)
        return jsonify({'advice': [], 'error': 'Không thể lấy lời khuyên từ chuyên gia GPT.'})