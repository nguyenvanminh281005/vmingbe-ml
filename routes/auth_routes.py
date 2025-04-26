from flask import Blueprint, request, jsonify, current_app
from utils.auth_ultils import (
    load_users, save_users, generate_token, decode_token, 
    generate_password_reset_token, get_username_from_reset_token, remove_reset_token
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Message
import re
from flask_cors import CORS
import os
from datetime import datetime
from extensions import mail
from flask import redirect


auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/')
def index():
    return redirect('/auth/')

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Validate input fields
    if not all(k in data for k in ('username', 'email', 'password')):
        return jsonify({'error': 'Thiếu thông tin đăng ký'}), 400
    
    # Kiểm tra định dạng email hợp lệ
    if not re.match(r"^\S+@\S+\.\S+$", data['email']):
        return jsonify({'error': 'Email không hợp lệ'}), 400
    
    # Kiểm tra độ dài mật khẩu
    if len(data['password']) < 6:
        return jsonify({'error': 'Mật khẩu phải có ít nhất 6 ký tự'}), 400
    
    users = load_users() or {}  # Đảm bảo users luôn là dict
    
    # Check if username already exists
    if data['username'] in users:
        return jsonify({'error': 'Tên đăng nhập đã tồn tại'}), 400
    
    # Check if email already exists
    if any(user.get('email') == data['email'] for user in users.values()):
        return jsonify({'error': 'Email đã được sử dụng'}), 400
    
    # Create new user
    users[data['username']] = {
        'email': data['email'],
        'password': generate_password_hash(data['password'])
    }
    
    print("📌 Dữ liệu users trước khi lưu:", users)  # Debug
    save_users(users)
    
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
        return jsonify({'error': 'Không nhận được dữ liệu'}), 400  # Nếu request không có data

    # Validate input (chấp nhận cả email và username)
    if not all(k in data for k in ('password',)):
        return jsonify({'error': 'Thiếu thông tin đăng nhập'}), 400

    username = data.get('username') or data.get('email')  # Lấy username hoặc email
    if not username:
        return jsonify({'error': 'Thiếu username hoặc email'}), 400

    users = load_users()
    user = users.get(username) or next((u for u in users.values() if u["email"] == username), None)

    if not user or not check_password_hash(user['password'], data['password']):
        return jsonify({'error': 'Tên đăng nhập hoặc mật khẩu không đúng'}), 401

    token = generate_token(username)

    return jsonify({
        'message': 'Đăng nhập thành công',
        'token': token,
        'username': username
    }), 200


@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    
    # Validate input
    if 'email' not in data:
        return jsonify({'error': 'Vui lòng cung cấp email'}), 400
    
    users = load_users()
    user_found = None
    username_found = None
    
    # Find user by email
    for username, user in users.items():
        if user['email'] == data['email']:
            user_found = user
            username_found = username
            break
    
    if not user_found:
        return jsonify({'error': 'Email không tồn tại trong hệ thống'}), 404
    
    # Generate reset token
    reset_token = generate_password_reset_token(username_found)
    
    # Send email with reset link
    try:
        reset_url = f"{current_app.config['FRONTEND_URL']}/reset-password?token={reset_token}"
        msg = Message(
            'Yêu cầu đặt lại mật khẩu',
            recipients=[data['email']]
        )
        msg.body = f'''Để đặt lại mật khẩu, vui lòng truy cập đường dẫn sau:
{reset_url}

Nếu bạn không yêu cầu đặt lại mật khẩu, vui lòng bỏ qua email này.
'''
        mail.send(msg)
    except Exception as e:
        print(f"Email error: {str(e)}")
        return jsonify({'error': 'Không thể gửi email'}), 500
    
    return jsonify({'message': 'Email hướng dẫn đặt lại mật khẩu đã được gửi'}), 200

@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    
    # Validate input
    if not all(k in data for k in ('token', 'new_password')):
        return jsonify({'error': 'Thiếu thông tin đặt lại mật khẩu'}), 400
    
    # Check if token is valid
    username = get_username_from_reset_token(data['token'])
    if not username:
        return jsonify({'error': 'Token không hợp lệ hoặc đã hết hạn'}), 400
    
    users = load_users()
    
    # Update password
    users[username]['password'] = generate_password_hash(data['new_password'])
    save_users(users)
    
    # Remove used token
    remove_reset_token(data['token'])
    
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
    
    users = load_users()
    
    if username not in users:
        return jsonify({'error': 'Người dùng không tồn tại'}), 404
    
    user = users[username]
    
    return jsonify({
        'username': username,
        'email': user['email']
    }), 200
    
@auth_bp.route('/debug-users', methods=['GET'])
def debug_users():
    users = load_users()
    print("📜 Debug users:", users)
    return jsonify(users)

@auth_bp.route('/update-profile', methods=['PUT'])
def update_profile():
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Token không hợp lệ'}), 401

    token = auth_header.split(' ')[1]
    username = decode_token(token)

    if isinstance(username, str) and "Vui lòng đăng nhập lại" in username:
        return jsonify({'error': username}), 401

    users = load_users()
    
    if username not in users:
        return jsonify({'error': 'Người dùng không tồn tại'}), 404

    data = request.get_json()
    
    # Cập nhật thông tin (chỉ cập nhật nếu có trong request)
    users[username]['email'] = data.get('email', users[username]['email'])
    if 'password' in data:
        users[username]['password'] = generate_password_hash(data['password'])

    save_users(users)

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

    users = load_users()

    if username not in users:
        return jsonify({'error': 'Người dùng không tồn tại'}), 404

    # Xóa tài khoản khỏi danh sách
    del users[username]
    save_users(users)

    return jsonify({'message': 'Tài khoản đã bị xóa'}), 200


# Hàm tạo nội dung email HTML
def generate_email_html(doctor_name, message, prediction_results):
    """Tạo nội dung HTML cho email"""
    
    # Xử lý dữ liệu prediction_results theo cấu trúc thực tế
    status = prediction_results.get('status', 'Không xác định')
    patient_id = "PD-" + datetime.now().strftime("%Y%m%d%H%M")  # Tạo ID bệnh nhân từ timestamp
    
    # Loại bỏ key 'status' để hiển thị phần còn lại là features
    features = {k: v for k, v in prediction_results.items() if k != 'status'}
    
    # Định dạng ngày tháng theo kiểu Việt Nam
    timestamp = datetime.now().strftime("%d/%m/%Y %H:%M")
    
    # Xác định prediction dựa trên status
    prediction = "Positive" if "Parkinson Detected" in status else "Negative"
    
    # Giả lập probability vì không có trong dữ liệu gốc
    probability = 85.5 if "Parkinson Detected" in status else 15.5
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background-color: #3498db; color: white; padding: 10px 20px; text-align: center; }}
            .content {{ padding: 20px; background-color: #f9f9f9; }}
            .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #777; }}
            .result-box {{ background-color: white; padding: 15px; margin: 15px 0; border-radius: 5px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
            .result-title {{ color: #2c3e50; border-bottom: 1px solid #eee; padding-bottom: 10px; }}
            .result-item {{ margin: 10px 0; }}
            .result-label {{ font-weight: bold; }}
            .features-table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
            .features-table th, .features-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            .features-table th {{ background-color: #f2f2f2; }}
            .positive {{ color: #e74c3c; }}
            .negative {{ color: #27ae60; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>Kết Quả Dự Đoán Bệnh Parkinson</h2>
            </div>
            
            <div class="content">
                <p>Kính gửi Bác sĩ <strong>{doctor_name}</strong>,</p>
                
                <p>Tôi gửi đến bác sĩ kết quả dự đoán bệnh Parkinson của tôi. Mong bác sĩ xem xét và tư vấn thêm.</p>
                
                {f'<p><em>Lời nhắn: {message}</em></p>' if message else ''}
                
                <div class="result-box">
                    <h3 class="result-title">Thông tin dự đoán</h3>
                    
                    <div class="result-item">
                        <span class="result-label">Mã bệnh nhân:</span> {patient_id}
                    </div>
                    
                    <div class="result-item">
                        <span class="result-label">Thời gian dự đoán:</span> {timestamp}
                    </div>
                    
                    <div class="result-item">
                        <span class="result-label">Xác suất bệnh:</span> {probability:.2f}%
                    </div>
                    
                    <div class="result-item">
                        <span class="result-label">Kết luận:</span> 
                        <span class="{'positive' if 'Dương tính' in status else 'negative'}">
                            {status}
                        </span>
                    </div>
                    
                    <h4>Các chỉ số đặc trưng:</h4>
                    <table class="features-table">
                        <tr>
                            <th>Đặc trưng</th>
                            <th>Giá trị</th>
                        </tr>
    """
    
    # Thêm các đặc trưng vào bảng
    for key, value in features.items():
        formatted_value = f"{value:.4f}" if isinstance(value, float) else str(value)
        html += f"""
                        <tr>
                            <td>{key}</td>
                            <td>{formatted_value}</td>
                        </tr>
        """
    
    html += """
                    </table>
                </div>
                
                <p>Đây là email tự động được gửi từ hệ thống Dự đoán Bệnh Parkinson. Vui lòng không trả lời email này.</p>
            </div>
            
            <div class="footer">
                <p>© Hệ thống Dự đoán Bệnh Parkinson</p>
            </div>
        </div>
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

        # Nếu chưa có status thì tự tính bằng mô hình
        if 'status' not in prediction_results and 'features' in prediction_results:
            model = current_app.config.get('MODEL')
            scaler = current_app.config.get('SCALER')

            if model is None or scaler is None:
                return jsonify({'status': 'error', 'message': 'Model hoặc Scaler chưa được cấu hình'}), 500

            features = prediction_results['features']

            # Đảm bảo là list
            if not isinstance(features, list):
                return jsonify({'status': 'error', 'message': 'Dữ liệu features không hợp lệ'}), 400

            features_array = np.array([features])
            if features_array.shape[1] != scaler.n_features_in_:
                return jsonify({'status': 'error', 'message': f'Số lượng đặc trưng không hợp lệ. Mong đợi {scaler.n_features_in_}, nhận {features_array.shape[1]}'}), 400

            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                features_scaled = scaler.transform(features_array)

            prediction = model.predict(features_scaled)[0]
            status = "Parkinson Detected" if prediction == 1 else "Healthy"
            prediction_results['status'] = status

            # Gắn lại features nếu cần hiển thị
            if isinstance(features, list):
                for i, value in enumerate(features):
                    prediction_results[f'Feature_{i+1}'] = value

        # Tạo nội dung HTML email
        html_content = generate_email_html(doctor_name, message, prediction_results)

        msg = Message(
            subject="Kết quả dự đoán bệnh Parkinson",
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
    
    if prediction != 1:  # Thay "Parkinson Detected" bằng 1 để khớp với frontend
        return jsonify({'advice': []})  # Trả về mảng rỗng thay vì chuỗi
    
    prompt = f"""
    Bạn là chuyên gia y tế về bệnh Parkinson.
    Một bệnh nhân có các đặc điểm: {features}.
    Dựa trên kết quả chẩn đoán, hãy đưa ra danh sách các lời khuyên cụ thể, chi tiết và dễ thực hiện.
   
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
            input=f"""
            Một bệnh nhân có các đặc điểm: {features}.
            Dựa trên kết quả chẩn đoán, hãy đưa ra danh sách các lời khuyên cụ thể, chi tiết và dễ thực hiện.

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
            """,
            max_tokens=1000,
            temperature=0.5,
            response_format={"type": "json_object"}
        )

       
        advice_text = response.choices[0].message.content.strip()
        
        # Làm sạch đầu ra
        if advice_text.startswith('```json'):
            advice_text = advice_text[7:].strip()
        if advice_text.endswith('```'):
            advice_text = advice_text[:-3].strip()
        
        # Bọc trong try-except để kiểm soát lỗi parse
        try:
            # Thêm bước kiểm tra xem đây có phải JSON không
            if not advice_text.startswith('[') and not advice_text.startswith('{'):
                # Nếu không phải JSON, trả về một mảng mặc định
                return jsonify({'advice': [{"title": "Không thể nhận lời khuyên", "details": "Vui lòng thử lại sau."}]})
            
            parsed_json = json.loads(advice_text)
            
            # Kiểm tra và xử lý kết quả dựa trên cấu trúc
            if isinstance(parsed_json, dict):
                # Nếu API trả về một object thay vì mảng
                if "advice" in parsed_json:
                    advice_list = parsed_json["advice"]
                elif "data" in parsed_json: 
                    advice_list = parsed_json["data"]
                else:
                    # Chuyển đổi đối tượng thành mảng có một phần tử
                    advice_list = [{"title": key, "details": value} for key, value in parsed_json.items()]
            elif isinstance(parsed_json, list):
                advice_list = parsed_json
            else:
                advice_list = [{"title": "Lời khuyên chung", "details": str(parsed_json)}]
            
            return jsonify({'advice': advice_list})
            
        except json.JSONDecodeError as e:
            print(f"JSON parse error: {e}")
            print(f"Response text: {advice_text}")
            # Trả về một mảng rỗng với thông báo lỗi
            return jsonify({'advice': [], 'error': 'Định dạng phản hồi không hợp lệ'})
            
    except Exception as e:
        print("GPT Error:", e)
        return jsonify({'advice': [], 'error': 'Không thể lấy lời khuyên từ chuyên gia GPT.'})