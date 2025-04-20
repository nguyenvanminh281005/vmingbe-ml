from flask import Blueprint, request, jsonify, current_app
import numpy as np
import warnings

prediction_bp = Blueprint('prediction', __name__)

@prediction_bp.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        print("Received Data:", data)

        # Kiểm tra dữ liệu đầu vào
        if not data or 'features' not in data or not isinstance(data['features'], list):
            return jsonify({'error': 'Dữ liệu không hợp lệ'}), 400
        
        # Lấy model và scaler từ config
        model = current_app.config.get('MODEL')
        scaler = current_app.config.get('SCALER')
        
        if model is None or scaler is None:
            return jsonify({'error': 'Model chưa được tải'}), 500

        # Chuyển đổi thành numpy array
        features = np.array([data['features']])
        print("Processed Features:", features)

        if features.shape[1] != scaler.n_features_in_:
            return jsonify({'error': f'Số lượng đặc trưng không hợp lệ. Mong đợi {scaler.n_features_in_}, nhận {features.shape[1]}'}), 400

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            features = scaler.transform(features)

        prediction = model.predict(features)[0]
        result = "Parkinson's Detected" if prediction == 1 else "Healthy"

        print("Prediction Result:", result)
        return jsonify({'prediction': result})
    
    except Exception as e:
        print("Error:", str(e))
        return jsonify({'error': str(e)}), 500
