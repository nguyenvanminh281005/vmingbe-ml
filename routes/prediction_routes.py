from flask import Blueprint, request, jsonify, current_app
import numpy as np
import warnings

prediction_bp = Blueprint('prediction', __name__)

@prediction_bp.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        print("Received Data:", data)

        if not data or 'features' not in data or not isinstance(data['features'], list):
            return jsonify({'error': 'Dữ liệu không hợp lệ'}), 400

        model_key = data.get('model', 'best')  # nếu không gửi thì lấy mô hình mặc định
        models = current_app.config.get('MODELS', {})
        scaler = current_app.config.get('SCALER')

        if model_key not in models:
            return jsonify({'error': f"Mô hình '{model_key}' không tồn tại"}), 400
        if scaler is None:
            return jsonify({'error': 'Scaler chưa được tải'}), 500

        model = models[model_key]

        features = np.array([data['features']])
        print("Processed Features:", features)

        if features.shape[1] != scaler.n_features_in_:
            return jsonify({'error': f'Số lượng đặc trưng không hợp lệ. Mong đợi {scaler.n_features_in_}, nhận {features.shape[1]}'}), 400

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            features = scaler.transform(features)

        prediction = model.predict(features)[0]
        result = "Disease Detected" if prediction == 1 else "Healthy"

        print(f"[{model_key}] Prediction Result:", result)
        return jsonify({'prediction': result})
    
    except Exception as e:
        print("Error:", str(e))
        return jsonify({'error': str(e)}), 500
