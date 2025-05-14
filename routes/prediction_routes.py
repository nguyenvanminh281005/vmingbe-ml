from flask import Blueprint, request, jsonify, current_app
import numpy as np
import warnings
import traceback

prediction_bp = Blueprint('prediction', __name__)

@prediction_bp.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        print("Received Data:", data)

        if not data:
            return jsonify({'error': 'Không nhận được dữ liệu JSON'}), 400
            
        # Xử lý cả trường hợp 'features' và 'feature' (phòng trường hợp frontend gọi sai key)
        features_data = None
        if 'features' in data and isinstance(data['features'], list):
            features_data = data['features']
        elif 'feature' in data and isinstance(data['feature'], list):
            features_data = data['feature']
        else:
            return jsonify({'error': 'Thiếu hoặc không đúng định dạng của trường "features"'}), 400
            
        # Kiểm tra model key
        model_key = data.get('model', 'best_model')  # Đảm bảo tên mặc định giống frontend
        models = current_app.config.get('MODELS', {})
        
        # Kiểm tra và lấy scaler
        scaler = current_app.config.get('SCALER')
        if scaler is None:
            return jsonify({'error': 'Scaler chưa được tải'}), 500
            
        # Kiểm tra model tồn tại
        if model_key not in models:
            available_models = list(models.keys())
            return jsonify({
                'error': f"Mô hình '{model_key}' không tồn tại",
                'available_models': available_models
            }), 400
            
        model = models[model_key]

        # Chuyển features thành numpy array, xử lý cả trường hợp người dùng gửi số dưới dạng string
        try:
            features_numeric = [float(x) for x in features_data]
            features = np.array([features_numeric])
        except (ValueError, TypeError):
            return jsonify({'error': 'Các giá trị đặc trưng phải là số'}), 400
            
        print("Processed Features:", features)

        # Kiểm tra số lượng đặc trưng
        expected_features = getattr(scaler, 'n_features_in_', 10)  # Fallback to 10 if attribute doesn't exist
        if features.shape[1] != expected_features:
            return jsonify({
                'error': f'Số lượng đặc trưng không hợp lệ. Mong đợi {expected_features}, nhận {features.shape[1]}'
            }), 400

        # Tiền xử lý dữ liệu với scaler
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                features_scaled = scaler.transform(features)
                
            # Dự đoán
            prediction = model.predict(features_scaled)[0]
            
            # Xử lý trường hợp model trả về giá trị dự đoán không phải 0/1
            if isinstance(prediction, np.ndarray) and prediction.size > 0:
                prediction = prediction[0]
                
            result = "Disease Detected" if int(prediction) == 1 else "Healthy"
            probability = None
            
            # Thêm xác suất nếu model hỗ trợ predict_proba
            if hasattr(model, 'predict_proba'):
                try:
                    proba = model.predict_proba(features_scaled)[0]
                    probability = float(proba[1]) if len(proba) > 1 else None
                except:
                    pass  # Bỏ qua nếu không lấy được xác suất
                    
            response = {
                'prediction': result,
                'prediction_code': int(prediction)
            }
            
            if probability is not None:
                response['probability'] = probability
                
            print(f"[{model_key}] Prediction Result:", response)
            return jsonify(response)
            
        except Exception as e:
            print(f"Error during prediction: {str(e)}")
            traceback.print_exc()
            return jsonify({'error': f'Lỗi khi dự đoán: {str(e)}'}), 500
    
    except Exception as e:
        print("Error:", str(e))
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@prediction_bp.route('/predict_batch', methods=['POST'])
def predict_batch():
    try:
        data = request.get_json()
        print("Received Batch Data:", data)

        if not data:
            return jsonify({'error': 'Không nhận được dữ liệu JSON'}), 400
            
        # Kiểm tra features_list hoặc batch_features
        features_list = None
        if 'features_list' in data and isinstance(data['features_list'], list):
            features_list = data['features_list']
        elif 'batch_features' in data and isinstance(data['batch_features'], list):
            features_list = data['batch_features']
        else:
            return jsonify({'error': 'Thiếu hoặc không đúng định dạng của trường "features_list"'}), 400

        # Kiểm tra model key  
        model_key = data.get('model', 'best_model')  # Đảm bảo tên mặc định giống frontend
        models = current_app.config.get('MODELS', {})
        scaler = current_app.config.get('SCALER')

        if model_key not in models:
            available_models = list(models.keys())
            return jsonify({
                'error': f"Mô hình '{model_key}' không tồn tại",
                'available_models': available_models
            }), 400
            
        if scaler is None:
            return jsonify({'error': 'Scaler chưa được tải'}), 500

        model = models[model_key]

        # Chuyển features thành numpy array, với xử lý lỗi
        try:
            # Chuyển đổi tất cả giá trị sang số
            features_numeric = []
            for row in features_list:
                try:
                    numeric_row = [float(x) for x in row]
                    features_numeric.append(numeric_row)
                except (ValueError, TypeError):
                    return jsonify({'error': f'Có giá trị không phải số trong dữ liệu'}), 400
                    
            features_array = np.array(features_numeric)
        except Exception as e:
            return jsonify({'error': f'Lỗi khi xử lý dữ liệu: {str(e)}'}), 400

        print("Processed Features Array:", features_array.shape)

        # Kiểm tra số lượng đặc trưng
        expected_features = getattr(scaler, 'n_features_in_', 10)  # Fallback to 10 if attribute doesn't exist
        if features_array.shape[1] != expected_features:
            return jsonify({
                'error': f'Số lượng đặc trưng không hợp lệ. Mong đợi {expected_features}, nhận {features_array.shape[1]}'
            }), 400

        # Tiền xử lý và dự đoán
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                features_scaled = scaler.transform(features_array)

            predictions = model.predict(features_scaled)
            
            # Thêm xác suất nếu model hỗ trợ
            probabilities = None
            if hasattr(model, 'predict_proba'):
                try:
                    probabilities = model.predict_proba(features_scaled)
                except:
                    pass  # Bỏ qua nếu không lấy được xác suất

            # Tạo danh sách kết quả
            result_list = []
            for i, pred in enumerate(predictions):
                # Đảm bảo pred là giá trị số nguyên
                pred_value = int(pred) if not isinstance(pred, np.ndarray) else int(pred[0])
                
                result = {
                    'index': i,
                    'prediction': "Disease Detected" if pred_value == 1 else "Healthy",
                    'prediction_code': pred_value
                }
                
                # Thêm xác suất nếu có
                if probabilities is not None:
                    result['probability'] = float(probabilities[i][1]) if len(probabilities[i]) > 1 else None
                
                result_list.append(result)

            print(f"[{model_key}] Batch Predictions: {len(result_list)} results")
            return jsonify({
                'results': result_list,
                'count': len(result_list)
            })

        except Exception as e:
            print(f"Error during batch prediction: {str(e)}")
            traceback.print_exc()
            return jsonify({'error': f'Lỗi khi dự đoán hàng loạt: {str(e)}'}), 500

    except Exception as e:
        print("Error in batch prediction:", str(e))
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500