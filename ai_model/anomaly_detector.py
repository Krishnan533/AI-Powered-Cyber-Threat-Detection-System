import os
import warnings
import joblib
import numpy as np

class AnomalyDetector:
    """Interface to load Isolation Forest models and scale features to detect anomalies."""
    
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.model_path = os.path.join(self.base_dir, "model.pkl")
        self.scaler_path = os.path.join(self.base_dir, "scaler.pkl")
        self.model = None
        self.scaler = None
        self.load_model()
        
    def load_model(self):
        """Loads model and scaler binaries from disk. Falls back to generating dummy rules if not trained yet."""
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("error", category=UserWarning)
                    self.model = joblib.load(self.model_path)
                    self.scaler = joblib.load(self.scaler_path)
                print("AnomalyDetector: Isolation Forest model and scaler loaded successfully.")
            except Warning as warn:
                print(f"AnomalyDetector Warning: Model artifact compatibility issue: {warn}. Anomaly detection will use fallback rules.")
                self.model = None
                self.scaler = None
            except Exception as e:
                print(f"AnomalyDetector Warning: Failed to load model files: {e}. Anomaly detection will use fallback rules.")
                self.model = None
                self.scaler = None
        else:
            print("AnomalyDetector Warning: Trained model files not found. Anomaly detection will use fallback rules until model is trained.")

    def is_trained(self):
        return self.model is not None and self.scaler is not None

    def predict_packet(self, packet_size, protocol, src_port, dst_port, time_delta):
        """
        Predicts if a single packet is an anomaly.
        
        Parameters:
        - packet_size (int)
        - protocol (str): 'TCP', 'UDP', 'ICMP', or others.
        - src_port (int or None)
        - dst_port (int or None)
        - time_delta (float): time difference since last packet from the same source IP.
        
        Returns:
        - is_anomaly (bool)
        - anomaly_score (float): ranges 0.0 to 1.0 (higher means more anomalous)
        """
        # Convert inputs to numerical features
        protocol_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1}
        proto_num = protocol_map.get(protocol.upper(), 0)
        
        sport = src_port if src_port is not None else 0
        dport = dst_port if dst_port is not None else 0
        
        features = np.array([[packet_size, proto_num, sport, dport, time_delta]])
        
        if self.is_trained():
            try:
                # Scale features
                features_scaled = self.scaler.transform(features)
                # Prediction (1 = inlier, -1 = outlier)
                prediction = self.model.predict(features_scaled)[0]
                
                # Isolation Forest decision_function returns signed anomaly scores:
                # Negative values represent anomalies, positive represent normal.
                # Standardize to a 0-1 scale.
                raw_score = self.model.decision_function(features_scaled)[0]
                # Map range approx [-0.5, 0.5] to [1.0, 0.0]
                anomaly_score = float(np.clip(0.5 - raw_score, 0.0, 1.0))
                
                return (prediction == -1), anomaly_score
            except Exception as e:
                print(f"AnomalyDetector Error during inference: {e}")
                
        # Fallback heuristic rules if model isn't initialized or crashes
        is_anomaly = False
        score_accumulator = 0.0
        
        # Heuristic 1: Extremely large packet sizes
        if packet_size > 1450:
            score_accumulator += 0.3
        # Heuristic 2: Suspicious ports (typical malware/trojan or scanning activity)
        suspicious_ports = {6667, 31337, 4444, 135, 139, 445}
        if sport in suspicious_ports or dport in suspicious_ports:
            score_accumulator += 0.4
            is_anomaly = True
        # Heuristic 3: Extremely fast arrival
        if time_delta < 0.001:
            score_accumulator += 0.2
            
        if score_accumulator >= 0.5:
            is_anomaly = True
            
        return is_anomaly, float(np.clip(score_accumulator, 0.0, 1.0))
