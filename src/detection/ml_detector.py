import numpy as np
from sklearn.ensemble import IsolationForest
import logging
import json
from datetime import datetime

class MLRansomwareDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1)
        self.setup_logging()
        
    def setup_logging(self):
        logging.basicConfig(
            filename='ml_detection.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def extract_features(self, system_activity):
        """
        Extract features from system activity:
        - File operations per second
        - Network traffic patterns
        - CPU usage
        - Memory usage
        - File entropy
        """
        features = [
            system_activity['file_ops_per_sec'],
            system_activity['network_traffic'],
            system_activity['cpu_usage'],
            system_activity['memory_usage'],
            system_activity['file_entropy']
        ]
        return np.array(features).reshape(1, -1)
    
    def train(self, historical_data):
        """Train the model on historical system behavior"""
        try:
            features = np.array([self.extract_features(data)[0] for data in historical_data])
            self.model.fit(features)
            logging.info("Model training completed successfully")
        except Exception as e:
            logging.error(f"Model training failed: {str(e)}")
    
    def detect_anomaly(self, current_activity):
        """Detect if current activity is anomalous"""
        try:
            features = self.extract_features(current_activity)
            prediction = self.model.predict(features)
            if prediction[0] == -1:  # Anomaly detected
                self.alert_anomaly(current_activity)
                return True
            return False
        except Exception as e:
            logging.error(f"Anomaly detection failed: {str(e)}")
            return False
    
    def alert_anomaly(self, activity):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': 'ML_ANOMALY_DETECTION',
            'details': activity,
            'severity': 'HIGH'
        }
        logging.warning(f"Anomaly detected: {json.dumps(alert)}")