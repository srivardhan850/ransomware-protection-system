import psutil
import os
import logging
from collections import deque
from datetime import datetime, timedelta

class BehaviorAnalyzer:
    def __init__(self):
        self.activity_history = deque(maxlen=1000)
        self.baseline = {
            'avg_file_ops': 0,
            'avg_network_traffic': 0,
            'normal_processes': set(),
            'normal_extensions': set(['.txt', '.doc', '.pdf', '.jpg'])
        }
        self.setup_logging()
    
    def setup_logging(self):
        logging.basicConfig(
            filename='behavior_analysis.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def analyze_file_operations(self, path):
        suspicious_patterns = {
            'rapid_encryption': 0,
            'mass_deletion': 0,
            'extension_changes': 0
        }
        
        for root, _, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    stats = os.stat(file_path)
                    # Check for rapid modifications
                    if datetime.fromtimestamp(stats.st_mtime) > datetime.now() - timedelta(minutes=5):
                        suspicious_patterns['rapid_encryption'] += 1
                except Exception as e:
                    logging.error(f"Error analyzing file {file_path}: {str(e)}")
        
        return suspicious_patterns
    
    def analyze_process_behavior(self):
        suspicious_processes = []
        for proc in psutil.process_iter(['name', 'cpu_percent', 'memory_percent']):
            try:
                if proc.info['cpu_percent'] > 70 or proc.info['memory_percent'] > 80:
                    suspicious_processes.append({
                        'name': proc.info['name'],
                        'cpu': proc.info['cpu_percent'],
                        'memory': proc.info['memory_percent']
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return suspicious_processes
    
    def check_network_behavior(self):
        network_anomalies = []
        net_connections = psutil.net_connections()
        
        # Check for unusual network connections
        for conn in net_connections:
            if conn.status == 'ESTABLISHED':
                if conn.raddr and conn.raddr.port in [445, 139]:  # Common ransomware ports
                    network_anomalies.append({
                        'local_address': conn.laddr,
                        'remote_address': conn.raddr,
                        'status': conn.status
                    })
        
        return network_anomalies
    
    def analyze_system_behavior(self, path):
        file_patterns = self.analyze_file_operations(path)
        process_patterns = self.analyze_process_behavior()
        network_patterns = self.check_network_behavior()
        
        # Combine all analyses
        if (file_patterns['rapid_encryption'] > 10 or
            len(process_patterns) > 3 or
            len(network_patterns) > 2):
            self.alert_suspicious_behavior({
                'file_patterns': file_patterns,
                'process_patterns': process_patterns,
                'network_patterns': network_patterns
            })
    
    def alert_suspicious_behavior(self, details):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': 'SUSPICIOUS_BEHAVIOR',
            'details': details,
            'severity': 'HIGH'
        }
        logging.warning(f"Suspicious behavior detected: {json.dumps(alert)}")