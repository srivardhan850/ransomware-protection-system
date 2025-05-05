import psutil
import logging
from datetime import datetime
import json

class NetworkMonitor:
    def __init__(self):
        self.suspicious_ports = [445, 139, 3389]  # Common ransomware ports
        self.connection_history = {}
        self.setup_logging()
    
    def setup_logging(self):
        logging.basicConfig(
            filename='network_monitor.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def monitor_connections(self):
        suspicious_connections = []
        try:
            for conn in psutil.net_connections():
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    if conn.raddr.port in self.suspicious_ports:
                        connection_info = {
                            'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}",
                            'pid': conn.pid,
                            'timestamp': datetime.now().isoformat()
                        }
                        suspicious_connections.append(connection_info)
                        self.log_suspicious_connection(connection_info)
            
            return suspicious_connections
        except Exception as e:
            logging.error(f"Error monitoring network connections: {str(e)}")
            return []
    
    def log_suspicious_connection(self, connection_info):
        logging.warning(f"Suspicious network connection detected: {json.dumps(connection_info)}")