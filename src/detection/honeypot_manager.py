import os
import shutil
import logging
from datetime import datetime
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class HoneypotManager:
    def __init__(self, base_path):
        self.base_path = base_path
        self.honeypot_files = []
        self.setup_logging()
        
    def setup_logging(self):
        logging.basicConfig(
            filename='honeypot.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def create_honeypot_files(self):
        """Create decoy files with attractive names"""
        honeypot_templates = [
            "financial_records.xlsx",
            "passwords.txt",
            "customer_database.db",
            "confidential_reports.pdf"
        ]
        
        for template in honeypot_templates:
            path = os.path.join(self.base_path, template)
            try:
                with open(path, 'w') as f:
                    f.write("HONEYPOT FILE - DO NOT MODIFY")
                self.honeypot_files.append(path)
                logging.info(f"Created honeypot file: {path}")
            except Exception as e:
                logging.error(f"Failed to create honeypot file {path}: {str(e)}")
    
    def monitor_honeypots(self):
        class HoneypotHandler(FileSystemEventHandler):
            def on_modified(self, event):
                if event.src_path in self.honeypot_files:
                    self.alert_honeypot_trigger(event.src_path)
        
        observer = Observer()
        observer.schedule(HoneypotHandler(), self.base_path, recursive=False)
        observer.start()
        return observer
    
    def alert_honeypot_trigger(self, file_path):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': 'HONEYPOT_TRIGGERED',
            'file': file_path,
            'severity': 'CRITICAL'
        }
        logging.critical(f"Honeypot triggered: {json.dumps(alert)}")