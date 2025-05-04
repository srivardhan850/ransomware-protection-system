import os
import time
import logging
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime

class RansomwareDetector(FileSystemEventHandler):
    def __init__(self):
        self.suspicious_patterns = {
            'extensions': ['.encrypted', '.crypto', '.locked', '.crypt', '.crypted', '.crinf'],
            'max_changes_per_second': 10,
            'suspicious_processes': ['unknown.exe', 'ransom.exe']
        }
        self.changes_count = 0
        self.last_check_time = time.time()
        self.setup_logging()
        
    def setup_logging(self):
        logging.basicConfig(
            filename='ransomware_detection.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def check_suspicious_processes(self):
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] in self.suspicious_patterns['suspicious_processes']:
                logging.warning(f"Suspicious process detected: {proc.info['name']}")
                return True
        return False

    def on_modified(self, event):
        if not event.is_directory:
            current_time = time.time()
            self.changes_count += 1
            
            # Check file extension
            if any(event.src_path.endswith(ext) for ext in self.suspicious_patterns['extensions']):
                self.alert("Suspicious file extension detected", event.src_path)
            
            # Check rapid file modifications
            if current_time - self.last_check_time > 1:
                self.changes_count = 0
                self.last_check_time = current_time

            if self.changes_count > self.suspicious_patterns['max_changes_per_second']:
                self.alert("Rapid file modifications detected", event.src_path)
            
            # Check suspicious processes
            if self.check_suspicious_processes():
                self.alert("Suspicious process detected", "System-wide check")

    def alert(self, reason, path):
        message = f"ALERT: {reason} at {path}"
        logging.critical(message)
        # Here you would implement your alert mechanism (email, SMS, etc.)
        print(message)

def start_monitoring(path):
    event_handler = RansomwareDetector()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    path_to_monitor = "."  # Monitor current directory
    start_monitoring(path_to_monitor)