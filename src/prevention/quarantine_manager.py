import os
import shutil
import logging
from datetime import datetime

class QuarantineManager:
    def __init__(self, quarantine_dir="quarantine"):
        self.quarantine_dir = quarantine_dir
        if not os.path.exists(quarantine_dir):
            os.makedirs(quarantine_dir)
        self.setup_logging()
    
    def setup_logging(self):
        logging.basicConfig(
            filename='quarantine.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def quarantine_file(self, file_path):
        try:
            filename = os.path.basename(file_path)
            quarantine_path = os.path.join(
                self.quarantine_dir,
                f"{filename}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )
            shutil.move(file_path, quarantine_path)
            logging.info(f"File quarantined: {file_path} -> {quarantine_path}")
            return True
        except Exception as e:
            logging.error(f"Failed to quarantine file {file_path}: {str(e)}")
            return False
    
    def restore_file(self, quarantine_path, restore_path):
        try:
            shutil.move(quarantine_path, restore_path)
            logging.info(f"File restored: {quarantine_path} -> {restore_path}")
            return True
        except Exception as e:
            logging.error(f"Failed to restore file {quarantine_path}: {str(e)}")
            return False