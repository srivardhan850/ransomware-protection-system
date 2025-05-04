import os
import shutil
import hashlib
from datetime import datetime
import schedule
import time
import logging

class BackupManager:
    def __init__(self, source_dir, backup_dir, retention_days=30):
        self.source_dir = source_dir
        self.backup_dir = backup_dir
        self.retention_days = retention_days
        self.setup_logging()
        
    def setup_logging(self):
        logging.basicConfig(
            filename='backup.log',
            level=logging.INFO,
            format='%(asctime)s - %(message)s'
        )
        
    def create_backup(self, source_path):
        try:
            # Create timestamp-based version
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            file_name = os.path.basename(source_path)
            backup_path = os.path.join(
                self.backup_dir, 
                f"{file_name}_{timestamp}"
            )
            
            # Create backup with file hash
            shutil.copy2(source_path, backup_path)
            file_hash = self._calculate_file_hash(backup_path)
            
            return {
                'status': 'success',
                'backup_path': backup_path,
                'hash': file_hash,
                'timestamp': timestamp
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def _calculate_file_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def restore_backup(self, backup_path, destination_path):
        try:
            shutil.copy2(backup_path, destination_path)
            return {'status': 'success'}
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
        
    def cleanup_old_backups(self):
        current_time = datetime.datetime.now()
        for backup in os.listdir(self.backup_dir):
            backup_path = os.path.join(self.backup_dir, backup)
            creation_time = datetime.datetime.fromtimestamp(os.path.getctime(backup_path))
            if (current_time - creation_time).days > self.retention_days:
                shutil.rmtree(backup_path)
                logging.info(f"Removed old backup: {backup_path}")
    
    def test_restore(self, backup_name, restore_path):
        backup_path = os.path.join(self.backup_dir, backup_name)
        try:
            shutil.copytree(backup_path, restore_path)
            logging.info(f"Test restore successful to {restore_path}")
            return True
        except Exception as e:
            logging.error(f"Test restore failed: {str(e)}")
            return False
            
    def schedule_backup(self, interval_hours=24):
        schedule.every(interval_hours).hours.do(self.create_backup)
        schedule.every(7).days.do(self.test_restore, 
                                backup_name=os.listdir(self.backup_dir)[-1],
                                restore_path="./test_restore")
        
        while True:
            schedule.run_pending()
            time.sleep(3600)

if __name__ == "__main__":
    backup_mgr = BackupManager("./protected_files", "./backups")
    backup_mgr.schedule_backup()