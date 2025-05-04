import os
import stat
import logging
import psutil
from datetime import datetime

class FileAccessControl:
    def __init__(self):
        self.protected_extensions = ['.doc', '.docx', '.xls', '.xlsx', '.pdf', '.jpg', 
                                   '.ppt', '.pptx', '.txt', '.csv', '.db', '.sql']
        self.suspicious_processes = ['unknown.exe', 'ransom.exe']
        self.setup_logging()
        
    def setup_logging(self):
        logging.basicConfig(
            filename='access_control.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def protect_directory(self, directory_path):
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if any(file.endswith(ext) for ext in self.protected_extensions):
                    file_path = os.path.join(root, file)
                    self._set_readonly(file_path)
            
            # Protect directory itself
            self._protect_directory_permissions(root)
    
    def _protect_directory_permissions(self, dir_path):
        try:
            # Set directory to read-only for regular users
            os.chmod(dir_path, stat.S_IREAD | stat.S_IEXEC)
            logging.info(f"Protected directory: {dir_path}")
        except Exception as e:
            logging.error(f"Failed to protect directory {dir_path}: {str(e)}")
    
    def _set_readonly(self, file_path):
        try:
            os.chmod(file_path, stat.S_IREAD)
            logging.info(f"Protected file: {file_path}")
        except Exception as e:
            logging.error(f"Failed to protect {file_path}: {str(e)}")

    def monitor_process_access(self):
        for proc in psutil.process_iter(['name', 'username']):
            if proc.info['name'] in self.suspicious_processes:
                logging.warning(f"Suspicious process detected: {proc.info['name']} by user {proc.info['username']}")
                self._terminate_suspicious_process(proc)

    def _terminate_suspicious_process(self, process):
        try:
            process.terminate()
            logging.info(f"Terminated suspicious process: {process.info['name']}")
        except Exception as e:
            logging.error(f"Failed to terminate process: {str(e)}")

if __name__ == "__main__":
    access_control = FileAccessControl()
    access_control.protect_directory("./protected_files")