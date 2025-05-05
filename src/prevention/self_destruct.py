import os
import logging
from cryptography.fernet import Fernet
from datetime import datetime

class SelfDestructMechanism:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)
        self.setup_logging()
    
    def setup_logging(self):
        logging.basicConfig(
            filename='self_destruct.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def encrypt_file_with_timer(self, file_path):
        try:
            with open(file_path, 'rb') as file:
                file_data = file.read()
            encrypted_data = self.cipher_suite.encrypt(file_data)
            timed_data = self.add_destruct_timer(encrypted_data)
            with open(file_path, 'wb') as file:
                file.write(timed_data)
            logging.info(f"File protected with self-destruct: {file_path}")
            return True
        except Exception as e:
            logging.error(f"Failed to protect file {file_path}: {str(e)}")
            return False
    
    def add_destruct_timer(self, encrypted_data):
        # Add timestamp and destruction trigger
        timestamp = datetime.now().timestamp()
        header = f"SELF_DESTRUCT_{timestamp}_".encode()
        return header + encrypted_data
    
    def check_and_destroy(self, file_path):
        try:
            with open(file_path, 'rb') as file:
                data = file.read()
            
            if data.startswith(b"SELF_DESTRUCT_"):
                # Trigger self-destruction
                self.destroy_file(file_path)
                return True
            return False
        except Exception as e:
            logging.error(f"Error checking file {file_path}: {str(e)}")
            return False
    
    def destroy_file(self, file_path):
        try:
            # Overwrite file with random data before deletion
            with open(file_path, 'wb') as file:
                file.write(os.urandom(1024))
            # Delete the file
            os.remove(file_path)
            logging.info(f"File self-destructed: {file_path}")
            return True
        except Exception as e:
            logging.error(f"Failed to destroy file {file_path}: {str(e)}")
            return False