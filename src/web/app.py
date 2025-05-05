from flask import Flask, render_template, jsonify, request
import os
import logging
from datetime import datetime
import sys
from flask_sqlalchemy import SQLAlchemy
from email.mime.text import MIMEText
import smtplib
from prevention.self_destruct import SelfDestructMechanism

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from monitor.filesystem_monitor import RansomwareDetector
from detection.honeypot_manager import HoneypotManager
from prevention.file_access_control import FileAccessControl
from backup.backup_manager import BackupManager

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ransomware_protection.db'
db = SQLAlchemy(app)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    type = db.Column(db.String(50))
    message = db.Column(db.String(500))
    severity = db.Column(db.String(20))
    email_sent = db.Column(db.Boolean, default=False)

# Configure logging
logging.basicConfig(
    filename='ransomware_detection.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def get_status():
    active_threats = 0
    try:
        # Check for suspicious activities
        honeypot_triggers = len([f for f in os.listdir('honeypots') if f.endswith('.trigger')])
        suspicious_files = len([f for f in os.listdir('protected') if f.endswith('.encrypted')])
        
        # Update active threats count
        active_threats = honeypot_triggers + suspicious_files
        
        # Add alert if threats detected
        if active_threats > 0:
            add_test_alert(
                type='ransomware',
                message=f'Suspicious activity detected! {active_threats} potential threats found.',
                severity='critical'
            )
    except Exception as e:
        logging.error(f"Error checking threats: {str(e)}")

    return jsonify({
        'system_status': 'active',
        'last_backup': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'protected_dirs': len(os.listdir('protected')) if os.path.exists('protected') else 0,
        'active_threats': active_threats,
        'alerts': get_recent_alerts()
    })

@app.route('/api/protect', methods=['POST'])
def protect_directory():
    directory = request.json.get('directory')
    if directory and os.path.exists(directory):
        try:
            # Initialize self-destruct mechanism
            self_destruct = SelfDestructMechanism()
            
            # Add directory to protected list
            with open('protected_directories.txt', 'a') as f:
                f.write(f"{directory}\n")
            
            # Apply self-destruct protection to all files
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    self_destruct.encrypt_file_with_timer(file_path)
                    
            logging.info(f"Added directory to protection with self-destruct: {directory}")
            return jsonify({'status': 'success'})
        except Exception as e:
            logging.error(f"Failed to protect directory: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)})
    return jsonify({'status': 'error', 'message': 'Invalid directory path'})

@app.route('/api/settings', methods=['POST'])
def save_settings():
    settings = request.json
    try:
        with open('settings.txt', 'w') as f:
            f.write(f"backup_frequency={settings.get('backupFrequency', 24)}\n")
            f.write(f"alert_threshold={settings.get('alertThreshold', 10)}\n")
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/statistics')
def get_statistics():
    try:
        # Get statistics from various components
        stats = {
            'total_protected_files': sum(1 for _ in os.walk('protected')),
            'backup_count': len(os.listdir('backups')) if os.path.exists('backups') else 0,
            'honeypot_triggers': len([f for f in os.listdir('honeypots') if f.endswith('.trigger')]),
            'system_uptime': time.time() - psutil.boot_time(),
            'monitoring_status': {
                'filesystem': True,
                'processes': True,
                'network': True
            }
        }
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def get_recent_alerts():
    try:
        alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(10).all()
        return [f"{alert.timestamp} - {alert.severity} - {alert.message}" for alert in alerts]
    except Exception as e:
        logging.error(f"Error reading alerts: {str(e)}")
        return []

@app.route('/api/test-alert', methods=['POST'])
def add_test_alert():
    try:
        test_alert = Alert(
            type='test',
            message='This is a test alert',
            severity='info'
        )
        db.session.add(test_alert)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Test alert added'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

def send_alert_email(alert_message, severity):
    try:
        smtp_server = "smtp.gmail.com"
        port = 587
        sender_email = "your-email@gmail.com"
        receiver_email = "admin@example.com"
        password = os.environ.get('EMAIL_PASSWORD')

        msg = MIMEText(alert_message)
        msg['Subject'] = f'Ransomware Protection Alert - {severity.upper()}'
        msg['From'] = sender_email
        msg['To'] = receiver_email

        with smtplib.SMTP(smtp_server, port) as server:
            server.starttls()
            server.login(sender_email, password)
            server.send_message(msg)
            
        return True
    except Exception as e:
        logging.error(f"Failed to send email alert: {str(e)}")
        return False

if __name__ == '__main__':
    # Create necessary directories if they don't exist
    for directory in ['honeypots', 'protected', 'backups']:
        if not os.path.exists(directory):
            os.makedirs(directory)
    
    with app.app_context():
        db.create_all()  # Create database tables
    
    app.run(debug=True)