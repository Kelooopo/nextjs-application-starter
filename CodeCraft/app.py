import sys
import os
import json
import threading
import time
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, session
from flask_socketio import SocketIO, emit
import platform
import psutil
import logging
from monitoring.system_monitor import SystemMonitor
from monitoring.network_monitor import NetworkMonitor
from monitoring.file_monitor import FileMonitor
from monitoring.threat_intel import ThreatIntelligence
from utils.encryption import EncryptionManager
from utils.email_notifier import EmailNotifier
from utils.logger import SecurityLogger

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'sentinelwatch-pro-2025')
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variables
running = True
monitoring_threads = []
alert_history = []
system_stats = []
security_events = []

# Configuration
CONFIG_FILE = 'config.json'
LOG_DIR = 'logs'
DEFAULT_CONFIG = {
    'whitelist_processes': ['explorer.exe', 'svchost.exe', 'cmd.exe', 'python.exe'] if platform.system() == "Windows" else ['bash', 'python3', 'systemd'],
    'monitored_ports': [22, 3389, 5900, 80, 443],
    'monitored_dirs': [os.path.expanduser('~/Documents'), os.path.expanduser('~/Downloads')],
    'email_enabled': False,
    'email_to': '',
    'email_from': '',
    'email_password': '',
    'virustotal_api_key': os.getenv('VIRUSTOTAL_API_KEY', ''),
    'otx_api_key': os.getenv('OTX_API_KEY', ''),
    'monitor_logins': True,
    'monitor_processes': True,
    'monitor_network': True,
    'monitor_files': False,
    'process_cpu_threshold': 80.0,
    'process_mem_threshold': 500.0,
    'network_sniff_interface': 'eth0' if platform.system() != "Windows" else 'Ethernet',
    'monitoring_interval': 30
}

# Initialize components
os.makedirs(LOG_DIR, exist_ok=True)
encryption_manager = EncryptionManager()
security_logger = SecurityLogger(LOG_DIR)

def load_config():
    """Load configuration from file or create default"""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
            # Ensure all default keys are present
            for key, value in DEFAULT_CONFIG.items():
                if key not in config:
                    config[key] = value
        else:
            config = DEFAULT_CONFIG.copy()
            save_config(config)
        
        # Decrypt sensitive data
        if config.get('email_password'):
            try:
                config['email_password'] = encryption_manager.decrypt(config['email_password'])
            except:
                config['email_password'] = ''
        
        return config
    except Exception as e:
        security_logger.log_error(f"Error loading config: {e}")
        return DEFAULT_CONFIG.copy()

def save_config(config):
    """Save configuration to file with encryption for sensitive data"""
    try:
        config_to_save = config.copy()
        if config_to_save.get('email_password'):
            config_to_save['email_password'] = encryption_manager.encrypt(config_to_save['email_password'])
        
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config_to_save, f, indent=4)
    except Exception as e:
        security_logger.log_error(f"Error saving config: {e}")

# Load initial configuration
config = load_config()

# Initialize monitoring components
system_monitor = SystemMonitor(config)
network_monitor = NetworkMonitor(config)
file_monitor = FileMonitor(config)
threat_intel = ThreatIntelligence(config)
email_notifier = EmailNotifier(config)

def broadcast_alert(alert):
    """Broadcast alert to all connected clients"""
    global alert_history
    alert['timestamp'] = datetime.now().isoformat()
    alert_history.append(alert)
    
    # Keep only last 1000 alerts
    if len(alert_history) > 1000:
        alert_history = alert_history[-1000:]
    
    # Log the alert
    security_logger.log_alert(alert)
    
    # Send email notification if enabled
    if config.get('email_enabled'):
        try:
            email_notifier.send_alert(alert)
        except Exception as e:
            security_logger.log_error(f"Email notification failed: {e}")
    
    # Broadcast to web clients
    socketio.emit('new_alert', alert)

def monitoring_worker():
    """Main monitoring loop"""
    global running
    
    while running:
        try:
            # System monitoring
            if config.get('monitor_processes'):
                alerts = system_monitor.check_processes()
                for alert in alerts:
                    broadcast_alert(alert)
            
            # Network monitoring
            if config.get('monitor_network'):
                alerts = network_monitor.check_connections()
                for alert in alerts:
                    broadcast_alert(alert)
            
            # Update system statistics
            stats = {
                'timestamp': datetime.now().isoformat(),
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent,
                'network_connections': len(psutil.net_connections())
            }
            system_stats.append(stats)
            
            # Keep only last 100 stats
            if len(system_stats) > 100:
                system_stats.pop(0)
            
            # Broadcast system stats
            socketio.emit('system_stats', stats)
            
            time.sleep(config.get('monitoring_interval', 30))
            
        except Exception as e:
            security_logger.log_error(f"Monitoring error: {e}")
            time.sleep(5)

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/api/config', methods=['GET', 'POST'])
def api_config():
    """Get or update configuration"""
    global config
    
    if request.method == 'GET':
        # Return config without sensitive data for display
        safe_config = config.copy()
        if 'email_password' in safe_config:
            safe_config['email_password'] = '***' if safe_config['email_password'] else ''
        return jsonify(safe_config)
    
    elif request.method == 'POST':
        try:
            new_config = request.json
            
            # Validate and update config
            for key in DEFAULT_CONFIG.keys():
                if key in new_config:
                    config[key] = new_config[key]
            
            # Update monitoring components
            system_monitor.update_config(config)
            network_monitor.update_config(config)
            file_monitor.update_config(config)
            threat_intel.update_config(config)
            email_notifier.update_config(config)
            
            save_config(config)
            return jsonify({'status': 'success'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/api/alerts')
def api_alerts():
    """Get alert history"""
    filter_type = request.args.get('filter', 'all').lower()
    limit = int(request.args.get('limit', 100))
    
    filtered_alerts = alert_history
    if filter_type != 'all':
        filtered_alerts = [a for a in alert_history if a.get('type', '').lower() == filter_type]
    
    return jsonify(filtered_alerts[-limit:])

@app.route('/api/stats')
def api_stats():
    """Get system statistics"""
    hours = int(request.args.get('hours', 1))
    cutoff_time = datetime.now() - timedelta(hours=hours)
    
    filtered_stats = [
        s for s in system_stats 
        if datetime.fromisoformat(s['timestamp']) > cutoff_time
    ]
    
    return jsonify(filtered_stats)

@app.route('/api/system-info')
def api_system_info():
    """Get current system information"""
    try:
        info = {
            'platform': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'cpu_count': psutil.cpu_count(),
            'memory_total': psutil.virtual_memory().total,
            'disk_total': psutil.disk_usage('/').total,
            'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            'uptime': str(datetime.now() - datetime.fromtimestamp(psutil.boot_time()))
        }
        return jsonify(info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan-file', methods=['POST'])
def api_scan_file():
    """Scan a file for threats"""
    try:
        file_path = request.json.get('file_path')
        if not file_path or not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 400
        
        result = threat_intel.scan_file(file_path)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs')
def api_logs():
    """Get recent log entries"""
    try:
        lines = int(request.args.get('lines', 100))
        logs = security_logger.get_recent_logs(lines)
        return jsonify(logs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print(f"Client connected: {request.sid}")
    # Send current system stats to new client
    if system_stats:
        emit('system_stats', system_stats[-1])

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print(f"Client disconnected: {request.sid}")

@socketio.on('start_monitoring')
def handle_start_monitoring():
    """Start monitoring processes"""
    global monitoring_threads
    
    if not any(t.is_alive() for t in monitoring_threads):
        monitoring_thread = threading.Thread(target=monitoring_worker, daemon=True)
        monitoring_thread.start()
        monitoring_threads.append(monitoring_thread)
        
        # Start file monitoring if enabled
        if config.get('monitor_files'):
            file_monitor.start_monitoring(broadcast_alert)
        
        emit('monitoring_status', {'status': 'started'})

@socketio.on('stop_monitoring')
def handle_stop_monitoring():
    """Stop monitoring processes"""
    global running
    running = False
    file_monitor.stop_monitoring()
    emit('monitoring_status', {'status': 'stopped'})

if __name__ == '__main__':
    try:
        # Start monitoring automatically
        monitoring_thread = threading.Thread(target=monitoring_worker, daemon=True)
        monitoring_thread.start()
        monitoring_threads.append(monitoring_thread)
        
        # Start file monitoring if enabled
        if config.get('monitor_files'):
            file_monitor.start_monitoring(broadcast_alert)
        
        print("SentinelWatch Pro Web Interface starting...")
        print(f"Dashboard will be available at: http://localhost:5000")
        
        socketio.run(app, host='0.0.0.0', port=5000, debug=False)
        
    except KeyboardInterrupt:
        print("\nShutting down SentinelWatch Pro...")
        running = False
        file_monitor.stop_monitoring()
    except Exception as e:
        print(f"Error starting application: {e}")
