import os
import logging
import json
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler

class SecurityLogger:
    def __init__(self, log_dir='logs'):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
        # Setup main logger
        self.logger = logging.getLogger('sentinelwatch')
        self.logger.setLevel(logging.INFO)
        
        # Create formatters
        self.formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Setup file handlers
        self._setup_file_handlers()
        
        # Setup console handler
        self._setup_console_handler()
    
    def _setup_file_handlers(self):
        """Setup rotating file handlers for different log types"""
        # Main log file
        main_log_file = os.path.join(self.log_dir, 'sentinelwatch.log')
        main_handler = RotatingFileHandler(
            main_log_file, maxBytes=10*1024*1024, backupCount=5
        )
        main_handler.setLevel(logging.INFO)
        main_handler.setFormatter(self.formatter)
        self.logger.addHandler(main_handler)
        
        # Alert log file
        alert_log_file = os.path.join(self.log_dir, 'alerts.log')
        self.alert_handler = RotatingFileHandler(
            alert_log_file, maxBytes=5*1024*1024, backupCount=3
        )
        self.alert_handler.setLevel(logging.WARNING)
        self.alert_handler.setFormatter(self.formatter)
        
        # Error log file
        error_log_file = os.path.join(self.log_dir, 'errors.log')
        self.error_handler = RotatingFileHandler(
            error_log_file, maxBytes=5*1024*1024, backupCount=3
        )
        self.error_handler.setLevel(logging.ERROR)
        self.error_handler.setFormatter(self.formatter)
        self.logger.addHandler(self.error_handler)
    
    def _setup_console_handler(self):
        """Setup console handler for important messages"""
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        console_handler.setFormatter(self.formatter)
        self.logger.addHandler(console_handler)
    
    def log_info(self, message):
        """Log informational message"""
        self.logger.info(message)
    
    def log_warning(self, message):
        """Log warning message"""
        self.logger.warning(message)
    
    def log_error(self, message):
        """Log error message"""
        self.logger.error(message)
    
    def log_alert(self, alert):
        """Log security alert"""
        alert_message = f"ALERT - {alert.get('severity', 'UNKNOWN').upper()}: {alert.get('title', 'Security Alert')} - {alert.get('message', '')}"
        
        # Log to main logger
        if alert.get('severity') == 'high':
            self.logger.error(alert_message)
        elif alert.get('severity') == 'medium':
            self.logger.warning(alert_message)
        else:
            self.logger.info(alert_message)
        
        # Log to alert file with JSON format
        alert_entry = {
            'timestamp': alert.get('timestamp', datetime.now().isoformat()),
            'type': alert.get('type', 'unknown'),
            'severity': alert.get('severity', 'unknown'),
            'title': alert.get('title', 'Security Alert'),
            'message': alert.get('message', ''),
            'details': {k: v for k, v in alert.items() if k not in ['timestamp', 'type', 'severity', 'title', 'message']}
        }
        
        try:
            with open(os.path.join(self.log_dir, 'alerts.json'), 'a') as f:
                f.write(json.dumps(alert_entry) + '\n')
        except Exception as e:
            self.logger.error(f"Failed to write alert to JSON log: {e}")
    
    def log_system_event(self, event_type, message, details=None):
        """Log system event"""
        event_message = f"SYSTEM - {event_type}: {message}"
        if details:
            event_message += f" - Details: {json.dumps(details)}"
        
        self.logger.info(event_message)
    
    def get_recent_logs(self, lines=100, log_type='main'):
        """Get recent log entries"""
        try:
            log_files = {
                'main': 'sentinelwatch.log',
                'alerts': 'alerts.log',
                'errors': 'errors.log'
            }
            
            log_file = os.path.join(self.log_dir, log_files.get(log_type, 'sentinelwatch.log'))
            
            if not os.path.exists(log_file):
                return []
            
            with open(log_file, 'r') as f:
                all_lines = f.readlines()
                return [line.strip() for line in all_lines[-lines:]]
        
        except Exception as e:
            self.logger.error(f"Failed to read log file: {e}")
            return [f"Error reading logs: {str(e)}"]
    
    def get_alerts_summary(self, hours=24):
        """Get summary of alerts from the last N hours"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            alerts_file = os.path.join(self.log_dir, 'alerts.json')
            
            if not os.path.exists(alerts_file):
                return {
                    'total': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'by_type': {}
                }
            
            summary = {
                'total': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'by_type': {}
            }
            
            with open(alerts_file, 'r') as f:
                for line in f:
                    try:
                        alert = json.loads(line.strip())
                        alert_time = datetime.fromisoformat(alert['timestamp'])
                        
                        if alert_time >= cutoff_time:
                            summary['total'] += 1
                            
                            severity = alert.get('severity', 'unknown')
                            if severity in summary:
                                summary[severity] += 1
                            
                            alert_type = alert.get('type', 'unknown')
                            if alert_type not in summary['by_type']:
                                summary['by_type'][alert_type] = 0
                            summary['by_type'][alert_type] += 1
                    
                    except (json.JSONDecodeError, ValueError, KeyError):
                        continue
            
            return summary
        
        except Exception as e:
            self.logger.error(f"Failed to generate alerts summary: {e}")
            return {'error': str(e)}
    
    def cleanup_old_logs(self, days=30):
        """Clean up log files older than specified days"""
        try:
            cutoff_time = datetime.now() - timedelta(days=days)
            
            for filename in os.listdir(self.log_dir):
                file_path = os.path.join(self.log_dir, filename)
                
                if os.path.isfile(file_path):
                    file_mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
                    
                    if file_mtime < cutoff_time:
                        try:
                            os.remove(file_path)
                            self.logger.info(f"Removed old log file: {filename}")
                        except Exception as e:
                            self.logger.error(f"Failed to remove old log file {filename}: {e}")
        
        except Exception as e:
            self.logger.error(f"Failed to cleanup old logs: {e}")
    
    def export_logs(self, start_date=None, end_date=None, output_file=None):
        """Export logs for a specific date range"""
        try:
            if not start_date:
                start_date = datetime.now() - timedelta(days=7)
            if not end_date:
                end_date = datetime.now()
            if not output_file:
                output_file = f"sentinelwatch_export_{start_date.strftime('%Y%m%d')}_{end_date.strftime('%Y%m%d')}.log"
            
            exported_lines = []
            
            # Export from main log
            main_log = os.path.join(self.log_dir, 'sentinelwatch.log')
            if os.path.exists(main_log):
                with open(main_log, 'r') as f:
                    for line in f:
                        try:
                            # Parse timestamp from log line
                            timestamp_str = line.split(' - ')[0]
                            log_time = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                            
                            if start_date <= log_time <= end_date:
                                exported_lines.append(line.strip())
                        except (ValueError, IndexError):
                            continue
            
            # Write exported logs
            with open(output_file, 'w') as f:
                f.write(f"SentinelWatch Pro Log Export\n")
                f.write(f"Export Date Range: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n\n")
                
                for line in exported_lines:
                    f.write(line + '\n')
            
            return output_file
        
        except Exception as e:
            self.logger.error(f"Failed to export logs: {e}")
            return None
