import os
import hashlib
import threading
import time
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class FileSystemEventHandlerCustom(FileSystemEventHandler):
    def __init__(self, callback, config):
        self.callback = callback
        self.config = config
        self.file_hashes = {}
        self.lock = threading.Lock()
        
    def on_modified(self, event):
        if not event.is_directory:
            self._handle_file_event(event.src_path, 'modified')
    
    def on_created(self, event):
        if not event.is_directory:
            self._handle_file_event(event.src_path, 'created')
    
    def on_deleted(self, event):
        if not event.is_directory:
            self._handle_file_event(event.src_path, 'deleted')
    
    def on_moved(self, event):
        if not event.is_directory:
            self._handle_file_event(event.dest_path, 'moved')
    
    def _handle_file_event(self, file_path, event_type):
        """Handle file system events"""
        try:
            # Skip temporary files and system files
            if self._should_ignore_file(file_path):
                return
            
            file_info = {
                'file_path': file_path,
                'event_type': event_type,
                'timestamp': datetime.now().isoformat(),
                'file_size': os.path.getsize(file_path) if os.path.exists(file_path) else 0
            }
            
            # Calculate file hash for integrity checking
            if event_type in ['created', 'modified'] and os.path.exists(file_path):
                file_hash = self._calculate_file_hash(file_path)
                file_info['file_hash'] = file_hash
                
                with self.lock:
                    # Check if file hash has changed (for modified files)
                    if event_type == 'modified' and file_path in self.file_hashes:
                        if self.file_hashes[file_path] == file_hash:
                            return  # File content hasn't actually changed
                    
                    self.file_hashes[file_path] = file_hash
            
            # Determine alert severity
            severity = self._determine_severity(file_path, event_type)
            
            alert = {
                'type': 'file',
                'severity': severity,
                'title': f'File {event_type.title()}',
                'message': f'File {event_type}: {file_path}',
                **file_info
            }
            
            self.callback(alert)
            
        except Exception as e:
            error_alert = {
                'type': 'file',
                'severity': 'low',
                'title': 'File Monitoring Error',
                'message': f'Error monitoring file {file_path}: {str(e)}'
            }
            self.callback(error_alert)
    
    def _should_ignore_file(self, file_path):
        """Check if file should be ignored"""
        ignore_patterns = [
            '.tmp', '.log', '.swp', '.swo', '~',
            '.DS_Store', 'Thumbs.db', '.git/',
            '__pycache__/', '.pyc', '.pyo'
        ]
        
        file_lower = file_path.lower()
        for pattern in ignore_patterns:
            if pattern in file_lower:
                return True
        
        return False
    
    def _calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of file"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception:
            return None
    
    def _determine_severity(self, file_path, event_type):
        """Determine alert severity based on file and event type"""
        critical_dirs = [
            '/etc/', '/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/',
            'C:\\Windows\\System32\\', 'C:\\Windows\\SysWOW64\\',
            'C:\\Program Files\\', 'C:\\Program Files (x86)\\'
        ]
        
        sensitive_extensions = [
            '.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1',
            '.sh', '.conf', '.cfg', '.ini'
        ]
        
        # Check if file is in critical directory
        for critical_dir in critical_dirs:
            if file_path.startswith(critical_dir):
                return 'high'
        
        # Check file extension
        _, ext = os.path.splitext(file_path)
        if ext.lower() in sensitive_extensions:
            return 'medium'
        
        # Default severity
        return 'low'

class FileMonitor:
    def __init__(self, config):
        self.config = config
        self.observer = None
        self.event_handler = None
        self.monitoring = False
        
    def update_config(self, config):
        """Update monitoring configuration"""
        self.config = config
        
        # Restart monitoring if configuration changed
        if self.monitoring:
            self.stop_monitoring()
            time.sleep(1)
            self.start_monitoring(self.callback)
    
    def start_monitoring(self, callback):
        """Start file system monitoring"""
        if self.monitoring:
            return
        
        self.callback = callback
        self.event_handler = FileSystemEventHandlerCustom(callback, self.config)
        self.observer = Observer()
        
        # Monitor configured directories
        monitored_dirs = self.config.get('monitored_dirs', [])
        for directory in monitored_dirs:
            if os.path.exists(directory):
                try:
                    self.observer.schedule(self.event_handler, directory, recursive=True)
                except Exception as e:
                    callback({
                        'type': 'file',
                        'severity': 'medium',
                        'title': 'File Monitoring Setup Error',
                        'message': f'Failed to monitor directory {directory}: {str(e)}'
                    })
        
        try:
            self.observer.start()
            self.monitoring = True
            
            callback({
                'type': 'system',
                'severity': 'low',
                'title': 'File Monitoring Started',
                'message': f'Monitoring {len(monitored_dirs)} directories for file changes'
            })
            
        except Exception as e:
            callback({
                'type': 'system',
                'severity': 'medium',
                'title': 'File Monitoring Error',
                'message': f'Failed to start file monitoring: {str(e)}'
            })
    
    def stop_monitoring(self):
        """Stop file system monitoring"""
        if self.observer and self.monitoring:
            self.observer.stop()
            self.observer.join()
            self.monitoring = False
            
            if hasattr(self, 'callback'):
                self.callback({
                    'type': 'system',
                    'severity': 'low',
                    'title': 'File Monitoring Stopped',
                    'message': 'File system monitoring has been stopped'
                })
    
    def scan_file_integrity(self, file_path):
        """Scan a specific file for integrity"""
        try:
            if not os.path.exists(file_path):
                return {
                    'error': 'File not found',
                    'file_path': file_path
                }
            
            # Calculate file hash
            file_hash = self.event_handler._calculate_file_hash(file_path) if self.event_handler else None
            file_size = os.path.getsize(file_path)
            file_mtime = datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
            
            return {
                'file_path': file_path,
                'file_size': file_size,
                'file_hash': file_hash,
                'modified_time': file_mtime,
                'exists': True
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'file_path': file_path
            }
    
    def get_monitored_directories(self):
        """Get list of monitored directories"""
        return self.config.get('monitored_dirs', [])
    
    def add_monitored_directory(self, directory):
        """Add a directory to monitoring"""
        if os.path.exists(directory):
            monitored_dirs = self.config.get('monitored_dirs', [])
            if directory not in monitored_dirs:
                monitored_dirs.append(directory)
                self.config['monitored_dirs'] = monitored_dirs
                
                # If monitoring is active, add the new directory
                if self.monitoring and self.observer:
                    try:
                        self.observer.schedule(self.event_handler, directory, recursive=True)
                        return True
                    except Exception as e:
                        return False
                return True
        return False
    
    def remove_monitored_directory(self, directory):
        """Remove a directory from monitoring"""
        monitored_dirs = self.config.get('monitored_dirs', [])
        if directory in monitored_dirs:
            monitored_dirs.remove(directory)
            self.config['monitored_dirs'] = monitored_dirs
            
            # Restart monitoring to remove the directory
            if self.monitoring:
                self.stop_monitoring()
                time.sleep(1)
                self.start_monitoring(self.callback)
            
            return True
        return False
