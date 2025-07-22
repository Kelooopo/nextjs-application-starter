import psutil
import time
import threading
from datetime import datetime
import platform
import os

class SystemMonitor:
    def __init__(self, config):
        self.config = config
        self.process_stats = {}
        self.suspicious_processes = set()
        self.lock = threading.Lock()
        
    def update_config(self, config):
        """Update monitoring configuration"""
        self.config = config
        
    def check_processes(self):
        """Monitor running processes for suspicious activity"""
        alerts = []
        
        try:
            current_processes = set()
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'cmdline']):
                try:
                    pinfo = proc.info
                    pid = pinfo['pid']
                    name = pinfo['name']
                    
                    current_processes.add(pid)
                    
                    # Skip whitelisted processes
                    if name in self.config.get('whitelist_processes', []):
                        continue
                    
                    # Check CPU usage
                    cpu_percent = proc.cpu_percent(interval=0.1)
                    if cpu_percent > self.config.get('process_cpu_threshold', 80.0):
                        alerts.append({
                            'type': 'process',
                            'severity': 'high',
                            'title': 'High CPU Usage Detected',
                            'message': f'Process {name} (PID: {pid}) is using {cpu_percent:.1f}% CPU',
                            'process_name': name,
                            'process_id': pid,
                            'cpu_usage': cpu_percent
                        })
                    
                    # Check memory usage
                    memory_mb = pinfo['memory_info'].rss / (1024 * 1024)
                    if memory_mb > self.config.get('process_mem_threshold', 500.0):
                        alerts.append({
                            'type': 'process',
                            'severity': 'medium',
                            'title': 'High Memory Usage Detected',
                            'message': f'Process {name} (PID: {pid}) is using {memory_mb:.1f} MB memory',
                            'process_name': name,
                            'process_id': pid,
                            'memory_usage': memory_mb
                        })
                    
                    # Check for suspicious process names
                    if self._is_suspicious_process(name, pinfo.get('cmdline', [])):
                        if pid not in self.suspicious_processes:
                            self.suspicious_processes.add(pid)
                            alerts.append({
                                'type': 'process',
                                'severity': 'high',
                                'title': 'Suspicious Process Detected',
                                'message': f'Potentially suspicious process: {name} (PID: {pid})',
                                'process_name': name,
                                'process_id': pid,
                                'cmdline': ' '.join(pinfo.get('cmdline', []))
                            })
                    
                    # Track process statistics for anomaly detection
                    with self.lock:
                        if pid not in self.process_stats:
                            self.process_stats[pid] = {
                                'name': name,
                                'cpu_history': [],
                                'memory_history': []
                            }
                        
                        stats = self.process_stats[pid]
                        stats['cpu_history'].append(cpu_percent)
                        stats['memory_history'].append(memory_mb)
                        
                        # Keep only last 10 measurements
                        stats['cpu_history'] = stats['cpu_history'][-10:]
                        stats['memory_history'] = stats['memory_history'][-10:]
                        
                        # Check for anomalies
                        anomaly_alert = self._check_process_anomaly(pid, stats)
                        if anomaly_alert:
                            alerts.append(anomaly_alert)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Clean up stats for terminated processes
            with self.lock:
                terminated_pids = set(self.process_stats.keys()) - current_processes
                for pid in terminated_pids:
                    if pid in self.process_stats:
                        del self.process_stats[pid]
                    if pid in self.suspicious_processes:
                        self.suspicious_processes.discard(pid)
        
        except Exception as e:
            alerts.append({
                'type': 'system',
                'severity': 'medium',
                'title': 'Process Monitoring Error',
                'message': f'Error during process monitoring: {str(e)}'
            })
        
        return alerts
    
    def _is_suspicious_process(self, name, cmdline):
        """Check if a process name or command line is suspicious"""
        suspicious_patterns = [
            'keylogger', 'rootkit', 'backdoor', 'trojan', 'malware',
            'cryptominer', 'coinminer', 'bitcoin', 'monero',
            'cmd.exe /c', 'powershell -enc', 'wscript', 'cscript',
            'nc.exe', 'netcat', 'ncat'
        ]
        
        name_lower = name.lower()
        cmdline_str = ' '.join(cmdline).lower()
        
        for pattern in suspicious_patterns:
            if pattern in name_lower or pattern in cmdline_str:
                return True
        
        # Check for processes running from temp directories
        temp_dirs = ['/tmp/', 'C:\\Temp\\', 'C:\\Windows\\Temp\\', '%TEMP%']
        for temp_dir in temp_dirs:
            if temp_dir.lower() in cmdline_str:
                return True
        
        return False
    
    def _check_process_anomaly(self, pid, stats):
        """Check for anomalous process behavior"""
        if len(stats['cpu_history']) < 5:
            return None
        
        # Calculate average and recent usage
        avg_cpu = sum(stats['cpu_history'][:-2]) / (len(stats['cpu_history']) - 2)
        recent_cpu = sum(stats['cpu_history'][-2:]) / 2
        
        avg_memory = sum(stats['memory_history'][:-2]) / (len(stats['memory_history']) - 2)
        recent_memory = sum(stats['memory_history'][-2:]) / 2
        
        # Check for sudden spikes
        cpu_spike = recent_cpu > avg_cpu * 2 and recent_cpu > 50
        memory_spike = recent_memory > avg_memory * 2 and recent_memory > 100
        
        if cpu_spike or memory_spike:
            return {
                'type': 'anomaly',
                'severity': 'medium',
                'title': 'Process Anomaly Detected',
                'message': f'Process {stats["name"]} (PID: {pid}) showing unusual resource usage patterns',
                'process_name': stats['name'],
                'process_id': pid,
                'anomaly_type': 'cpu_spike' if cpu_spike else 'memory_spike'
            }
        
        return None
    
    def get_system_info(self):
        """Get comprehensive system information"""
        try:
            return {
                'platform': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'disk_total': psutil.disk_usage('/').total if platform.system() != 'Windows' else psutil.disk_usage('C:').total,
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                'uptime': str(datetime.now() - datetime.fromtimestamp(psutil.boot_time()))
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_running_processes(self):
        """Get list of currently running processes"""
        processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'status']):
                try:
                    pinfo = proc.info
                    processes.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'cpu_percent': proc.cpu_percent(interval=0.1),
                        'memory_mb': pinfo['memory_info'].rss / (1024 * 1024),
                        'status': pinfo['status']
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print(f"Error getting process list: {e}")
        
        return processes
