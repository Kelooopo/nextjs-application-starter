import psutil
import socket
import threading
import time
from datetime import datetime
import subprocess
import platform

class NetworkMonitor:
    def __init__(self, config):
        self.config = config
        self.suspicious_connections = set()
        self.connection_history = {}
        self.lock = threading.Lock()
        
    def update_config(self, config):
        """Update monitoring configuration"""
        self.config = config
        
    def check_connections(self):
        """Monitor network connections for suspicious activity"""
        alerts = []
        
        try:
            connections = psutil.net_connections(kind='inet')
            current_time = datetime.now()
            
            for conn in connections:
                try:
                    if not conn.laddr:
                        continue
                    
                    local_port = conn.laddr.port
                    remote_addr = conn.raddr.ip if conn.raddr else None
                    remote_port = conn.raddr.port if conn.raddr else None
                    status = conn.status
                    
                    # Check for connections to monitored ports
                    if local_port in self.config.get('monitored_ports', []):
                        connection_key = f"{remote_addr}:{remote_port}->{local_port}"
                        
                        if connection_key not in self.suspicious_connections:
                            self.suspicious_connections.add(connection_key)
                            alerts.append({
                                'type': 'network',
                                'severity': 'medium',
                                'title': 'Connection to Monitored Port',
                                'message': f'Connection detected on monitored port {local_port} from {remote_addr}:{remote_port}',
                                'local_port': local_port,
                                'remote_address': remote_addr,
                                'remote_port': remote_port,
                                'connection_status': status
                            })
                    
                    # Check for unusual outbound connections
                    if remote_addr and self._is_suspicious_connection(remote_addr, remote_port):
                        connection_key = f"{remote_addr}:{remote_port}"
                        
                        if connection_key not in self.suspicious_connections:
                            self.suspicious_connections.add(connection_key)
                            alerts.append({
                                'type': 'network',
                                'severity': 'high',
                                'title': 'Suspicious Outbound Connection',
                                'message': f'Suspicious connection to {remote_addr}:{remote_port}',
                                'remote_address': remote_addr,
                                'remote_port': remote_port,
                                'local_port': local_port,
                                'connection_status': status
                            })
                    
                    # Track connection patterns
                    with self.lock:
                        if remote_addr:
                            if remote_addr not in self.connection_history:
                                self.connection_history[remote_addr] = []
                            
                            self.connection_history[remote_addr].append({
                                'timestamp': current_time.isoformat(),
                                'port': remote_port,
                                'local_port': local_port,
                                'status': status
                            })
                            
                            # Keep only last 100 connections per IP
                            self.connection_history[remote_addr] = self.connection_history[remote_addr][-100:]
                            
                            # Check for connection flooding
                            recent_connections = [
                                c for c in self.connection_history[remote_addr]
                                if (current_time - datetime.fromisoformat(c['timestamp'])).total_seconds() < 300
                            ]
                            
                            if len(recent_connections) > 50:  # More than 50 connections in 5 minutes
                                alerts.append({
                                    'type': 'network',
                                    'severity': 'high',
                                    'title': 'Connection Flooding Detected',
                                    'message': f'Excessive connections from {remote_addr} ({len(recent_connections)} in 5 minutes)',
                                    'remote_address': remote_addr,
                                    'connection_count': len(recent_connections)
                                })
                
                except Exception as e:
                    continue
            
            # Check network statistics for anomalies
            network_stats = psutil.net_io_counters()
            anomaly_alert = self._check_network_anomaly(network_stats)
            if anomaly_alert:
                alerts.append(anomaly_alert)
                
        except Exception as e:
            alerts.append({
                'type': 'network',
                'severity': 'medium',
                'title': 'Network Monitoring Error',
                'message': f'Error during network monitoring: {str(e)}'
            })
        
        return alerts
    
    def _is_suspicious_connection(self, remote_addr, remote_port):
        """Check if a connection is suspicious"""
        # Check for known suspicious ports
        suspicious_ports = [
            4444, 5555, 6666, 1234, 31337,  # Common backdoor ports
            6667, 6668, 6669,  # IRC ports
            25, 587, 465,  # SMTP ports (potential spam)
        ]
        
        if remote_port in suspicious_ports:
            return True
        
        # Check for connections to private IP ranges from public IPs
        if self._is_private_ip(remote_addr):
            return False  # Private IPs are generally safe
        
        # Check for connections to known malicious IP ranges
        # This is a simplified check - in production, use threat intelligence feeds
        suspicious_ranges = [
            '10.0.0.',    # Example suspicious range
            '192.168.1.', # Example suspicious range
        ]
        
        for suspicious_range in suspicious_ranges:
            if remote_addr.startswith(suspicious_range):
                return True
        
        return False
    
    def _is_private_ip(self, ip):
        """Check if an IP address is in a private range"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False
    
    def _check_network_anomaly(self, current_stats):
        """Check for network traffic anomalies"""
        # This is a simplified implementation
        # In production, you would track historical data and use more sophisticated analysis
        
        bytes_sent = current_stats.bytes_sent
        bytes_recv = current_stats.bytes_recv
        
        # Check for unusual traffic volumes (simplified)
        if bytes_sent > 1024 * 1024 * 1024:  # More than 1GB sent
            return {
                'type': 'network',
                'severity': 'medium',
                'title': 'High Outbound Traffic',
                'message': f'Unusually high outbound traffic detected: {bytes_sent / (1024**3):.2f} GB',
                'bytes_sent': bytes_sent
            }
        
        return None
    
    def get_network_connections(self):
        """Get current network connections"""
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr:
                    connections.append({
                        'local_address': conn.laddr.ip,
                        'local_port': conn.laddr.port,
                        'remote_address': conn.raddr.ip if conn.raddr else None,
                        'remote_port': conn.raddr.port if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    })
        except Exception as e:
            print(f"Error getting network connections: {e}")
        
        return connections
    
    def get_network_stats(self):
        """Get network interface statistics"""
        try:
            stats = psutil.net_io_counters()
            return {
                'bytes_sent': stats.bytes_sent,
                'bytes_recv': stats.bytes_recv,
                'packets_sent': stats.packets_sent,
                'packets_recv': stats.packets_recv,
                'errin': stats.errin,
                'errout': stats.errout,
                'dropin': stats.dropin,
                'dropout': stats.dropout
            }
        except Exception as e:
            return {'error': str(e)}
    
    def scan_port(self, host, port, timeout=3):
        """Scan a specific port on a host"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
