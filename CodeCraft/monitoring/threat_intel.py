import os
import hashlib
import requests
import json
import time
from datetime import datetime, timedelta

class ThreatIntelligence:
    def __init__(self, config):
        self.config = config
        self.cache = {}
        self.cache_timeout = 3600  # 1 hour cache
        
    def update_config(self, config):
        """Update threat intelligence configuration"""
        self.config = config
    
    def scan_file(self, file_path):
        """Scan file using threat intelligence services"""
        try:
            if not os.path.exists(file_path):
                return {'error': 'File not found', 'file_path': file_path}
            
            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            if not file_hash:
                return {'error': 'Could not calculate file hash', 'file_path': file_path}
            
            file_size = os.path.getsize(file_path)
            
            result = {
                'file_path': file_path,
                'file_size': file_size,
                'file_hash': file_hash,
                'scan_time': datetime.now().isoformat(),
                'is_malware': False,
                'suspicious': False,
                'virustotal_result': None,
                'otx_result': None
            }
            
            # Check cache first
            if file_hash in self.cache:
                cache_entry = self.cache[file_hash]
                if datetime.now() - datetime.fromisoformat(cache_entry['timestamp']) < timedelta(seconds=self.cache_timeout):
                    result.update(cache_entry['data'])
                    result['from_cache'] = True
                    return result
            
            # Scan with VirusTotal
            vt_result = self._scan_with_virustotal(file_hash)
            if vt_result:
                result['virustotal_result'] = vt_result
                if vt_result.get('malicious', 0) > 0:
                    result['is_malware'] = True
                elif vt_result.get('suspicious', 0) > 0:
                    result['suspicious'] = True
            
            # Scan with OTX
            otx_result = self._scan_with_otx(file_hash)
            if otx_result:
                result['otx_result'] = otx_result
                if otx_result.get('threat_found'):
                    result['is_malware'] = True
            
            # Cache the result
            self.cache[file_hash] = {
                'timestamp': datetime.now().isoformat(),
                'data': {
                    'virustotal_result': result['virustotal_result'],
                    'otx_result': result['otx_result'],
                    'is_malware': result['is_malware'],
                    'suspicious': result['suspicious']
                }
            }
            
            return result
            
        except Exception as e:
            return {'error': str(e), 'file_path': file_path}
    
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
    
    def _scan_with_virustotal(self, file_hash):
        """Scan file hash with VirusTotal API"""
        api_key = self.config.get('virustotal_api_key', '')
        if not api_key:
            return None
        
        try:
            url = f"https://www.virustotal.com/vtapi/v2/file/report"
            params = {
                'apikey': api_key,
                'resource': file_hash
            }
            
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                if data.get('response_code') == 1:
                    return {
                        'total_scans': data.get('total', 0),
                        'positive_scans': data.get('positives', 0),
                        'malicious': data.get('positives', 0),
                        'suspicious': 0,  # VirusTotal doesn't separate suspicious
                        'scan_date': data.get('scan_date', ''),
                        'permalink': data.get('permalink', '')
                    }
                else:
                    return {'message': 'File not found in VirusTotal database'}
            
        except Exception as e:
            return {'error': f'VirusTotal API error: {str(e)}'}
        
        return None
    
    def _scan_with_otx(self, file_hash):
        """Scan file hash with AlienVault OTX API"""
        api_key = self.config.get('otx_api_key', '')
        if not api_key:
            return None
        
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"
            headers = {
                'X-OTX-API-KEY': api_key
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                pulse_count = len(data.get('pulse_info', {}).get('pulses', []))
                threat_found = pulse_count > 0
                
                return {
                    'threat_found': threat_found,
                    'pulse_count': pulse_count,
                    'reputation': data.get('reputation', 0),
                    'first_seen': data.get('first_seen', ''),
                    'last_seen': data.get('last_seen', '')
                }
            
        except Exception as e:
            return {'error': f'OTX API error: {str(e)}'}
        
        return None
    
    def check_ip_reputation(self, ip_address):
        """Check IP address reputation"""
        try:
            result = {
                'ip_address': ip_address,
                'is_malicious': False,
                'reputation_score': 0,
                'sources': {}
            }
            
            # Check with VirusTotal
            vt_result = self._check_ip_virustotal(ip_address)
            if vt_result:
                result['sources']['virustotal'] = vt_result
                if vt_result.get('malicious', 0) > 0:
                    result['is_malicious'] = True
                    result['reputation_score'] += 50
            
            # Check with OTX
            otx_result = self._check_ip_otx(ip_address)
            if otx_result:
                result['sources']['otx'] = otx_result
                if otx_result.get('threat_found'):
                    result['is_malicious'] = True
                    result['reputation_score'] += 30
            
            return result
            
        except Exception as e:
            return {'error': str(e), 'ip_address': ip_address}
    
    def _check_ip_virustotal(self, ip_address):
        """Check IP with VirusTotal"""
        api_key = self.config.get('virustotal_api_key', '')
        if not api_key:
            return None
        
        try:
            url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
            params = {
                'apikey': api_key,
                'ip': ip_address
            }
            
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                if data.get('response_code') == 1:
                    detected_urls = data.get('detected_urls', [])
                    detected_samples = data.get('detected_samples', [])
                    
                    return {
                        'malicious': len(detected_urls) + len(detected_samples),
                        'detected_urls': len(detected_urls),
                        'detected_samples': len(detected_samples),
                        'country': data.get('country', ''),
                        'asn': data.get('asn', '')
                    }
            
        except Exception as e:
            return {'error': f'VirusTotal IP check error: {str(e)}'}
        
        return None
    
    def _check_ip_otx(self, ip_address):
        """Check IP with OTX"""
        api_key = self.config.get('otx_api_key', '')
        if not api_key:
            return None
        
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
            headers = {
                'X-OTX-API-KEY': api_key
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                pulse_count = len(data.get('pulse_info', {}).get('pulses', []))
                threat_found = pulse_count > 0
                
                return {
                    'threat_found': threat_found,
                    'pulse_count': pulse_count,
                    'reputation': data.get('reputation', 0),
                    'country': data.get('country_name', ''),
                    'asn': data.get('asn', '')
                }
            
        except Exception as e:
            return {'error': f'OTX IP check error: {str(e)}'}
        
        return None
    
    def get_threat_feeds(self):
        """Get latest threat intelligence feeds"""
        feeds = []
        
        # Get latest pulses from OTX
        otx_feeds = self._get_otx_feeds()
        if otx_feeds:
            feeds.extend(otx_feeds)
        
        return feeds
    
    def _get_otx_feeds(self):
        """Get threat feeds from OTX"""
        api_key = self.config.get('otx_api_key', '')
        if not api_key:
            return []
        
        try:
            url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
            headers = {
                'X-OTX-API-KEY': api_key
            }
            params = {
                'limit': 10
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                feeds = []
                for pulse in data.get('results', []):
                    feeds.append({
                        'source': 'OTX',
                        'title': pulse.get('name', ''),
                        'description': pulse.get('description', ''),
                        'created': pulse.get('created', ''),
                        'modified': pulse.get('modified', ''),
                        'tags': pulse.get('tags', []),
                        'indicators_count': len(pulse.get('indicators', []))
                    })
                
                return feeds
            
        except Exception as e:
            return []
        
        return []
    
    def clear_cache(self):
        """Clear threat intelligence cache"""
        self.cache.clear()
