"""
SentinelWatch Pro AI-Powered Threat Detection Engine
Revolutionary AI/ML capabilities for advanced threat detection and behavioral analysis
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import json
import hashlib
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
import logging
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import joblib
import os

logger = logging.getLogger(__name__)

@dataclass
class ThreatScore:
    """Advanced threat scoring system"""
    overall_score: float
    behavioral_score: float
    anomaly_score: float
    intelligence_score: float
    confidence: float
    risk_factors: List[str]
    recommended_action: str
    explanation: str

@dataclass
class BehavioralPattern:
    """User/System behavioral pattern"""
    entity_id: str
    entity_type: str  # user, host, process, network
    pattern_type: str  # login, network, process, file_access
    baseline_metrics: Dict[str, float]
    current_metrics: Dict[str, float]
    deviation_score: float
    last_updated: datetime

class AIThreatDetectionEngine:
    """AI-powered threat detection with machine learning capabilities"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.models_path = self.config.get('models_path', 'models/')
        self.learning_window = self.config.get('learning_window', 7)  # days
        self.anomaly_threshold = self.config.get('anomaly_threshold', -0.5)
        self.confidence_threshold = self.config.get('confidence_threshold', 0.7)
        
        # Initialize ML models
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.clustering_model = DBSCAN(eps=0.5, min_samples=5)
        
        # Behavioral baselines
        self.behavioral_baselines: Dict[str, BehavioralPattern] = {}
        self.event_history = deque(maxlen=10000)  # Keep last 10k events
        
        # Threat intelligence integration
        self.threat_signatures = {}
        self.ioc_cache = {}
        
        # Model training status
        self.model_trained = False
        self.last_training = None
        self.training_lock = threading.Lock()
        
        # Load pre-trained models if available
        self._load_models()
        
        # Start background learning
        self.learning_thread = threading.Thread(target=self._continuous_learning_loop)
        self.learning_thread.daemon = True
        self.learning_thread.start()
        
    def analyze_event(self, event_data: Dict[str, Any]) -> ThreatScore:
        """Comprehensive AI-powered event analysis"""
        try:
            # Extract features from event
            features = self._extract_features(event_data)
            
            # Behavioral analysis
            behavioral_score = self._analyze_behavioral_patterns(event_data, features)
            
            # Anomaly detection
            anomaly_score = self._detect_anomalies(features)
            
            # Threat intelligence correlation
            intelligence_score = self._correlate_threat_intelligence(event_data)
            
            # Advanced pattern matching
            pattern_score = self._advanced_pattern_matching(event_data)
            
            # Calculate overall threat score
            overall_score = self._calculate_overall_score(
                behavioral_score, anomaly_score, intelligence_score, pattern_score
            )
            
            # Generate risk factors and recommendations
            risk_factors = self._identify_risk_factors(
                event_data, behavioral_score, anomaly_score, intelligence_score
            )
            
            recommended_action = self._recommend_action(overall_score, risk_factors)
            explanation = self._generate_explanation(overall_score, risk_factors)
            
            # Calculate confidence based on multiple factors
            confidence = self._calculate_confidence(event_data, overall_score)
            
            threat_score = ThreatScore(
                overall_score=overall_score,
                behavioral_score=behavioral_score,
                anomaly_score=anomaly_score,
                intelligence_score=intelligence_score,
                confidence=confidence,
                risk_factors=risk_factors,
                recommended_action=recommended_action,
                explanation=explanation
            )
            
            # Store event for learning
            self.event_history.append({
                'timestamp': datetime.utcnow(),
                'event_data': event_data,
                'features': features,
                'threat_score': asdict(threat_score)
            })
            
            return threat_score
            
        except Exception as e:
            logger.error(f"Error in AI threat analysis: {e}")
            return ThreatScore(
                overall_score=0.0,
                behavioral_score=0.0,
                anomaly_score=0.0,
                intelligence_score=0.0,
                confidence=0.0,
                risk_factors=['analysis_error'],
                recommended_action='monitor',
                explanation=f"Analysis failed: {str(e)}"
            )
    
    def _extract_features(self, event_data: Dict[str, Any]) -> np.ndarray:
        """Advanced feature extraction from security events"""
        features = []
        
        # Time-based features
        now = datetime.utcnow()
        event_time = event_data.get('timestamp', now)
        if isinstance(event_time, str):
            event_time = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
        
        # Time of day (0-23)
        features.append(event_time.hour)
        # Day of week (0-6)
        features.append(event_time.weekday())
        # Is weekend (0/1)
        features.append(1 if event_time.weekday() >= 5 else 0)
        
        # Network features
        source_ip = event_data.get('source_ip', '0.0.0.0')
        dest_ip = event_data.get('destination_ip', '0.0.0.0')
        
        # IP reputation scores (simplified)
        features.append(self._get_ip_reputation_score(source_ip))
        features.append(self._get_ip_reputation_score(dest_ip))
        
        # Process features
        process_name = event_data.get('process_name', '')
        features.append(len(process_name))
        features.append(1 if any(suspicious in process_name.lower() for suspicious in 
                              ['powershell', 'cmd', 'bash', 'nc', 'netcat']) else 0)
        
        # File features
        if 'file_path' in event_data:
            file_path = event_data['file_path']
            features.append(len(file_path))
            features.append(1 if any(ext in file_path.lower() for ext in 
                                  ['.exe', '.bat', '.ps1', '.sh', '.scr']) else 0)
        else:
            features.extend([0, 0])
        
        # User features
        user_name = event_data.get('user_name', '')
        features.append(len(user_name))
        features.append(1 if user_name.lower() in ['admin', 'administrator', 'root'] else 0)
        
        # Event frequency features
        event_type = event_data.get('category', 'unknown')
        recent_events = self._count_recent_events(event_type, minutes=10)
        features.append(recent_events)
        
        # Severity mapping
        severity_map = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        severity = event_data.get('severity', 'medium')
        features.append(severity_map.get(severity, 2))
        
        return np.array(features, dtype=float)
    
    def _analyze_behavioral_patterns(self, event_data: Dict[str, Any], features: np.ndarray) -> float:
        """Advanced behavioral pattern analysis"""
        entity_id = event_data.get('user_name') or event_data.get('host_name', 'unknown')
        entity_type = 'user' if event_data.get('user_name') else 'host'
        pattern_type = event_data.get('category', 'general')
        
        # Create pattern key
        pattern_key = f"{entity_id}:{entity_type}:{pattern_type}"
        
        if pattern_key not in self.behavioral_baselines:
            # First time seeing this entity/pattern - establish baseline
            self.behavioral_baselines[pattern_key] = BehavioralPattern(
                entity_id=entity_id,
                entity_type=entity_type,
                pattern_type=pattern_type,
                baseline_metrics=self._calculate_baseline_metrics(features),
                current_metrics=self._calculate_baseline_metrics(features),
                deviation_score=0.0,
                last_updated=datetime.utcnow()
            )
            return 0.0  # No deviation for new patterns
        
        # Compare current behavior to baseline
        baseline = self.behavioral_baselines[pattern_key]
        current_metrics = self._calculate_baseline_metrics(features)
        
        # Calculate deviation score
        deviation_score = self._calculate_behavioral_deviation(
            baseline.baseline_metrics, current_metrics
        )
        
        # Update baseline with exponential moving average
        alpha = 0.1  # Learning rate
        for key in baseline.baseline_metrics:
            if key in current_metrics:
                baseline.baseline_metrics[key] = (
                    alpha * current_metrics[key] + 
                    (1 - alpha) * baseline.baseline_metrics[key]
                )
        
        baseline.current_metrics = current_metrics
        baseline.deviation_score = deviation_score
        baseline.last_updated = datetime.utcnow()
        
        return min(deviation_score, 1.0)  # Cap at 1.0
    
    def _detect_anomalies(self, features: np.ndarray) -> float:
        """Machine learning-based anomaly detection"""
        if not self.model_trained:
            return 0.0
        
        try:
            # Normalize features
            features_scaled = self.scaler.transform([features])
            
            # Get anomaly score from isolation forest
            anomaly_score = self.isolation_forest.decision_function(features_scaled)[0]
            
            # Convert to 0-1 scale (higher = more anomalous)
            normalized_score = max(0, -anomaly_score)  # Isolation forest returns negative for anomalies
            
            return min(normalized_score, 1.0)
            
        except Exception as e:
            logger.warning(f"Anomaly detection failed: {e}")
            return 0.0
    
    def _correlate_threat_intelligence(self, event_data: Dict[str, Any]) -> float:
        """Correlate event with threat intelligence"""
        intelligence_score = 0.0
        
        # Check IPs against threat intelligence
        for ip_field in ['source_ip', 'destination_ip']:
            if ip_field in event_data:
                ip = event_data[ip_field]
                threat_info = self._check_ip_threat_intelligence(ip)
                if threat_info:
                    intelligence_score = max(intelligence_score, threat_info.get('confidence', 0.5))
        
        # Check domains
        if 'domain' in event_data:
            domain_threat = self._check_domain_threat_intelligence(event_data['domain'])
            if domain_threat:
                intelligence_score = max(intelligence_score, domain_threat.get('confidence', 0.5))
        
        # Check file hashes
        if 'file_hash' in event_data:
            hash_threat = self._check_hash_threat_intelligence(event_data['file_hash'])
            if hash_threat:
                intelligence_score = max(intelligence_score, hash_threat.get('confidence', 0.7))
        
        return intelligence_score
    
    def _advanced_pattern_matching(self, event_data: Dict[str, Any]) -> float:
        """Advanced pattern matching for sophisticated attacks"""
        pattern_score = 0.0
        
        # MITRE ATT&CK pattern detection
        pattern_score = max(pattern_score, self._detect_mitre_patterns(event_data))
        
        # Kill chain analysis
        pattern_score = max(pattern_score, self._analyze_kill_chain(event_data))
        
        # Lateral movement detection
        pattern_score = max(pattern_score, self._detect_lateral_movement(event_data))
        
        # Data exfiltration patterns
        pattern_score = max(pattern_score, self._detect_exfiltration_patterns(event_data))
        
        return pattern_score
    
    def _detect_mitre_patterns(self, event_data: Dict[str, Any]) -> float:
        """Detect MITRE ATT&CK framework patterns"""
        score = 0.0
        
        # T1055 - Process Injection
        if (event_data.get('process_name', '').lower() in ['rundll32.exe', 'regsvr32.exe'] or
            'injection' in event_data.get('message', '').lower()):
            score = max(score, 0.8)
        
        # T1003 - Credential Dumping
        if any(tool in event_data.get('process_name', '').lower() for tool in 
               ['mimikatz', 'lsass', 'procdump']):
            score = max(score, 0.9)
        
        # T1082 - System Information Discovery
        if any(cmd in event_data.get('command_line', '').lower() for cmd in 
               ['systeminfo', 'whoami', 'net user']):
            score = max(score, 0.4)
        
        # T1021 - Remote Services
        if (event_data.get('source_ip') and event_data.get('destination_ip') and
            event_data.get('category') == 'network' and
            any(port in str(event_data.get('destination_port', '')) for port in ['3389', '22', '5985'])):
            score = max(score, 0.6)
        
        return score
    
    def _analyze_kill_chain(self, event_data: Dict[str, Any]) -> float:
        """Analyze cyber kill chain progression"""
        # This would track events across the kill chain phases
        # For now, return a simplified analysis
        
        phase_scores = {
            'reconnaissance': 0.2,
            'weaponization': 0.4,
            'delivery': 0.6,
            'exploitation': 0.8,
            'installation': 0.7,
            'command_control': 0.9,
            'actions_objectives': 1.0
        }
        
        category = event_data.get('category', '').lower()
        if category in phase_scores:
            return phase_scores[category]
        
        return 0.0
    
    def _detect_lateral_movement(self, event_data: Dict[str, Any]) -> float:
        """Detect lateral movement patterns"""
        score = 0.0
        
        # Check for authentication events across multiple hosts
        if (event_data.get('category') == 'authentication' and
            event_data.get('source_ip') != event_data.get('destination_ip')):
            
            # Look for multiple authentication attempts in short time
            recent_auth_hosts = self._count_recent_auth_hosts(event_data.get('user_name'), minutes=30)
            if recent_auth_hosts > 3:
                score = max(score, 0.7)
            elif recent_auth_hosts > 1:
                score = max(score, 0.4)
        
        # Administrative tool usage on remote hosts
        if (event_data.get('process_name', '').lower() in ['psexec.exe', 'wmic.exe'] and
            event_data.get('source_ip') != event_data.get('destination_ip')):
            score = max(score, 0.8)
        
        return score
    
    def _detect_exfiltration_patterns(self, event_data: Dict[str, Any]) -> float:
        """Detect data exfiltration patterns"""
        score = 0.0
        
        # Large data transfers
        if event_data.get('bytes_transferred', 0) > 100_000_000:  # > 100MB
            score = max(score, 0.6)
        
        # Unusual time of data transfer
        if event_data.get('timestamp'):
            hour = datetime.fromisoformat(str(event_data['timestamp'])).hour
            if hour < 6 or hour > 22:  # Outside business hours
                score = max(score, 0.3)
        
        # Compression/archiving tools
        if any(tool in event_data.get('process_name', '').lower() for tool in 
               ['7z', 'winrar', 'zip', 'tar']):
            score = max(score, 0.4)
        
        return score
    
    def _calculate_overall_score(self, behavioral: float, anomaly: float, 
                               intelligence: float, pattern: float) -> float:
        """Calculate weighted overall threat score"""
        weights = {
            'behavioral': 0.25,
            'anomaly': 0.25,
            'intelligence': 0.30,
            'pattern': 0.20
        }
        
        overall = (behavioral * weights['behavioral'] + 
                  anomaly * weights['anomaly'] + 
                  intelligence * weights['intelligence'] + 
                  pattern * weights['pattern'])
        
        return min(overall, 1.0)
    
    def _identify_risk_factors(self, event_data: Dict[str, Any], 
                             behavioral: float, anomaly: float, intelligence: float) -> List[str]:
        """Identify specific risk factors"""
        risk_factors = []
        
        if behavioral > 0.5:
            risk_factors.append('behavioral_anomaly')
        
        if anomaly > 0.5:
            risk_factors.append('statistical_anomaly')
        
        if intelligence > 0.3:
            risk_factors.append('threat_intelligence_match')
        
        # Specific indicators
        if event_data.get('severity') in ['high', 'critical']:
            risk_factors.append('high_severity_event')
        
        if any(word in event_data.get('message', '').lower() for word in 
               ['failed', 'error', 'denied', 'blocked']):
            risk_factors.append('security_control_triggered')
        
        if event_data.get('user_name', '').lower() in ['admin', 'administrator', 'root']:
            risk_factors.append('privileged_account')
        
        return risk_factors
    
    def _recommend_action(self, overall_score: float, risk_factors: List[str]) -> str:
        """Recommend appropriate response action"""
        if overall_score >= 0.8:
            return 'immediate_response'
        elif overall_score >= 0.6:
            return 'investigate'
        elif overall_score >= 0.4:
            return 'monitor_closely'
        elif overall_score >= 0.2:
            return 'monitor'
        else:
            return 'log_only'
    
    def _generate_explanation(self, overall_score: float, risk_factors: List[str]) -> str:
        """Generate human-readable explanation"""
        if overall_score >= 0.8:
            return f"High-confidence threat detected with risk factors: {', '.join(risk_factors)}"
        elif overall_score >= 0.6:
            return f"Potentially suspicious activity detected: {', '.join(risk_factors)}"
        elif overall_score >= 0.4:
            return f"Anomalous behavior observed: {', '.join(risk_factors)}"
        elif overall_score >= 0.2:
            return f"Minor security indicators: {', '.join(risk_factors)}"
        else:
            return "Normal activity with no significant security indicators"
    
    def _calculate_confidence(self, event_data: Dict[str, Any], overall_score: float) -> float:
        """Calculate confidence in the threat assessment"""
        confidence = 0.5  # Base confidence
        
        # Increase confidence with more data points
        data_points = len([v for v in event_data.values() if v is not None])
        confidence += min(data_points * 0.02, 0.3)
        
        # Increase confidence with threat intelligence correlation
        if overall_score > 0.5:
            confidence += 0.2
        
        # Model training status affects confidence
        if self.model_trained:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _continuous_learning_loop(self):
        """Continuous learning from security events"""
        while True:
            try:
                time.sleep(3600)  # Run every hour
                
                if len(self.event_history) > 100:  # Need sufficient data
                    with self.training_lock:
                        self._retrain_models()
                        
            except Exception as e:
                logger.error(f"Continuous learning error: {e}")
    
    def _retrain_models(self):
        """Retrain ML models with recent data"""
        try:
            # Prepare training data
            features_list = []
            for event in list(self.event_history)[-1000:]:  # Last 1000 events
                if 'features' in event:
                    features_list.append(event['features'])
            
            if len(features_list) < 50:
                return
            
            X = np.array(features_list)
            
            # Retrain isolation forest
            self.isolation_forest.fit(X)
            
            # Retrain scaler
            self.scaler.fit(X)
            
            self.model_trained = True
            self.last_training = datetime.utcnow()
            
            # Save models
            self._save_models()
            
            logger.info(f"Models retrained with {len(features_list)} samples")
            
        except Exception as e:
            logger.error(f"Model retraining failed: {e}")
    
    def _save_models(self):
        """Save trained models to disk"""
        try:
            os.makedirs(self.models_path, exist_ok=True)
            
            joblib.dump(self.isolation_forest, os.path.join(self.models_path, 'isolation_forest.joblib'))
            joblib.dump(self.scaler, os.path.join(self.models_path, 'scaler.joblib'))
            
            # Save metadata
            metadata = {
                'last_training': self.last_training.isoformat() if self.last_training else None,
                'training_samples': len(self.event_history)
            }
            
            with open(os.path.join(self.models_path, 'metadata.json'), 'w') as f:
                json.dump(metadata, f)
                
        except Exception as e:
            logger.error(f"Failed to save models: {e}")
    
    def _load_models(self):
        """Load pre-trained models from disk"""
        try:
            if os.path.exists(os.path.join(self.models_path, 'isolation_forest.joblib')):
                self.isolation_forest = joblib.load(os.path.join(self.models_path, 'isolation_forest.joblib'))
                self.scaler = joblib.load(os.path.join(self.models_path, 'scaler.joblib'))
                self.model_trained = True
                
                # Load metadata
                metadata_path = os.path.join(self.models_path, 'metadata.json')
                if os.path.exists(metadata_path):
                    with open(metadata_path, 'r') as f:
                        metadata = json.load(f)
                        if metadata.get('last_training'):
                            self.last_training = datetime.fromisoformat(metadata['last_training'])
                
                logger.info("Pre-trained models loaded successfully")
                
        except Exception as e:
            logger.warning(f"Failed to load pre-trained models: {e}")
    
    def get_ai_statistics(self) -> Dict[str, Any]:
        """Get AI engine statistics and health"""
        return {
            'model_trained': self.model_trained,
            'last_training': self.last_training.isoformat() if self.last_training else None,
            'events_analyzed': len(self.event_history),
            'behavioral_patterns': len(self.behavioral_baselines),
            'threat_signatures': len(self.threat_signatures),
            'confidence_threshold': self.confidence_threshold,
            'anomaly_threshold': self.anomaly_threshold
        }
    
    # Helper methods for simplified implementation
    def _get_ip_reputation_score(self, ip: str) -> float:
        """Get IP reputation score (0-1, higher = more suspicious)"""
        # Simplified implementation - would integrate with threat intel feeds
        if ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.'):
            return 0.0  # Internal IPs
        return 0.1  # Unknown external IPs get low score
    
    def _calculate_baseline_metrics(self, features: np.ndarray) -> Dict[str, float]:
        """Calculate baseline metrics from features"""
        return {
            'mean': float(np.mean(features)),
            'std': float(np.std(features)),
            'max': float(np.max(features)),
            'min': float(np.min(features))
        }
    
    def _calculate_behavioral_deviation(self, baseline: Dict[str, float], 
                                      current: Dict[str, float]) -> float:
        """Calculate behavioral deviation score"""
        deviations = []
        for key in baseline:
            if key in current and baseline[key] != 0:
                deviation = abs(current[key] - baseline[key]) / baseline[key]
                deviations.append(deviation)
        
        return np.mean(deviations) if deviations else 0.0
    
    def _count_recent_events(self, event_type: str, minutes: int = 10) -> int:
        """Count recent events of specific type"""
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        count = 0
        for event in self.event_history:
            if (event['timestamp'] > cutoff and 
                event['event_data'].get('category') == event_type):
                count += 1
        return count
    
    def _count_recent_auth_hosts(self, username: str, minutes: int = 30) -> int:
        """Count recent authentication hosts for user"""
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        hosts = set()
        for event in self.event_history:
            if (event['timestamp'] > cutoff and 
                event['event_data'].get('user_name') == username and
                event['event_data'].get('category') == 'authentication'):
                hosts.add(event['event_data'].get('host_name', 'unknown'))
        return len(hosts)
    
    def _check_ip_threat_intelligence(self, ip: str) -> Optional[Dict[str, Any]]:
        """Check IP against threat intelligence (placeholder)"""
        # This would integrate with real threat intelligence feeds
        return None
    
    def _check_domain_threat_intelligence(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check domain against threat intelligence (placeholder)"""
        return None
    
    def _check_hash_threat_intelligence(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Check file hash against threat intelligence (placeholder)"""
        return None