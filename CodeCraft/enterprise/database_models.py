"""
SentinelWatch Pro Enterprise Database Models
Advanced enterprise-grade database schema for security monitoring
"""

import os
from datetime import datetime, timedelta
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, ForeignKey, Index, JSON
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.ext.hybrid import hybrid_property
import json
from cryptography.fernet import Fernet

# Initialize database
Base = declarative_base()
db = SQLAlchemy(model_class=Base)
migrate = Migrate()

class ThreatIntelligence(db.Model):
    """Advanced threat intelligence database"""
    __tablename__ = 'threat_intelligence'
    
    id = Column(Integer, primary_key=True)
    ioc_type = Column(String(50), nullable=False)  # ip, domain, hash, url, email
    ioc_value = Column(String(500), nullable=False, index=True)
    threat_type = Column(String(100))  # malware, phishing, botnet, etc.
    severity = Column(String(20), default='medium')
    confidence = Column(Float, default=0.5)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    source = Column(String(100))  # virustotal, otx, custom
    context = Column(JSON)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    detections = relationship("ThreatDetection", back_populates="threat_intel")
    
    def __repr__(self):
        return f'<ThreatIntel {self.ioc_type}:{self.ioc_value}>'

class Asset(db.Model):
    """Enterprise asset inventory"""
    __tablename__ = 'assets'
    
    id = Column(Integer, primary_key=True)
    asset_type = Column(String(50), nullable=False)  # server, workstation, network_device
    hostname = Column(String(255), index=True)
    ip_address = Column(String(45), index=True)  # IPv4/IPv6
    mac_address = Column(String(18))
    os_type = Column(String(50))
    os_version = Column(String(100))
    domain = Column(String(255))
    owner = Column(String(100))
    business_unit = Column(String(100))
    criticality = Column(String(20), default='medium')  # low, medium, high, critical
    location = Column(String(255))
    last_seen = Column(DateTime, default=datetime.utcnow)
    status = Column(String(20), default='active')
    asset_metadata = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    incidents = relationship("SecurityIncident", back_populates="asset")
    vulnerabilities = relationship("Vulnerability", back_populates="asset")
    
    def __repr__(self):
        return f'<Asset {self.hostname}:{self.ip_address}>'

class SecurityIncident(db.Model):
    """Enterprise incident management"""
    __tablename__ = 'security_incidents'
    
    id = Column(Integer, primary_key=True)
    incident_id = Column(String(50), unique=True, index=True)  # INC-2025-001
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(String(20), nullable=False)  # low, medium, high, critical
    status = Column(String(50), default='new')  # new, assigned, investigating, contained, resolved
    category = Column(String(100))  # malware, phishing, data_breach, etc.
    source = Column(String(100))  # automated, user_report, external
    
    # Asset information
    asset_id = Column(Integer, ForeignKey('assets.id'))
    asset = relationship("Asset", back_populates="incidents")
    
    # Assignment and workflow
    assigned_to = Column(String(100))
    team = Column(String(100))
    priority = Column(Integer, default=3)  # 1=critical, 5=low
    
    # Timeline
    created_at = Column(DateTime, default=datetime.utcnow)
    first_response_at = Column(DateTime)
    resolved_at = Column(DateTime)
    closed_at = Column(DateTime)
    
    # Metrics
    mean_time_to_detect = Column(Integer)  # minutes
    mean_time_to_respond = Column(Integer)  # minutes
    mean_time_to_resolve = Column(Integer)  # minutes
    
    # Additional data
    evidence = Column(JSON)
    remediation_steps = Column(Text)
    root_cause = Column(Text)
    lessons_learned = Column(Text)
    
    # Relationships
    alerts = relationship("Alert", back_populates="incident")
    
    @hybrid_property
    def sla_status(self):
        """Calculate SLA compliance based on severity"""
        if self.status in ['resolved', 'closed']:
            return 'met'
        
        sla_hours = {'critical': 1, 'high': 4, 'medium': 24, 'low': 72}
        target = sla_hours.get(self.severity, 24)
        
        if (datetime.utcnow() - self.created_at).total_seconds() / 3600 > target:
            return 'breached'
        return 'within_sla'
    
    def __repr__(self):
        return f'<Incident {self.incident_id}:{self.title}>'

class Alert(db.Model):
    """Enhanced alert system"""
    __tablename__ = 'alerts'
    
    id = Column(Integer, primary_key=True)
    alert_id = Column(String(50), unique=True, index=True)
    title = Column(String(500), nullable=False)
    message = Column(Text)
    severity = Column(String(20), nullable=False)
    category = Column(String(100))
    source_system = Column(String(100))
    
    # Status and workflow
    status = Column(String(50), default='new')  # new, acknowledged, investigating, resolved, false_positive
    assigned_to = Column(String(100))
    
    # Context
    source_ip = Column(String(45))
    destination_ip = Column(String(45))
    process_name = Column(String(255))
    user_name = Column(String(100))
    host_name = Column(String(255))
    
    # Timestamps
    event_time = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    acknowledged_at = Column(DateTime)
    resolved_at = Column(DateTime)
    
    # Relationships
    incident_id = Column(Integer, ForeignKey('security_incidents.id'))
    incident = relationship("SecurityIncident", back_populates="alerts")
    
    # Raw event data
    raw_data = Column(JSON)
    enrichment_data = Column(JSON)
    
    def __repr__(self):
        return f'<Alert {self.alert_id}:{self.title}>'

class ThreatDetection(db.Model):
    """Advanced threat detection results"""
    __tablename__ = 'threat_detections'
    
    id = Column(Integer, primary_key=True)
    detection_id = Column(String(50), unique=True, index=True)
    threat_intel_id = Column(Integer, ForeignKey('threat_intelligence.id'))
    threat_intel = relationship("ThreatIntelligence", back_populates="detections")
    
    detected_value = Column(String(500), nullable=False)
    detection_method = Column(String(100))  # signature, behavioral, ml, heuristic
    confidence_score = Column(Float)
    
    # Context
    asset_affected = Column(String(255))
    process_info = Column(JSON)
    network_info = Column(JSON)
    file_info = Column(JSON)
    
    # Actions taken
    action_taken = Column(String(100))  # blocked, quarantined, monitored, alerted
    remediation_status = Column(String(50), default='pending')
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Detection {self.detection_id}:{self.detected_value}>'

class Vulnerability(db.Model):
    """Vulnerability management"""
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    cve_id = Column(String(20), index=True)
    title = Column(String(500))
    description = Column(Text)
    severity = Column(String(20))  # critical, high, medium, low
    cvss_score = Column(Float)
    
    # Asset relationship
    asset_id = Column(Integer, ForeignKey('assets.id'))
    asset = relationship("Asset", back_populates="vulnerabilities")
    
    # Vulnerability details
    affected_software = Column(String(255))
    software_version = Column(String(100))
    patch_available = Column(Boolean, default=False)
    patch_priority = Column(String(20))
    
    # Status tracking
    status = Column(String(50), default='open')  # open, patched, mitigated, accepted
    discovered_at = Column(DateTime, default=datetime.utcnow)
    patched_at = Column(DateTime)
    
    # Additional context
    exploit_available = Column(Boolean, default=False)
    in_wild = Column(Boolean, default=False)
    references = Column(JSON)
    
    def __repr__(self):
        return f'<Vulnerability {self.cve_id}:{self.title}>'

class ComplianceCheck(db.Model):
    """Compliance monitoring and reporting"""
    __tablename__ = 'compliance_checks'
    
    id = Column(Integer, primary_key=True)
    framework = Column(String(50), nullable=False)  # SOC2, PCI_DSS, GDPR, ISO27001
    control_id = Column(String(50), nullable=False)
    control_name = Column(String(255))
    description = Column(Text)
    
    # Assessment results
    status = Column(String(50))  # compliant, non_compliant, not_applicable
    evidence = Column(Text)
    remediation_plan = Column(Text)
    risk_level = Column(String(20))
    
    # Timeline
    last_assessed = Column(DateTime, default=datetime.utcnow)
    next_assessment = Column(DateTime)
    
    # Responsible parties
    owner = Column(String(100))
    assessor = Column(String(100))
    
    def __repr__(self):
        return f'<ComplianceCheck {self.framework}:{self.control_id}>'

class SystemMetrics(db.Model):
    """Historical system performance metrics"""
    __tablename__ = 'system_metrics'
    
    id = Column(Integer, primary_key=True)
    hostname = Column(String(255), nullable=False, index=True)
    
    # Performance metrics
    cpu_percent = Column(Float)
    memory_percent = Column(Float)
    disk_percent = Column(Float)
    network_bytes_sent = Column(Integer)
    network_bytes_recv = Column(Integer)
    
    # Process information
    process_count = Column(Integer)
    thread_count = Column(Integer)
    
    # Additional metrics
    load_average = Column(Float)
    uptime_seconds = Column(Integer)
    
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f'<SystemMetrics {self.hostname}:{self.timestamp}>'

class IntegrationConfig(db.Model):
    """Enterprise integration configurations"""
    __tablename__ = 'integration_configs'
    
    id = Column(Integer, primary_key=True)
    integration_type = Column(String(100), nullable=False)  # siem, cloud, ticketing, etc.
    integration_name = Column(String(255), nullable=False)
    
    # Configuration
    endpoint_url = Column(String(500))
    auth_type = Column(String(50))  # api_key, oauth, certificate
    encrypted_credentials = Column(Text)  # Encrypted storage
    
    # Status
    is_active = Column(Boolean, default=True)
    last_sync = Column(DateTime)
    sync_status = Column(String(50))  # success, error, pending
    error_message = Column(Text)
    
    # Configuration details
    config_data = Column(JSON)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def encrypt_credentials(self, credentials):
        """Encrypt sensitive credentials"""
        key = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key())
        f = Fernet(key)
        self.encrypted_credentials = f.encrypt(credentials.encode()).decode()
    
    def decrypt_credentials(self):
        """Decrypt sensitive credentials"""
        key = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key())
        f = Fernet(key)
        if self.encrypted_credentials:
            return f.decrypt(self.encrypted_credentials.encode()).decode()
        return None
    
    def __repr__(self):
        return f'<Integration {self.integration_type}:{self.integration_name}>'

# Database indexes for performance
Index('idx_alerts_severity_created', Alert.severity, Alert.created_at)
Index('idx_incidents_status_priority', SecurityIncident.status, SecurityIncident.priority)
Index('idx_threat_intel_type_value', ThreatIntelligence.ioc_type, ThreatIntelligence.ioc_value)
Index('idx_assets_ip_hostname', Asset.ip_address, Asset.hostname)
Index('idx_metrics_hostname_timestamp', SystemMetrics.hostname, SystemMetrics.timestamp)

def init_database(app):
    """Initialize database with Flask app"""
    db.init_app(app)
    migrate.init_app(app, db)
    
    # Create all tables
    with app.app_context():
        db.create_all()
        
    return db