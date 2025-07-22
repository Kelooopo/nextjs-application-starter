"""
SentinelWatch Pro Enterprise Integrations
Mind-blowing enterprise integration framework with advanced security features
"""

import asyncio
import json
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import hashlib
import hmac
import base64
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import boto3
import paramiko
from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry, push_to_gateway
from elasticsearch import Elasticsearch
import logging
from dataclasses import dataclass
# from microsoft_teams import ConnectorCard, MessageCard  # Alternative Teams implementation

# Metrics for monitoring integration health
INTEGRATION_REQUESTS = Counter('sentinel_integration_requests_total', 'Total integration requests', ['integration_type', 'status'])
INTEGRATION_LATENCY = Histogram('sentinel_integration_request_duration_seconds', 'Integration request duration', ['integration_type'])
INTEGRATION_STATUS = Gauge('sentinel_integration_status', 'Integration health status', ['integration_name'])

logger = logging.getLogger(__name__)

@dataclass
class IntegrationResult:
    """Standardized integration result"""
    success: bool
    message: str
    data: Dict[str, Any] = None
    error_code: str = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()

class BaseIntegration:
    """Base class for all enterprise integrations"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = config.get('name', 'unknown')
        self.enabled = config.get('enabled', True)
        self.retry_config = config.get('retry', {'retries': 3, 'backoff_factor': 0.3})
        self.timeout = config.get('timeout', 30)
        
        # Setup HTTP session with retries
        self.session = requests.Session()
        retry_strategy = Retry(
            total=self.retry_config['retries'],
            backoff_factor=self.retry_config['backoff_factor'],
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    def is_healthy(self) -> bool:
        """Check if integration is healthy"""
        try:
            return self.health_check()
        except Exception as e:
            logger.error(f"Health check failed for {self.name}: {e}")
            INTEGRATION_STATUS.labels(integration_name=self.name).set(0)
            return False
    
    def health_check(self) -> bool:
        """Override this method in subclasses"""
        return True
    
    def execute_with_metrics(self, operation_name: str, func, *args, **kwargs):
        """Execute function with automatic metrics collection"""
        start_time = time.time()
        status = 'success'
        
        try:
            result = func(*args, **kwargs)
            INTEGRATION_STATUS.labels(integration_name=self.name).set(1)
            return result
        except Exception as e:
            status = 'error'
            INTEGRATION_STATUS.labels(integration_name=self.name).set(0)
            logger.error(f"Integration {self.name} operation {operation_name} failed: {e}")
            raise
        finally:
            duration = time.time() - start_time
            INTEGRATION_LATENCY.labels(integration_type=self.__class__.__name__).observe(duration)
            INTEGRATION_REQUESTS.labels(integration_type=self.__class__.__name__, status=status).inc()

class SIEMIntegration(BaseIntegration):
    """Advanced SIEM integration for Splunk, QRadar, Sentinel"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.siem_type = config['siem_type']  # splunk, qradar, sentinel
        self.api_endpoint = config['api_endpoint']
        self.auth_token = config['auth_token']
        self.index_name = config.get('index_name', 'sentinelwatch')
    
    def send_event(self, event_data: Dict[str, Any]) -> IntegrationResult:
        """Send security event to SIEM"""
        def _send():
            if self.siem_type == 'splunk':
                return self._send_to_splunk(event_data)
            elif self.siem_type == 'qradar':
                return self._send_to_qradar(event_data)
            elif self.siem_type == 'sentinel':
                return self._send_to_sentinel(event_data)
            else:
                raise ValueError(f"Unsupported SIEM type: {self.siem_type}")
        
        return self.execute_with_metrics('send_event', _send)
    
    def _send_to_splunk(self, event_data: Dict[str, Any]) -> IntegrationResult:
        """Send event to Splunk HEC"""
        payload = {
            'time': int(time.time()),
            'index': self.index_name,
            'sourcetype': 'sentinelwatch:alert',
            'event': event_data
        }
        
        headers = {
            'Authorization': f'Splunk {self.auth_token}',
            'Content-Type': 'application/json'
        }
        
        response = self.session.post(
            f"{self.api_endpoint}/services/collector/event",
            json=payload,
            headers=headers,
            timeout=self.timeout
        )
        
        if response.status_code == 200:
            return IntegrationResult(success=True, message="Event sent to Splunk successfully")
        else:
            return IntegrationResult(success=False, message=f"Splunk error: {response.text}")
    
    def _send_to_qradar(self, event_data: Dict[str, Any]) -> IntegrationResult:
        """Send event to IBM QRadar"""
        # QRadar uses custom event format
        qradar_event = f"<{int(time.time())}> {json.dumps(event_data)}"
        
        headers = {
            'SEC': self.auth_token,
            'Content-Type': 'application/json'
        }
        
        response = self.session.post(
            f"{self.api_endpoint}/api/siem/events",
            data=qradar_event,
            headers=headers,
            timeout=self.timeout
        )
        
        if response.status_code in [200, 202]:
            return IntegrationResult(success=True, message="Event sent to QRadar successfully")
        else:
            return IntegrationResult(success=False, message=f"QRadar error: {response.text}")
    
    def _send_to_sentinel(self, event_data: Dict[str, Any]) -> IntegrationResult:
        """Send event to Microsoft Sentinel"""
        # Azure Sentinel Log Analytics workspace integration
        payload = json.dumps(event_data)
        
        headers = {
            'Authorization': f'Bearer {self.auth_token}',
            'Content-Type': 'application/json',
            'Log-Type': 'SentinelWatch'
        }
        
        response = self.session.post(
            f"{self.api_endpoint}/api/logs",
            data=payload,
            headers=headers,
            timeout=self.timeout
        )
        
        if response.status_code == 200:
            return IntegrationResult(success=True, message="Event sent to Sentinel successfully")
        else:
            return IntegrationResult(success=False, message=f"Sentinel error: {response.text}")

class CloudSecurityIntegration(BaseIntegration):
    """Advanced cloud security integration for AWS, Azure, GCP"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.cloud_provider = config['provider']  # aws, azure, gcp
        self.region = config.get('region', 'us-east-1')
        
        if self.cloud_provider == 'aws':
            self.aws_client = boto3.client('guardduty', region_name=self.region)
            self.s3_client = boto3.client('s3', region_name=self.region)
    
    def check_cloud_threats(self) -> IntegrationResult:
        """Check for cloud-based security threats"""
        def _check():
            if self.cloud_provider == 'aws':
                return self._check_aws_guardduty()
            # Add Azure Security Center and GCP Security Command Center support
            else:
                return IntegrationResult(success=False, message=f"Cloud provider {self.cloud_provider} not yet supported")
        
        return self.execute_with_metrics('check_cloud_threats', _check)
    
    def _check_aws_guardduty(self) -> IntegrationResult:
        """Check AWS GuardDuty for threats"""
        try:
            response = self.aws_client.list_findings(
                DetectorId=self.config['detector_id'],
                FindingCriteria={
                    'Criterion': {
                        'severity': {
                            'Gte': 4.0  # Medium and higher severity
                        },
                        'updatedAt': {
                            'Gte': int((datetime.utcnow() - timedelta(hours=1)).timestamp() * 1000)
                        }
                    }
                }
            )
            
            findings = response.get('FindingIds', [])
            
            if findings:
                # Get detailed findings
                detailed_findings = self.aws_client.get_findings(
                    DetectorId=self.config['detector_id'],
                    FindingIds=findings[:10]  # Limit to first 10
                )
                
                return IntegrationResult(
                    success=True,
                    message=f"Found {len(findings)} AWS security findings",
                    data={'findings': detailed_findings['Findings']}
                )
            else:
                return IntegrationResult(success=True, message="No new AWS security findings")
                
        except Exception as e:
            return IntegrationResult(success=False, message=f"AWS GuardDuty error: {str(e)}")

class ThreatIntelligenceIntegration(BaseIntegration):
    """Advanced threat intelligence integration"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.providers = config.get('providers', [])
        self.api_keys = config.get('api_keys', {})
        self.cache_duration = config.get('cache_duration', 3600)  # 1 hour
        self.threat_cache = {}
    
    def enrich_indicator(self, ioc_type: str, ioc_value: str) -> IntegrationResult:
        """Enrich IOC with threat intelligence"""
        def _enrich():
            cache_key = f"{ioc_type}:{ioc_value}"
            
            # Check cache first
            if cache_key in self.threat_cache:
                cache_entry = self.threat_cache[cache_key]
                if (datetime.utcnow() - cache_entry['timestamp']).seconds < self.cache_duration:
                    return IntegrationResult(
                        success=True,
                        message="Retrieved from cache",
                        data=cache_entry['data']
                    )
            
            # Enrich from multiple sources
            enrichment_data = {}
            
            for provider in self.providers:
                try:
                    if provider == 'virustotal' and 'virustotal' in self.api_keys:
                        vt_data = self._query_virustotal(ioc_type, ioc_value)
                        if vt_data:
                            enrichment_data['virustotal'] = vt_data
                    
                    elif provider == 'otx' and 'otx' in self.api_keys:
                        otx_data = self._query_otx(ioc_type, ioc_value)
                        if otx_data:
                            enrichment_data['otx'] = otx_data
                    
                    elif provider == 'misp' and 'misp' in self.api_keys:
                        misp_data = self._query_misp(ioc_type, ioc_value)
                        if misp_data:
                            enrichment_data['misp'] = misp_data
                            
                except Exception as e:
                    logger.warning(f"Failed to query {provider} for {ioc_value}: {e}")
                    continue
            
            # Cache results
            self.threat_cache[cache_key] = {
                'data': enrichment_data,
                'timestamp': datetime.utcnow()
            }
            
            return IntegrationResult(
                success=True,
                message=f"Enriched {ioc_value} with {len(enrichment_data)} sources",
                data=enrichment_data
            )
        
        return self.execute_with_metrics('enrich_indicator', _enrich)
    
    def _query_virustotal(self, ioc_type: str, ioc_value: str) -> Optional[Dict]:
        """Query VirusTotal API"""
        api_key = self.api_keys['virustotal']
        
        if ioc_type == 'ip':
            url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
            params = {'apikey': api_key, 'ip': ioc_value}
        elif ioc_type == 'domain':
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {'apikey': api_key, 'domain': ioc_value}
        elif ioc_type == 'hash':
            url = f"https://www.virustotal.com/vtapi/v2/file/report"
            params = {'apikey': api_key, 'resource': ioc_value}
        else:
            return None
        
        response = self.session.get(url, params=params, timeout=self.timeout)
        
        if response.status_code == 200:
            return response.json()
        return None
    
    def _query_otx(self, ioc_type: str, ioc_value: str) -> Optional[Dict]:
        """Query AlienVault OTX API"""
        api_key = self.api_keys['otx']
        headers = {'X-OTX-API-KEY': api_key}
        
        if ioc_type == 'ip':
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc_value}/general"
        elif ioc_type == 'domain':
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{ioc_value}/general"
        elif ioc_type == 'hash':
            url = f"https://otx.alienvault.com/api/v1/indicators/file/{ioc_value}/general"
        else:
            return None
        
        response = self.session.get(url, headers=headers, timeout=self.timeout)
        
        if response.status_code == 200:
            return response.json()
        return None

class TicketingIntegration(BaseIntegration):
    """Advanced ticketing system integration (Jira, ServiceNow, etc.)"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.platform = config['platform']  # jira, servicenow, freshservice
        self.base_url = config['base_url']
        self.username = config['username']
        self.api_token = config['api_token']
        self.project_key = config.get('project_key', 'SEC')
    
    def create_incident_ticket(self, incident_data: Dict[str, Any]) -> IntegrationResult:
        """Create incident ticket automatically"""
        def _create():
            if self.platform == 'jira':
                return self._create_jira_ticket(incident_data)
            elif self.platform == 'servicenow':
                return self._create_servicenow_ticket(incident_data)
            else:
                raise ValueError(f"Unsupported ticketing platform: {self.platform}")
        
        return self.execute_with_metrics('create_ticket', _create)
    
    def _create_jira_ticket(self, incident_data: Dict[str, Any]) -> IntegrationResult:
        """Create Jira ticket for security incident"""
        severity_priority_map = {
            'critical': 'Highest',
            'high': 'High',
            'medium': 'Medium',
            'low': 'Low'
        }
        
        ticket_data = {
            'fields': {
                'project': {'key': self.project_key},
                'summary': f"[SECURITY] {incident_data['title']}",
                'description': {
                    'type': 'doc',
                    'version': 1,
                    'content': [{
                        'type': 'paragraph',
                        'content': [{
                            'type': 'text',
                            'text': f"Security Incident: {incident_data['description']}\n\n"
                                   f"Severity: {incident_data['severity']}\n"
                                   f"Detected at: {incident_data['created_at']}\n"
                                   f"Source: SentinelWatch Pro"
                        }]
                    }]
                },
                'issuetype': {'name': 'Bug'},  # or 'Security Incident' if custom type exists
                'priority': {'name': severity_priority_map.get(incident_data['severity'], 'Medium')},
                'labels': ['security', 'automated', 'sentinelwatch']
            }
        }
        
        auth = (self.username, self.api_token)
        response = self.session.post(
            f"{self.base_url}/rest/api/3/issue",
            json=ticket_data,
            auth=auth,
            timeout=self.timeout
        )
        
        if response.status_code == 201:
            ticket_info = response.json()
            return IntegrationResult(
                success=True,
                message=f"Created Jira ticket {ticket_info['key']}",
                data={'ticket_key': ticket_info['key'], 'ticket_url': f"{self.base_url}/browse/{ticket_info['key']}"}
            )
        else:
            return IntegrationResult(success=False, message=f"Jira error: {response.text}")

class CommunicationIntegration(BaseIntegration):
    """Advanced communication integration (Slack, Teams, Email)"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.channels = config.get('channels', {})
        self.escalation_rules = config.get('escalation_rules', {})
    
    def send_security_alert(self, alert_data: Dict[str, Any]) -> IntegrationResult:
        """Send security alert through multiple channels"""
        def _send():
            results = []
            severity = alert_data.get('severity', 'medium')
            
            # Determine which channels to use based on severity
            channels_to_use = self._get_channels_for_severity(severity)
            
            for channel_type, channel_config in channels_to_use.items():
                try:
                    if channel_type == 'slack':
                        result = self._send_slack_alert(alert_data, channel_config)
                    elif channel_type == 'teams':
                        result = self._send_teams_alert(alert_data, channel_config)
                    elif channel_type == 'email':
                        result = self._send_email_alert(alert_data, channel_config)
                    else:
                        continue
                    
                    results.append(result)
                    
                except Exception as e:
                    logger.error(f"Failed to send alert via {channel_type}: {e}")
                    results.append(IntegrationResult(success=False, message=f"{channel_type} error: {str(e)}"))
            
            successful_channels = sum(1 for r in results if r.success)
            
            return IntegrationResult(
                success=successful_channels > 0,
                message=f"Alert sent via {successful_channels}/{len(results)} channels",
                data={'results': results}
            )
        
        return self.execute_with_metrics('send_alert', _send)
    
    def _get_channels_for_severity(self, severity: str) -> Dict[str, Dict]:
        """Get appropriate communication channels based on severity"""
        if severity == 'critical':
            return {k: v for k, v in self.channels.items() if v.get('critical', False)}
        elif severity == 'high':
            return {k: v for k, v in self.channels.items() if v.get('high', True)}
        else:
            return {k: v for k, v in self.channels.items() if not v.get('critical_only', False)}
    
    def _send_teams_alert(self, alert_data: Dict[str, Any], config: Dict[str, Any]) -> IntegrationResult:
        """Send alert to Microsoft Teams"""
        webhook_url = config['webhook_url']
        
        # Create Teams adaptive card payload
        teams_payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": self._get_color_for_severity(alert_data.get('severity', 'medium')),
            "summary": f"Security Alert: {alert_data['title']}",
            "sections": [{
                "activityTitle": f"🚨 Security Alert: {alert_data['title']}",
                "activitySubtitle": alert_data['message'],
                "facts": [
                    {"name": "Severity", "value": alert_data.get('severity', 'Unknown')},
                    {"name": "Source", "value": alert_data.get('source', 'SentinelWatch Pro')},
                    {"name": "Time", "value": alert_data.get('created_at', datetime.utcnow().isoformat())}
                ]
            }],
            "potentialAction": [{
                "@type": "OpenUri",
                "name": "View Dashboard",
                "targets": [{
                    "os": "default",
                    "uri": f"https://{config.get('dashboard_url', 'localhost:5000')}"
                }]
            }]
        }
        
        # Add additional facts if available
        if alert_data.get('host_name'):
            teams_payload['sections'][0]['facts'].append({"name": "Host", "value": alert_data['host_name']})
        if alert_data.get('source_ip'):
            teams_payload['sections'][0]['facts'].append({"name": "Source IP", "value": alert_data['source_ip']})
        
        response = self.session.post(webhook_url, json=teams_payload, timeout=self.timeout)
        
        if response.status_code == 200:
            return IntegrationResult(success=True, message="Teams alert sent successfully")
        else:
            return IntegrationResult(success=False, message=f"Teams error: {response.text}")
    
    def _get_color_for_severity(self, severity: str) -> str:
        """Get color code for severity level"""
        colors = {
            'critical': 'FF0000',  # Red
            'high': 'FF6600',      # Orange
            'medium': 'FFCC00',    # Yellow
            'low': '00CC00'        # Green
        }
        return colors.get(severity, 'CCCCCC')

class ComplianceIntegration(BaseIntegration):
    """Advanced compliance monitoring integration"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.frameworks = config.get('frameworks', [])  # SOC2, PCI_DSS, GDPR, ISO27001
        self.evidence_storage = config.get('evidence_storage', {})
    
    def generate_compliance_report(self, framework: str, period_days: int = 30) -> IntegrationResult:
        """Generate compliance report for specific framework"""
        def _generate():
            # This would integrate with compliance databases and evidence collection
            report_data = {
                'framework': framework,
                'period': f"{period_days} days",
                'generated_at': datetime.utcnow().isoformat(),
                'compliance_score': self._calculate_compliance_score(framework, period_days),
                'controls_assessed': self._assess_controls(framework),
                'findings': self._get_compliance_findings(framework, period_days),
                'recommendations': self._get_recommendations(framework)
            }
            
            # Store evidence if configured
            if self.evidence_storage.get('enabled'):
                self._store_compliance_evidence(report_data)
            
            return IntegrationResult(
                success=True,
                message=f"Generated {framework} compliance report",
                data=report_data
            )
        
        return self.execute_with_metrics('generate_compliance_report', _generate)
    
    def _calculate_compliance_score(self, framework: str, period_days: int) -> float:
        """Calculate compliance score (0-100)"""
        # This would analyze actual security events and controls
        # For demo purposes, return a calculated score
        return 85.5
    
    def _assess_controls(self, framework: str) -> List[Dict]:
        """Assess compliance controls"""
        # Framework-specific control assessment
        controls = []
        
        if framework == 'SOC2':
            controls = [
                {'control': 'CC6.1', 'name': 'Logical Access Controls', 'status': 'compliant'},
                {'control': 'CC7.1', 'name': 'System Monitoring', 'status': 'compliant'},
                {'control': 'CC8.1', 'name': 'Change Management', 'status': 'needs_attention'}
            ]
        elif framework == 'PCI_DSS':
            controls = [
                {'control': '1.1.1', 'name': 'Firewall Configuration', 'status': 'compliant'},
                {'control': '2.1', 'name': 'Default Passwords', 'status': 'compliant'},
                {'control': '10.1', 'name': 'Audit Trails', 'status': 'compliant'}
            ]
        
        return controls

class IntegrationOrchestrator:
    """Orchestrates all enterprise integrations"""
    
    def __init__(self):
        self.integrations: Dict[str, BaseIntegration] = {}
        self.health_check_interval = 300  # 5 minutes
        self.running = False
        self.health_check_thread = None
    
    def register_integration(self, name: str, integration: BaseIntegration):
        """Register a new integration"""
        self.integrations[name] = integration
        logger.info(f"Registered integration: {name}")
    
    def start_health_monitoring(self):
        """Start background health monitoring"""
        self.running = True
        self.health_check_thread = threading.Thread(target=self._health_check_loop)
        self.health_check_thread.daemon = True
        self.health_check_thread.start()
        logger.info("Started integration health monitoring")
    
    def stop_health_monitoring(self):
        """Stop background health monitoring"""
        self.running = False
        if self.health_check_thread:
            self.health_check_thread.join()
        logger.info("Stopped integration health monitoring")
    
    def _health_check_loop(self):
        """Background health check loop"""
        while self.running:
            for name, integration in self.integrations.items():
                try:
                    is_healthy = integration.is_healthy()
                    logger.debug(f"Integration {name} health: {'OK' if is_healthy else 'FAILED'}")
                except Exception as e:
                    logger.error(f"Health check error for {name}: {e}")
            
            time.sleep(self.health_check_interval)
    
    def get_integration_status(self) -> Dict[str, Dict]:
        """Get status of all integrations"""
        status = {}
        for name, integration in self.integrations.items():
            status[name] = {
                'enabled': integration.enabled,
                'healthy': integration.is_healthy(),
                'last_check': datetime.utcnow().isoformat()
            }
        return status
    
    async def broadcast_alert(self, alert_data: Dict[str, Any]) -> List[IntegrationResult]:
        """Broadcast alert to all relevant integrations"""
        tasks = []
        
        for name, integration in self.integrations.items():
            if not integration.enabled:
                continue
            
            if isinstance(integration, SIEMIntegration):
                tasks.append(asyncio.create_task(self._async_send_to_siem(integration, alert_data)))
            elif isinstance(integration, CommunicationIntegration):
                tasks.append(asyncio.create_task(self._async_send_alert(integration, alert_data)))
            elif isinstance(integration, TicketingIntegration) and alert_data.get('severity') in ['critical', 'high']:
                tasks.append(asyncio.create_task(self._async_create_ticket(integration, alert_data)))
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return [r for r in results if isinstance(r, IntegrationResult)]
        
        return []
    
    async def _async_send_to_siem(self, integration: SIEMIntegration, alert_data: Dict[str, Any]) -> IntegrationResult:
        """Async wrapper for SIEM integration"""
        return await asyncio.to_thread(integration.send_event, alert_data)
    
    async def _async_send_alert(self, integration: CommunicationIntegration, alert_data: Dict[str, Any]) -> IntegrationResult:
        """Async wrapper for communication integration"""
        return await asyncio.to_thread(integration.send_security_alert, alert_data)
    
    async def _async_create_ticket(self, integration: TicketingIntegration, alert_data: Dict[str, Any]) -> IntegrationResult:
        """Async wrapper for ticketing integration"""
        return await asyncio.to_thread(integration.create_incident_ticket, alert_data)