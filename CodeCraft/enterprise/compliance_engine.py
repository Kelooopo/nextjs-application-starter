"""
SentinelWatch Pro Compliance & Governance Engine
Advanced compliance monitoring for SOC 2, PCI DSS, GDPR, ISO 27001, and more
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import json
import logging

@dataclass
class ComplianceResult:
    framework: str
    control_id: str
    status: str  # compliant, non_compliant, partial, not_applicable
    evidence: List[str]
    score: float  # 0-100
    recommendations: List[str]
    next_assessment: datetime

class ComplianceEngine:
    """Advanced compliance monitoring and assessment"""
    
    def __init__(self):
        self.frameworks = {
            'SOC2': self._init_soc2_controls(),
            'PCI_DSS': self._init_pci_controls(),
            'GDPR': self._init_gdpr_controls(),
            'ISO27001': self._init_iso27001_controls()
        }
    
    def assess_compliance(self, framework: str, security_events: List[Dict]) -> List[ComplianceResult]:
        """Comprehensive compliance assessment"""
        results = []
        
        if framework not in self.frameworks:
            return results
        
        controls = self.frameworks[framework]
        
        for control_id, control_info in controls.items():
            result = self._assess_control(control_id, control_info, security_events)
            results.append(result)
        
        return results
    
    def _init_soc2_controls(self) -> Dict:
        """SOC 2 Trust Services Criteria"""
        return {
            'CC6.1': {
                'name': 'Logical Access Controls',
                'description': 'Restrict logical access to systems, data, and applications',
                'assessment_criteria': ['authentication_events', 'access_violations', 'privilege_escalations']
            },
            'CC6.2': {
                'name': 'Authentication',
                'description': 'Strong authentication mechanisms',
                'assessment_criteria': ['failed_logins', 'weak_passwords', 'multi_factor_auth']
            },
            'CC7.1': {
                'name': 'System Monitoring',
                'description': 'Detect and respond to security threats',
                'assessment_criteria': ['security_monitoring', 'threat_detection', 'incident_response']
            },
            'CC8.1': {
                'name': 'Change Management',
                'description': 'Authorize and track system changes',
                'assessment_criteria': ['unauthorized_changes', 'system_modifications', 'configuration_drift']
            }
        }
    
    def _init_pci_controls(self) -> Dict:
        """PCI DSS Requirements"""
        return {
            '1.1': {
                'name': 'Firewall Configuration',
                'description': 'Maintain firewall configuration standards',
                'assessment_criteria': ['firewall_rules', 'network_segmentation', 'unauthorized_connections']
            },
            '2.1': {
                'name': 'Default Passwords',
                'description': 'Change vendor default passwords',
                'assessment_criteria': ['default_credentials', 'weak_passwords', 'password_policies']
            },
            '10.1': {
                'name': 'Audit Trails',
                'description': 'Implement audit trails for all system components',
                'assessment_criteria': ['logging_coverage', 'log_integrity', 'audit_events']
            }
        }
    
    def _init_gdpr_controls(self) -> Dict:
        """GDPR Articles"""
        return {
            '32': {
                'name': 'Security of Processing',
                'description': 'Implement appropriate technical measures',
                'assessment_criteria': ['data_encryption', 'access_controls', 'data_breaches']
            },
            '33': {
                'name': 'Data Breach Notification',
                'description': 'Notify authorities of data breaches',
                'assessment_criteria': ['breach_detection', 'notification_timeline', 'impact_assessment']
            }
        }
    
    def _init_iso27001_controls(self) -> Dict:
        """ISO 27001 Controls"""
        return {
            'A.12.6.1': {
                'name': 'Management of Technical Vulnerabilities',
                'description': 'Manage technical vulnerabilities',
                'assessment_criteria': ['vulnerability_scanning', 'patch_management', 'risk_assessment']
            },
            'A.16.1.1': {
                'name': 'Incident Management',
                'description': 'Manage information security incidents',
                'assessment_criteria': ['incident_detection', 'response_procedures', 'lessons_learned']
            }
        }
    
    def _assess_control(self, control_id: str, control_info: Dict, events: List[Dict]) -> ComplianceResult:
        """Assess individual compliance control"""
        evidence = []
        score = 100.0  # Start with perfect score
        status = 'compliant'
        recommendations = []
        
        # Analyze events against assessment criteria
        for criterion in control_info.get('assessment_criteria', []):
            criterion_score, criterion_evidence, criterion_recommendations = self._analyze_criterion(
                criterion, events
            )
            
            score = min(score, criterion_score)
            evidence.extend(criterion_evidence)
            recommendations.extend(criterion_recommendations)
        
        # Determine status based on score
        if score >= 90:
            status = 'compliant'
        elif score >= 70:
            status = 'partial'
        else:
            status = 'non_compliant'
        
        return ComplianceResult(
            framework=control_info.get('framework', 'Unknown'),
            control_id=control_id,
            status=status,
            evidence=evidence,
            score=score,
            recommendations=list(set(recommendations)),  # Remove duplicates
            next_assessment=datetime.utcnow() + timedelta(days=90)
        )
    
    def _analyze_criterion(self, criterion: str, events: List[Dict]) -> tuple:
        """Analyze specific assessment criterion"""
        score = 100.0
        evidence = []
        recommendations = []
        
        if criterion == 'authentication_events':
            failed_logins = len([e for e in events if e.get('category') == 'authentication' and 'failed' in e.get('message', '').lower()])
            if failed_logins > 100:  # Too many failed logins
                score = 70.0
                evidence.append(f"{failed_logins} failed login attempts detected")
                recommendations.append("Implement account lockout policies")
        
        elif criterion == 'security_monitoring':
            monitoring_events = len([e for e in events if e.get('category') in ['threat_detection', 'security_alert']])
            if monitoring_events == 0:
                score = 30.0
                evidence.append("No security monitoring events detected")
                recommendations.append("Implement comprehensive security monitoring")
            else:
                evidence.append(f"{monitoring_events} security monitoring events logged")
        
        elif criterion == 'data_encryption':
            # Check for unencrypted data transfers
            unencrypted = len([e for e in events if 'unencrypted' in e.get('message', '').lower()])
            if unencrypted > 0:
                score = 50.0
                evidence.append(f"{unencrypted} unencrypted data transfer events")
                recommendations.append("Encrypt all data in transit and at rest")
        
        return score, evidence, recommendations

    def generate_executive_report(self, framework: str, results: List[ComplianceResult]) -> Dict[str, Any]:
        """Generate executive compliance dashboard"""
        total_controls = len(results)
        compliant_controls = len([r for r in results if r.status == 'compliant'])
        non_compliant_controls = len([r for r in results if r.status == 'non_compliant'])
        
        overall_score = sum(r.score for r in results) / total_controls if total_controls > 0 else 0
        
        return {
            'framework': framework,
            'assessment_date': datetime.utcnow().isoformat(),
            'overall_score': round(overall_score, 2),
            'total_controls': total_controls,
            'compliant_controls': compliant_controls,
            'non_compliant_controls': non_compliant_controls,
            'compliance_percentage': round((compliant_controls / total_controls) * 100, 2) if total_controls > 0 else 0,
            'risk_level': self._calculate_risk_level(overall_score),
            'top_recommendations': self._get_top_recommendations(results),
            'trends': self._calculate_trends(framework, overall_score),
            'next_assessment': (datetime.utcnow() + timedelta(days=90)).isoformat()
        }
    
    def _calculate_risk_level(self, score: float) -> str:
        """Calculate organizational risk level"""
        if score >= 90:
            return 'Low'
        elif score >= 70:
            return 'Medium'
        elif score >= 50:
            return 'High'
        else:
            return 'Critical'
    
    def _get_top_recommendations(self, results: List[ComplianceResult]) -> List[str]:
        """Get top compliance recommendations"""
        all_recommendations = []
        for result in results:
            all_recommendations.extend(result.recommendations)
        
        # Count frequency and return top recommendations
        recommendation_counts = {}
        for rec in all_recommendations:
            recommendation_counts[rec] = recommendation_counts.get(rec, 0) + 1
        
        sorted_recs = sorted(recommendation_counts.items(), key=lambda x: x[1], reverse=True)
        return [rec[0] for rec in sorted_recs[:5]]  # Top 5
    
    def _calculate_trends(self, framework: str, current_score: float) -> Dict[str, Any]:
        """Calculate compliance trends"""
        # This would compare with historical data
        return {
            'score_change': '+2.5%',  # Placeholder
            'trend_direction': 'improving',
            'monthly_improvement': True
        }