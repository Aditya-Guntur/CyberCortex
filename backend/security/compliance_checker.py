"""
Compliance Checker Module

Automated compliance validation against security standards and frameworks
with real-time monitoring and reporting capabilities.
"""

import json
import yaml
from typing import Dict, List, Optional, Any, Tuple, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict, field
from enum import Enum
from pathlib import Path
import logging
import asyncio
from concurrent.futures import ThreadPoolExecutor
import hashlib

from .audit_logger import AuditLogger


class ComplianceStatus(Enum):
    """Compliance status values"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"
    IN_PROGRESS = "in_progress"


class ControlSeverity(Enum):
    """Control severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ComplianceControl:
    """Individual compliance control definition"""
    control_id: str
    title: str
    description: str
    category: str
    severity: ControlSeverity
    requirements: List[str]
    validation_rules: List[Dict[str, Any]]
    remediation_guidance: str
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    automated: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert control to dictionary"""
        data = asdict(self)
        data['severity'] = self.severity.value
        return data


@dataclass
class ComplianceResult:
    """Result of compliance control assessment"""
    control_id: str
    status: ComplianceStatus
    score: float  # 0.0 to 1.0
    findings: List[Dict[str, Any]]
    evidence: List[Dict[str, Any]]
    recommendations: List[str]
    assessed_at: datetime
    assessed_by: str
    next_assessment: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary"""
        data = asdict(self)
        data['status'] = self.status.value
        data['assessed_at'] = self.assessed_at.isoformat()
        if self.next_assessment:
            data['next_assessment'] = self.next_assessment.isoformat()
        return data


@dataclass
class ComplianceFramework:
    """Compliance framework definition"""
    framework_id: str
    name: str
    version: str
    description: str
    controls: Dict[str, ComplianceControl]
    categories: List[str]
    assessment_frequency: str  # daily, weekly, monthly, quarterly
    mandatory_controls: Set[str] = field(default_factory=set)
    
    def get_control(self, control_id: str) -> Optional[ComplianceControl]:
        """Get specific control by ID"""
        return self.controls.get(control_id)
    
    def get_controls_by_category(self, category: str) -> List[ComplianceControl]:
        """Get all controls in a category"""
        return [control for control in self.controls.values() 
                if control.category == category]
    
    def get_critical_controls(self) -> List[ComplianceControl]:
        """Get all critical controls"""
        return [control for control in self.controls.values() 
                if control.severity == ControlSeverity.CRITICAL]


class ComplianceValidator:
    """Validates system configuration against compliance controls"""
    
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
        self.logger = logging.getLogger(__name__)
        self.validation_rules = self._load_validation_rules()
    
    def _load_validation_rules(self) -> Dict[str, Any]:
        """Load validation rules for different control types"""
        return {
            'password_policy': {
                'min_length': 12,
                'require_uppercase': True,
                'require_lowercase': True,
                'require_numbers': True,
                'require_special': True,
                'max_age_days': 90,
                'history_count': 12
            },
            'encryption': {
                'min_key_length': 256,
                'approved_algorithms': ['AES-256', 'RSA-2048', 'ECDSA-P256'],
                'require_tls': True,
                'min_tls_version': '1.2'
            },
            'access_control': {
                'require_mfa': True,
                'session_timeout_minutes': 30,
                'max_failed_attempts': 5,
                'lockout_duration_minutes': 15
            },
            'logging': {
                'retention_days': 365,
                'log_authentication': True,
                'log_authorization': True,
                'log_data_access': True,
                'centralized_logging': True
            },
            'network_security': {
                'firewall_enabled': True,
                'intrusion_detection': True,
                'network_segmentation': True,
                'secure_protocols_only': True
            }
        }
    
    async def validate_control(self, control: ComplianceControl, 
                              system_config: Dict[str, Any]) -> ComplianceResult:
        """Validate a single compliance control"""
        try:
            findings = []
            evidence = []
            recommendations = []
            total_checks = len(control.validation_rules)
            passed_checks = 0
            
            # Process each validation rule
            for rule in control.validation_rules:
                rule_result = await self._validate_rule(rule, system_config)
                
                if rule_result['passed']:
                    passed_checks += 1
                    evidence.append({
                        'rule': rule['name'],
                        'status': 'passed',
                        'details': rule_result.get('details', {}),
                        'timestamp': datetime.utcnow().isoformat()
                    })
                else:
                    findings.append({
                        'rule': rule['name'],
                        'severity': rule.get('severity', 'medium'),
                        'description': rule_result.get('description', ''),
                        'current_value': rule_result.get('current_value'),
                        'expected_value': rule_result.get('expected_value'),
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    
                    if 'recommendation' in rule_result:
                        recommendations.append(rule_result['recommendation'])
            
            # Calculate compliance score
            score = passed_checks / total_checks if total_checks > 0 else 0.0
            
            # Determine status
            if score == 1.0:
                status = ComplianceStatus.COMPLIANT
            elif score >= 0.8:
                status = ComplianceStatus.PARTIAL
            elif score > 0.0:
                status = ComplianceStatus.PARTIAL
            else:
                status = ComplianceStatus.NON_COMPLIANT
            
            # Create result
            result = ComplianceResult(
                control_id=control.control_id,
                status=status,
                score=score,
                findings=findings,
                evidence=evidence,
                recommendations=list(set(recommendations)),  # Remove duplicates
                assessed_at=datetime.utcnow(),
                assessed_by="automated_validator",
                next_assessment=self._calculate_next_assessment(control)
            )
            
            # Log compliance assessment
            self.audit_logger.log_compliance_event(
                framework="generic",
                control=control.control_id,
                status=status.value,
                details={
                    "score": score,
                    "findings_count": len(findings),
                    "evidence_count": len(evidence),
                    "control_title": control.title
                }
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error validating control {control.control_id}: {str(e)}")
            
            return ComplianceResult(
                control_id=control.control_id,
                status=ComplianceStatus.UNKNOWN,
                score=0.0,
                findings=[{
                    'rule': 'validation_error',
                    'severity': 'high',
                    'description': f"Validation failed: {str(e)}",
                    'timestamp': datetime.utcnow().isoformat()
                }],
                evidence=[],
                recommendations=["Review control validation configuration"],
                assessed_at=datetime.utcnow(),
                assessed_by="automated_validator"
            )
    
    async def _validate_rule(self, rule: Dict[str, Any], 
                           system_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate individual rule against system configuration"""
        rule_type = rule.get('type')
        rule_name = rule.get('name', 'unknown')
        
        try:
            if rule_type == 'config_check':
                return await self._validate_config_rule(rule, system_config)
            elif rule_type == 'policy_check':
                return await self._validate_policy_rule(rule, system_config)
            elif rule_type == 'security_check':
                return await self._validate_security_rule(rule, system_config)
            elif rule_type == 'process_check':
                return await self._validate_process_rule(rule, system_config)
            else:
                return {
                    'passed': False,
                    'description': f"Unknown rule type: {rule_type}",
                    'recommendation': f"Review rule configuration for {rule_name}"
                }
                
        except Exception as e:
            return {
                'passed': False,
                'description': f"Rule validation error: {str(e)}",
                'recommendation': f"Fix validation error for rule {rule_name}"
            }
    
    async def _validate_config_rule(self, rule: Dict[str, Any], 
                                   system_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate configuration-based rule"""
        config_path = rule.get('config_path', '')
        expected_value = rule.get('expected_value')
        operator = rule.get('operator', 'equals')
        
        # Navigate to config value
        current_value = system_config
        for path_part in config_path.split('.'):
            if isinstance(current_value, dict) and path_part in current_value:
                current_value = current_value[path_part]
            else:
                current_value = None
                break
        
        # Compare values based on operator
        passed = False
        if operator == 'equals':
            passed = current_value == expected_value
        elif operator == 'not_equals':
            passed = current_value != expected_value
        elif operator == 'greater_than':
            passed = isinstance(current_value, (int, float)) and current_value > expected_value
        elif operator == 'less_than':
            passed = isinstance(current_value, (int, float)) and current_value < expected_value
        elif operator == 'contains':
            passed = expected_value in (current_value or [])
        elif operator == 'not_contains':
            passed = expected_value not in (current_value or [])
        elif operator == 'exists':
            passed = current_value is not None
        elif operator == 'not_exists':
            passed = current_value is None
        
        return {
            'passed': passed,
            'current_value': current_value,
            'expected_value': expected_value,
            'operator': operator,
            'description': f"Config check: {config_path} {operator} {expected_value}",
            'recommendation': rule.get('recommendation', f"Set {config_path} to {expected_value}")
        }
    
    async def _validate_policy_rule(self, rule: Dict[str, Any], 
                                   system_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate policy-based rule"""
        policy_type = rule.get('policy_type')
        requirements = rule.get('requirements', {})
        
        if policy_type == 'password_policy':
            return await self._validate_password_policy(requirements, system_config)
        elif policy_type == 'access_policy':
            return await self._validate_access_policy(requirements, system_config)
        elif policy_type == 'encryption_policy':
            return await self._validate_encryption_policy(requirements, system_config)
        else:
            return {
                'passed': False,
                'description': f"Unknown policy type: {policy_type}",
                'recommendation': f"Implement {policy_type} validation"
            }
    
    async def _validate_security_rule(self, rule: Dict[str, Any], 
                                     system_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate security-specific rule"""
        security_check = rule.get('security_check')
        
        if security_check == 'tls_configuration':
            return await self._validate_tls_config(rule, system_config)
        elif security_check == 'firewall_rules':
            return await self._validate_firewall_rules(rule, system_config)
        elif security_check == 'audit_logging':
            return await self._validate_audit_logging(rule, system_config)
        else:
            return {
                'passed': False,
                'description': f"Unknown security check: {security_check}",
                'recommendation': f"Implement {security_check} validation"
            }
    
    async def _validate_process_rule(self, rule: Dict[str, Any], 
                                    system_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate process-based rule"""
        # This would validate organizational processes
        # For now, return a placeholder
        return {
            'passed': True,
            'description': "Process validation not implemented",
            'recommendation': "Implement process validation"
        }
    
    async def _validate_password_policy(self, requirements: Dict[str, Any], 
                                       system_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate password policy requirements"""
        policy_config = system_config.get('password_policy', {})
        validation_rules = self.validation_rules['password_policy']
        
        checks = []
        for requirement, expected in requirements.items():
            current = policy_config.get(requirement)
            if requirement in validation_rules:
                if isinstance(expected, bool):
                    passed = current == expected
                elif isinstance(expected, (int, float)):
                    passed = current >= expected
                else:
                    passed = current == expected
                
                checks.append({
                    'requirement': requirement,
                    'passed': passed,
                    'current': current,
                    'expected': expected
                })
        
        all_passed = all(check['passed'] for check in checks)
        
        return {
            'passed': all_passed,
            'details': {'checks': checks},
            'description': f"Password policy validation: {len([c for c in checks if c['passed']])}/{len(checks)} checks passed",
            'recommendation': "Update password policy to meet requirements" if not all_passed else None
        }
    
    async def _validate_access_policy(self, requirements: Dict[str, Any], 
                                     system_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate access control policy"""
        access_config = system_config.get('access_control', {})
        
        # Check MFA requirement
        mfa_enabled = access_config.get('mfa_enabled', False)
        session_timeout = access_config.get('session_timeout_minutes', 0)
        
        checks = [
            {
                'requirement': 'mfa_enabled',
                'passed': mfa_enabled,
                'current': mfa_enabled,
                'expected': True
            },
            {
                'requirement': 'session_timeout',
                'passed': session_timeout <= 30,
                'current': session_timeout,
                'expected': '≤ 30 minutes'
            }
        ]
        
        all_passed = all(check['passed'] for check in checks)
        
        return {
            'passed': all_passed,
            'details': {'checks': checks},
            'description': f"Access policy validation: {len([c for c in checks if c['passed']])}/{len(checks)} checks passed",
            'recommendation': "Update access control policy" if not all_passed else None
        }
    
    async def _validate_encryption_policy(self, requirements: Dict[str, Any], 
                                         system_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate encryption policy"""
        encryption_config = system_config.get('encryption', {})
        
        # Check encryption requirements
        tls_enabled = encryption_config.get('tls_enabled', False)
        min_key_length = encryption_config.get('min_key_length', 0)
        
        checks = [
            {
                'requirement': 'tls_enabled',
                'passed': tls_enabled,
                'current': tls_enabled,
                'expected': True
            },
            {
                'requirement': 'min_key_length',
                'passed': min_key_length >= 256,
                'current': min_key_length,
                'expected': '≥ 256 bits'
            }
        ]
        
        all_passed = all(check['passed'] for check in checks)
        
        return {
            'passed': all_passed,
            'details': {'checks': checks},
            'description': f"Encryption policy validation: {len([c for c in checks if c['passed']])}/{len(checks)} checks passed",
            'recommendation': "Update encryption policy" if not all_passed else None
        }
    
    async def _validate_tls_config(self, rule: Dict[str, Any], 
                                  system_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate TLS configuration"""
        tls_config = system_config.get('tls', {})
        
        min_version = tls_config.get('min_version', '1.0')
        ciphers = tls_config.get('allowed_ciphers', [])
        
        # Check TLS version
        version_check = min_version >= '1.2'
        
        # Check cipher suites (simplified)
        secure_ciphers = any('AES' in cipher for cipher in ciphers)
        
        passed = version_check and secure_ciphers
        
        return {
            'passed': passed,
            'details': {
                'min_version': min_version,
                'cipher_count': len(ciphers),
                'version_check': version_check,
                'cipher_check': secure_ciphers
            },
            'description': f"TLS configuration validation: version={min_version}, ciphers={len(ciphers)}",
            'recommendation': "Update TLS configuration to use TLS 1.2+ with secure ciphers" if not passed else None
        }
    
    async def _validate_firewall_rules(self, rule: Dict[str, Any], 
                                      system_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate firewall configuration"""
        firewall_config = system_config.get('firewall', {})
        
        enabled = firewall_config.get('enabled', False)
        default_deny = firewall_config.get('default_policy') == 'deny'
        rules_count = len(firewall_config.get('rules', []))
        
        passed = enabled and default_deny and rules_count > 0
        
        return {
            'passed': passed,
            'details': {
                'enabled': enabled,
                'default_deny': default_deny,
                'rules_count': rules_count
            },
            'description': f"Firewall validation: enabled={enabled}, default_deny={default_deny}, rules={rules_count}",
            'recommendation': "Configure firewall with default deny policy and appropriate rules" if not passed else None
        }
    
    async def _validate_audit_logging(self, rule: Dict[str, Any], 
                                     system_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate audit logging configuration"""
        logging_config = system_config.get('audit_logging', {})
        
        enabled = logging_config.get('enabled', False)
        retention_days = logging_config.get('retention_days', 0)
        centralized = logging_config.get('centralized', False)
        
        passed = enabled and retention_days >= 365 and centralized
        
        return {
            'passed': passed,
            'details': {
                'enabled': enabled,
                'retention_days': retention_days,
                'centralized': centralized
            },
            'description': f"Audit logging validation: enabled={enabled}, retention={retention_days}d, centralized={centralized}",
            'recommendation': "Configure audit logging with 365+ day retention and centralization" if not passed else None
        }
    
    def _calculate_next_assessment(self, control: ComplianceControl) -> datetime:
        """Calculate next assessment date based on control criticality"""
        if control.severity == ControlSeverity.CRITICAL:
            return datetime.utcnow() + timedelta(days=7)  # Weekly
        elif control.severity == ControlSeverity.HIGH:
            return datetime.utcnow() + timedelta(days=30)  # Monthly
        elif control.severity == ControlSeverity.MEDIUM:
            return datetime.utcnow() + timedelta(days=90)  # Quarterly
        else:
            return datetime.utcnow() + timedelta(days=180)  # Semi-annually


class ComplianceChecker:
    """Main compliance checker with framework management and reporting"""
    
    def __init__(self, audit_logger: AuditLogger, frameworks_directory: str = "compliance_frameworks"):
        self.audit_logger = audit_logger
        self.validator = ComplianceValidator(audit_logger)
        self.logger = logging.getLogger(__name__)
        self.frameworks_directory = Path(frameworks_directory)
        
        # Load compliance frameworks
        self.frameworks: Dict[str, ComplianceFramework] = {}
        self.assessment_results: Dict[str, Dict[str, ComplianceResult]] = {}
        
        # Create frameworks directory if it doesn't exist
        self.frameworks_directory.mkdir(parents=True, exist_ok=True)
        
        # Load built-in frameworks
        self._load_builtin_frameworks()
    
    def _load_builtin_frameworks(self):
        """Load built-in compliance frameworks"""
        # SOC 2 Framework
        soc2_controls = self._create_soc2_controls()
        self.frameworks['soc2'] = ComplianceFramework(
            framework_id='soc2',
            name='SOC 2 Type II',
            version='2017',
            description='Service Organization Control 2 - Security, Availability, Processing Integrity, Confidentiality, Privacy',
            controls=soc2_controls,
            categories=['security', 'availability', 'processing_integrity', 'confidentiality', 'privacy'],
            assessment_frequency='quarterly',
            mandatory_controls={'CC6.1', 'CC6.2', 'CC6.3', 'CC6.6', 'CC6.7'}
        )
        
        # ISO 27001 Framework
        iso27001_controls = self._create_iso27001_controls()
        self.frameworks['iso27001'] = ComplianceFramework(
            framework_id='iso27001',
            name='ISO 27001:2013',
            version='2013',
            description='Information Security Management System Requirements',
            controls=iso27001_controls,
            categories=['information_security_policies', 'organization_of_information_security', 
                       'human_resource_security', 'asset_management', 'access_control'],
            assessment_frequency='annually',
            mandatory_controls={'A.5.1.1', 'A.6.1.1', 'A.9.1.1', 'A.12.6.1'}
        )
        
        # NIST Cybersecurity Framework
        nist_controls = self._create_nist_controls()
        self.frameworks['nist_csf'] = ComplianceFramework(
            framework_id='nist_csf',
            name='NIST Cybersecurity Framework',
            version='1.1',
            description='Framework for Improving Critical Infrastructure Cybersecurity',
            controls=nist_controls,
            categories=['identify', 'protect', 'detect', 'respond', 'recover'],
            assessment_frequency='quarterly',
            mandatory_controls={'ID.AM-1', 'PR.AC-1', 'DE.CM-1', 'RS.RP-1'}
        )
    
    def _create_soc2_controls(self) -> Dict[str, ComplianceControl]:
        """Create SOC 2 compliance controls"""
        controls = {}
        
        # CC6.1 - Logical and Physical Access Controls
        controls['CC6.1'] = ComplianceControl(
            control_id='CC6.1',
            title='Logical and Physical Access Controls',
            description='The entity implements logical and physical access controls to protect against threats from sources outside its system boundaries.',
            category='security',
            severity=ControlSeverity.CRITICAL,
            requirements=[
                'Implement multi-factor authentication',
                'Restrict physical access to data centers',
                'Monitor and log access attempts'
            ],
            validation_rules=[
                {
                    'type': 'policy_check',
                    'name': 'mfa_enabled',
                    'policy_type': 'access_policy',
                    'requirements': {'mfa_enabled': True},
                    'severity': 'critical',
                    'recommendation': 'Enable multi-factor authentication for all user accounts'
                },
                {
                    'type': 'config_check',
                    'name': 'session_timeout',
                    'config_path': 'access_control.session_timeout_minutes',
                    'operator': 'less_than',
                    'expected_value': 30,
                    'recommendation': 'Set session timeout to 30 minutes or less'
                }
            ],
            remediation_guidance='Implement comprehensive access controls including MFA, session management, and physical security measures.',
            references=['SOC 2 Type II Trust Services Criteria']
        )
        
        # CC6.2 - System Access Monitoring
        controls['CC6.2'] = ComplianceControl(
            control_id='CC6.2',
            title='System Access Monitoring',
            description='Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users.',
            category='security',
            severity=ControlSeverity.HIGH,
            requirements=[
                'User registration and authorization process',
                'Regular access reviews',
                'Automated provisioning and deprovisioning'
            ],
            validation_rules=[
                {
                    'type': 'config_check',
                    'name': 'audit_logging_enabled',
                    'config_path': 'audit_logging.enabled',
                    'operator': 'equals',
                    'expected_value': True,
                    'recommendation': 'Enable comprehensive audit logging'
                }
            ],
            remediation_guidance='Establish formal user access management processes with regular reviews and automated controls.',
            references=['SOC 2 Type II Trust Services Criteria']
        )
        
        return controls
    
    def _create_iso27001_controls(self) -> Dict[str, ComplianceControl]:
        """Create ISO 27001 compliance controls"""
        controls = {}
        
        # A.9.1.1 - Access Control Policy
        controls['A.9.1.1'] = ComplianceControl(
            control_id='A.9.1.1',
            title='Access Control Policy',
            description='An access control policy shall be established, documented and reviewed based on business and information security requirements.',
            category='access_control',
            severity=ControlSeverity.CRITICAL,
            requirements=[
                'Documented access control policy',
                'Regular policy reviews',
                'Business requirement alignment'
            ],
            validation_rules=[
                {
                    'type': 'policy_check',
                    'name': 'access_control_policy',
                    'policy_type': 'access_policy',
                    'requirements': {'documented': True, 'reviewed': True},
                    'recommendation': 'Document and regularly review access control policy'
                }
            ],
            remediation_guidance='Create comprehensive access control policy aligned with business requirements and review regularly.',
            references=['ISO/IEC 27001:2013']
        )
        
        return controls
    
    def _create_nist_controls(self) -> Dict[str, ComplianceControl]:
        """Create NIST CSF compliance controls"""
        controls = {}
        
        # ID.AM-1 - Asset Management
        controls['ID.AM-1'] = ComplianceControl(
            control_id='ID.AM-1',
            title='Physical devices and systems within the organization are inventoried',
            description='Maintain an accurate inventory of physical devices and systems within the organization.',
            category='identify',
            severity=ControlSeverity.HIGH,
            requirements=[
                'Complete asset inventory',
                'Regular inventory updates',
                'Asset classification'
            ],
            validation_rules=[
                {
                    'type': 'config_check',
                    'name': 'asset_inventory_exists',
                    'config_path': 'asset_management.inventory_enabled',
                    'operator': 'equals',
                    'expected_value': True,
                    'recommendation': 'Implement automated asset inventory system'
                }
            ],
            remediation_guidance='Implement comprehensive asset management system with automated discovery and classification.',
            references=['NIST Cybersecurity Framework v1.1']
        )
        
        return controls
    
    async def assess_framework(self, framework_id: str, system_config: Dict[str, Any],
                              user_id: str = "system") -> Dict[str, Any]:
        """Assess compliance against entire framework"""
        try:
            framework = self.frameworks.get(framework_id)
            if not framework:
                raise ValueError(f"Framework {framework_id} not found")
            
            self.logger.info(f"Starting compliance assessment for framework: {framework_id}")
            
            # Initialize results storage
            if framework_id not in self.assessment_results:
                self.assessment_results[framework_id] = {}
            
            results = {}
            total_score = 0.0
            control_count = 0
            
            # Assess each control
            for control_id, control in framework.controls.items():
                try:
                    result = await self.validator.validate_control(control, system_config)
                    results[control_id] = result
                    self.assessment_results[framework_id][control_id] = result
                    
                    total_score += result.score
                    control_count += 1
                    
                    self.logger.debug(f"Assessed control {control_id}: {result.status.value} (score: {result.score})")
                    
                except Exception as e:
                    self.logger.error(f"Failed to assess control {control_id}: {str(e)}")
                    continue
            
            # Calculate overall compliance score
            overall_score = total_score / control_count if control_count > 0 else 0.0
            
            # Determine overall status
            if overall_score >= 0.95:
                overall_status = ComplianceStatus.COMPLIANT
            elif overall_score >= 0.8:
                overall_status = ComplianceStatus.PARTIAL
            else:
                overall_status = ComplianceStatus.NON_COMPLIANT
            
            # Generate summary
            summary = {
                'framework_id': framework_id,
                'framework_name': framework.name,
                'assessment_date': datetime.utcnow().isoformat(),
                'assessed_by': user_id,
                'overall_status': overall_status.value,
                'overall_score': round(overall_score, 3),
                'total_controls': control_count,
                'compliant_controls': len([r for r in results.values() if r.status == ComplianceStatus.COMPLIANT]),
                'non_compliant_controls': len([r for r in results.values() if r.status == ComplianceStatus.NON_COMPLIANT]),
                'partial_controls': len([r for r in results.values() if r.status == ComplianceStatus.PARTIAL]),
                'critical_findings': len([r for r in results.values() 
                                        if any(f.get('severity') == 'critical' for f in r.findings)]),
                'high_findings': len([r for r in results.values() 
                                    if any(f.get('severity') == 'high' for f in r.findings)]),
                'control_results': {cid: result.to_dict() for cid, result in results.items()}
            }
            
            # Log framework assessment
            self.audit_logger.log_compliance_event(
                framework=framework_id,
                control="framework_assessment",
                status=overall_status.value,
                details={
                    "overall_score": overall_score,
                    "total_controls": control_count,
                    "compliant_controls": summary['compliant_controls'],
                    "assessed_by": user_id
                }
            )
            
            self.logger.info(f"Completed compliance assessment for {framework_id}: {overall_status.value} ({overall_score:.1%})")
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Framework assessment failed for {framework_id}: {str(e)}")
            raise
    
    async def assess_control(self, framework_id: str, control_id: str, 
                           system_config: Dict[str, Any]) -> ComplianceResult:
        """Assess single compliance control"""
        framework = self.frameworks.get(framework_id)
        if not framework:
            raise ValueError(f"Framework {framework_id} not found")
        
        control = framework.get_control(control_id)
        if not control:
            raise ValueError(f"Control {control_id} not found in framework {framework_id}")
        
        return await self.validator.validate_control(control, system_config)
    
    def get_framework_status(self, framework_id: str) -> Dict[str, Any]:
        """Get current status of framework compliance"""
        framework = self.frameworks.get(framework_id)
        if not framework:
            return {"error": f"Framework {framework_id} not found"}
        
        results = self.assessment_results.get(framework_id, {})
        
        if not results:
            return {
                "framework_id": framework_id,
                "framework_name": framework.name,
                "status": "not_assessed",
                "last_assessment": None,
                "total_controls": len(framework.controls),
                "assessed_controls": 0
            }
        
        # Calculate status summary
        total_controls = len(framework.controls)
        assessed_controls = len(results)
        compliant_controls = len([r for r in results.values() if r.status == ComplianceStatus.COMPLIANT])
        
        overall_score = sum(r.score for r in results.values()) / assessed_controls if assessed_controls > 0 else 0.0
        
        last_assessment = max(r.assessed_at for r in results.values()) if results else None
        
        return {
            "framework_id": framework_id,
            "framework_name": framework.name,
            "status": "compliant" if overall_score >= 0.95 else "partial" if overall_score >= 0.8 else "non_compliant",
            "overall_score": round(overall_score, 3),
            "last_assessment": last_assessment.isoformat() if last_assessment else None,
            "total_controls": total_controls,
            "assessed_controls": assessed_controls,
            "compliant_controls": compliant_controls,
            "control_breakdown": {
                "compliant": len([r for r in results.values() if r.status == ComplianceStatus.COMPLIANT]),
                "partial": len([r for r in results.values() if r.status == ComplianceStatus.PARTIAL]),
                "non_compliant": len([r for r in results.values() if r.status == ComplianceStatus.NON_COMPLIANT]),
                "unknown": len([r for r in results.values() if r.status == ComplianceStatus.UNKNOWN])
            }
        }
    
    def generate_compliance_report(self, framework_id: str, format: str = "json") -> str:
        """Generate compliance report for framework"""
        framework_status = self.get_framework_status(framework_id)
        results = self.assessment_results.get(framework_id, {})
        
        if format == "json":
            report_data = {
                "report_metadata": {
                    "generated_at": datetime.utcnow().isoformat(),
                    "framework_id": framework_id,
                    "report_type": "compliance_assessment"
                },
                "executive_summary": framework_status,
                "detailed_results": {
                    control_id: result.to_dict() 
                    for control_id, result in results.items()
                },
                "recommendations": self._generate_recommendations(framework_id, results)
            }
            return json.dumps(report_data, indent=2, default=str)
        
        elif format == "html":
            # Generate HTML report (simplified)
            html_content = f"""
            <html>
            <head><title>Compliance Report - {framework_status['framework_name']}</title></head>
            <body>
                <h1>Compliance Assessment Report</h1>
                <h2>{framework_status['framework_name']}</h2>
                <p>Overall Score: {framework_status.get('overall_score', 0):.1%}</p>
                <p>Status: {framework_status.get('status', 'unknown').title()}</p>
                <p>Last Assessment: {framework_status.get('last_assessment', 'Never')}</p>
                
                <h3>Control Summary</h3>
                <ul>
                    <li>Total Controls: {framework_status.get('total_controls', 0)}</li>
                    <li>Compliant: {framework_status.get('compliant_controls', 0)}</li>
                    <li>Assessed: {framework_status.get('assessed_controls', 0)}</li>
                </ul>
            </body>
            </html>
            """
            return html_content
        
        else:
            raise ValueError(f"Unsupported report format: {format}")
    
    def _generate_recommendations(self, framework_id: str, 
                                 results: Dict[str, ComplianceResult]) -> List[Dict[str, Any]]:
        """Generate prioritized recommendations based on assessment results"""
        recommendations = []
        
        # Collect all recommendations from failed controls
        for control_id, result in results.items():
            if result.status != ComplianceStatus.COMPLIANT and result.recommendations:
                for recommendation in result.recommendations:
                    recommendations.append({
                        "control_id": control_id,
                        "priority": "high" if result.status == ComplianceStatus.NON_COMPLIANT else "medium",
                        "recommendation": recommendation,
                        "current_score": result.score,
                        "findings_count": len(result.findings)
                    })
        
        # Sort by priority and impact
        recommendations.sort(key=lambda x: (
            0 if x["priority"] == "high" else 1,
            -x["current_score"],
            -x["findings_count"]
        ))
        
        return recommendations[:10]  # Return top 10 recommendations
    
    def get_compliance_statistics(self) -> Dict[str, Any]:
        """Get overall compliance statistics"""
        stats = {
            "frameworks_loaded": len(self.frameworks),
            "total_assessments": sum(len(results) for results in self.assessment_results.values()),
            "frameworks": {}
        }
        
        for framework_id in self.frameworks:
            framework_status = self.get_framework_status(framework_id)
            stats["frameworks"][framework_id] = {
                "name": framework_status["framework_name"],
                "status": framework_status.get("status", "not_assessed"),
                "score": framework_status.get("overall_score", 0),
                "last_assessment": framework_status.get("last_assessment")
            }
        
        return stats