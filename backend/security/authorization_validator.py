"""
Authorization Validator Module

Implements comprehensive target validation, scope limiting, and authorization controls
for ethical security testing with enterprise-grade audit logging.
"""

import ipaddress
import re
import json
import hashlib
from typing import List, Dict, Optional, Set, Tuple, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import logging
from urllib.parse import urlparse

from .audit_logger import AuditLogger


class AuthorizationLevel(Enum):
    """Authorization levels for security operations"""
    READ_ONLY = "read_only"
    LIMITED_SCAN = "limited_scan"
    FULL_ASSESSMENT = "full_assessment"
    PENETRATION_TEST = "penetration_test"
    EMERGENCY_RESPONSE = "emergency_response"


class ScopeType(Enum):
    """Types of assessment scopes"""
    NETWORK = "network"
    WEB_APPLICATION = "web_application"
    API = "api"
    CLOUD_INFRASTRUCTURE = "cloud_infrastructure"
    MOBILE_APPLICATION = "mobile_application"


@dataclass
class AuthorizationScope:
    """Defines the scope and boundaries of authorized security testing"""
    scope_id: str
    scope_type: ScopeType
    targets: List[str]
    excluded_targets: List[str]
    allowed_ports: List[int]
    blocked_ports: List[int]
    max_scan_rate: int  # requests per second
    max_concurrent_scans: int
    time_restrictions: Dict[str, Any]
    authorization_level: AuthorizationLevel
    authorized_by: str
    authorized_at: datetime
    expires_at: datetime
    compliance_requirements: List[str]
    emergency_contacts: List[str]
    
    def is_expired(self) -> bool:
        """Check if authorization has expired"""
        return datetime.utcnow() > self.expires_at
    
    def is_target_authorized(self, target: str) -> bool:
        """Check if a specific target is authorized for testing"""
        # Check if target is explicitly excluded
        for excluded in self.excluded_targets:
            if self._matches_pattern(target, excluded):
                return False
        
        # Check if target is in authorized list
        for authorized in self.targets:
            if self._matches_pattern(target, authorized):
                return True
        
        return False
    
    def _matches_pattern(self, target: str, pattern: str) -> bool:
        """Check if target matches authorization pattern"""
        try:
            # Handle IP ranges
            if '/' in pattern:
                return ipaddress.ip_address(target) in ipaddress.ip_network(pattern, strict=False)
            
            # Handle domain patterns
            if pattern.startswith('*.'):
                domain_pattern = pattern[2:]
                return target.endswith(domain_pattern)
            
            # Exact match
            return target == pattern
            
        except (ipaddress.AddressValueError, ValueError):
            # Fallback to string matching for non-IP targets
            return target == pattern or target.endswith(f".{pattern}")


class TargetValidator:
    """Validates targets against authorization whitelist and security policies"""
    
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
        self.logger = logging.getLogger(__name__)
        self._load_security_policies()
    
    def _load_security_policies(self):
        """Load security policies and restrictions"""
        self.forbidden_networks = [
            ipaddress.ip_network('127.0.0.0/8'),    # Loopback
            ipaddress.ip_network('169.254.0.0/16'), # Link-local
            ipaddress.ip_network('224.0.0.0/4'),    # Multicast
            ipaddress.ip_network('240.0.0.0/4'),    # Reserved
        ]
        
        self.forbidden_domains = [
            'localhost',
            '*.gov',
            '*.mil',
            '*.edu',
            'banking.*',
            'financial.*'
        ]
        
        self.forbidden_ports = [
            22,    # SSH
            23,    # Telnet
            135,   # RPC
            139,   # NetBIOS
            445,   # SMB
            1433,  # SQL Server
            3389,  # RDP
        ]
    
    def validate_target(self, target: str, scope: AuthorizationScope, 
                       scan_type: str = "basic") -> Tuple[bool, str]:
        """
        Validate if target is authorized for security testing
        
        Args:
            target: Target to validate (IP, domain, URL)
            scope: Authorization scope
            scan_type: Type of scan being performed
            
        Returns:
            Tuple of (is_valid, reason)
        """
        try:
            # Log validation attempt
            self.audit_logger.log_security_event(
                event_type="target_validation",
                severity="info",
                details={
                    "target": target,
                    "scope_id": scope.scope_id,
                    "scan_type": scan_type,
                    "timestamp": datetime.utcnow().isoformat()
                }
            )
            
            # Check if scope is expired
            if scope.is_expired():
                reason = f"Authorization scope {scope.scope_id} has expired"
                self._log_validation_failure(target, reason, scope)
                return False, reason
            
            # Parse and normalize target
            normalized_target = self._normalize_target(target)
            if not normalized_target:
                reason = f"Invalid target format: {target}"
                self._log_validation_failure(target, reason, scope)
                return False, reason
            
            # Check against forbidden networks/domains
            if self._is_forbidden_target(normalized_target):
                reason = f"Target {target} is in forbidden network/domain list"
                self._log_validation_failure(target, reason, scope)
                return False, reason
            
            # Check authorization scope
            if not scope.is_target_authorized(normalized_target):
                reason = f"Target {target} not in authorized scope"
                self._log_validation_failure(target, reason, scope)
                return False, reason
            
            # Check time restrictions
            if not self._check_time_restrictions(scope):
                reason = "Current time outside authorized testing window"
                self._log_validation_failure(target, reason, scope)
                return False, reason
            
            # Validate scan type authorization
            if not self._is_scan_type_authorized(scan_type, scope.authorization_level):
                reason = f"Scan type {scan_type} not authorized for level {scope.authorization_level.value}"
                self._log_validation_failure(target, reason, scope)
                return False, reason
            
            # Log successful validation
            self.audit_logger.log_security_event(
                event_type="target_validation_success",
                severity="info",
                details={
                    "target": target,
                    "normalized_target": normalized_target,
                    "scope_id": scope.scope_id,
                    "scan_type": scan_type,
                    "authorization_level": scope.authorization_level.value
                }
            )
            
            return True, "Target validation successful"
            
        except Exception as e:
            reason = f"Validation error: {str(e)}"
            self.logger.error(f"Target validation failed: {reason}")
            self._log_validation_failure(target, reason, scope)
            return False, reason
    
    def _normalize_target(self, target: str) -> Optional[str]:
        """Normalize target to standard format"""
        try:
            # Handle URLs
            if target.startswith(('http://', 'https://')):
                parsed = urlparse(target)
                return parsed.hostname
            
            # Handle IP addresses
            try:
                ip = ipaddress.ip_address(target)
                return str(ip)
            except ipaddress.AddressValueError:
                pass
            
            # Handle domain names
            if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
                return target.lower()
            
            return None
            
        except Exception:
            return None
    
    def _is_forbidden_target(self, target: str) -> bool:
        """Check if target is in forbidden list"""
        try:
            # Check IP networks
            ip = ipaddress.ip_address(target)
            for network in self.forbidden_networks:
                if ip in network:
                    return True
        except ipaddress.AddressValueError:
            # Check domain patterns
            for pattern in self.forbidden_domains:
                if pattern.startswith('*.'):
                    if target.endswith(pattern[2:]):
                        return True
                elif pattern.endswith('.*'):
                    if target.startswith(pattern[:-2]):
                        return True
                elif target == pattern:
                    return True
        
        return False
    
    def _check_time_restrictions(self, scope: AuthorizationScope) -> bool:
        """Check if current time is within authorized testing window"""
        if not scope.time_restrictions:
            return True
        
        now = datetime.utcnow()
        current_hour = now.hour
        current_day = now.strftime('%A').lower()
        
        # Check day restrictions
        if 'allowed_days' in scope.time_restrictions:
            if current_day not in scope.time_restrictions['allowed_days']:
                return False
        
        # Check hour restrictions
        if 'allowed_hours' in scope.time_restrictions:
            start_hour = scope.time_restrictions['allowed_hours'].get('start', 0)
            end_hour = scope.time_restrictions['allowed_hours'].get('end', 23)
            
            if not (start_hour <= current_hour <= end_hour):
                return False
        
        return True
    
    def _is_scan_type_authorized(self, scan_type: str, auth_level: AuthorizationLevel) -> bool:
        """Check if scan type is authorized for the given authorization level"""
        scan_permissions = {
            AuthorizationLevel.READ_ONLY: ['discovery', 'enumeration'],
            AuthorizationLevel.LIMITED_SCAN: ['discovery', 'enumeration', 'vulnerability_scan'],
            AuthorizationLevel.FULL_ASSESSMENT: ['discovery', 'enumeration', 'vulnerability_scan', 'compliance_check'],
            AuthorizationLevel.PENETRATION_TEST: ['discovery', 'enumeration', 'vulnerability_scan', 'compliance_check', 'exploitation'],
            AuthorizationLevel.EMERGENCY_RESPONSE: ['*']  # All scan types allowed
        }
        
        allowed_scans = scan_permissions.get(auth_level, [])
        return '*' in allowed_scans or scan_type in allowed_scans
    
    def _log_validation_failure(self, target: str, reason: str, scope: AuthorizationScope):
        """Log validation failure for security monitoring"""
        self.audit_logger.log_security_event(
            event_type="target_validation_failure",
            severity="warning",
            details={
                "target": target,
                "reason": reason,
                "scope_id": scope.scope_id,
                "authorization_level": scope.authorization_level.value,
                "timestamp": datetime.utcnow().isoformat()
            }
        )


class AuthorizationValidator:
    """Main authorization validator with comprehensive security controls"""
    
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
        self.target_validator = TargetValidator(audit_logger)
        self.logger = logging.getLogger(__name__)
        self.active_scopes: Dict[str, AuthorizationScope] = {}
        self.scope_usage: Dict[str, Dict[str, Any]] = {}
    
    def create_authorization_scope(self, scope_data: Dict[str, Any], 
                                 authorized_by: str) -> AuthorizationScope:
        """Create new authorization scope with validation"""
        try:
            scope = AuthorizationScope(
                scope_id=self._generate_scope_id(),
                scope_type=ScopeType(scope_data['scope_type']),
                targets=scope_data['targets'],
                excluded_targets=scope_data.get('excluded_targets', []),
                allowed_ports=scope_data.get('allowed_ports', []),
                blocked_ports=scope_data.get('blocked_ports', []),
                max_scan_rate=scope_data.get('max_scan_rate', 10),
                max_concurrent_scans=scope_data.get('max_concurrent_scans', 5),
                time_restrictions=scope_data.get('time_restrictions', {}),
                authorization_level=AuthorizationLevel(scope_data['authorization_level']),
                authorized_by=authorized_by,
                authorized_at=datetime.utcnow(),
                expires_at=datetime.fromisoformat(scope_data['expires_at']),
                compliance_requirements=scope_data.get('compliance_requirements', []),
                emergency_contacts=scope_data.get('emergency_contacts', [])
            )
            
            # Store active scope
            self.active_scopes[scope.scope_id] = scope
            self.scope_usage[scope.scope_id] = {
                'created_at': datetime.utcnow(),
                'scan_count': 0,
                'last_used': None,
                'violations': []
            }
            
            # Log scope creation
            self.audit_logger.log_security_event(
                event_type="authorization_scope_created",
                severity="info",
                details={
                    "scope_id": scope.scope_id,
                    "authorized_by": authorized_by,
                    "authorization_level": scope.authorization_level.value,
                    "target_count": len(scope.targets),
                    "expires_at": scope.expires_at.isoformat()
                }
            )
            
            return scope
            
        except Exception as e:
            self.logger.error(f"Failed to create authorization scope: {str(e)}")
            raise ValueError(f"Invalid scope configuration: {str(e)}")
    
    def validate_operation(self, scope_id: str, target: str, operation: str,
                          user_id: str, additional_params: Dict[str, Any] = None) -> Tuple[bool, str]:
        """Validate security operation against authorization scope"""
        try:
            # Get scope
            scope = self.active_scopes.get(scope_id)
            if not scope:
                reason = f"Authorization scope {scope_id} not found"
                self._log_operation_failure(scope_id, target, operation, user_id, reason)
                return False, reason
            
            # Validate target
            is_valid, validation_reason = self.target_validator.validate_target(
                target, scope, operation
            )
            
            if not is_valid:
                self._log_operation_failure(scope_id, target, operation, user_id, validation_reason)
                return False, validation_reason
            
            # Check rate limits
            if not self._check_rate_limits(scope_id, scope):
                reason = "Rate limit exceeded for scope"
                self._log_operation_failure(scope_id, target, operation, user_id, reason)
                return False, reason
            
            # Check concurrent scan limits
            if not self._check_concurrent_limits(scope_id, scope):
                reason = "Concurrent scan limit exceeded"
                self._log_operation_failure(scope_id, target, operation, user_id, reason)
                return False, reason
            
            # Update usage tracking
            self._update_scope_usage(scope_id)
            
            # Log successful operation
            self.audit_logger.log_security_event(
                event_type="operation_authorized",
                severity="info",
                details={
                    "scope_id": scope_id,
                    "target": target,
                    "operation": operation,
                    "user_id": user_id,
                    "additional_params": additional_params or {}
                }
            )
            
            return True, "Operation authorized"
            
        except Exception as e:
            reason = f"Authorization validation error: {str(e)}"
            self.logger.error(reason)
            self._log_operation_failure(scope_id, target, operation, user_id, reason)
            return False, reason
    
    def revoke_scope(self, scope_id: str, revoked_by: str, reason: str):
        """Revoke authorization scope"""
        if scope_id in self.active_scopes:
            scope = self.active_scopes[scope_id]
            
            # Log revocation
            self.audit_logger.log_security_event(
                event_type="authorization_scope_revoked",
                severity="warning",
                details={
                    "scope_id": scope_id,
                    "revoked_by": revoked_by,
                    "reason": reason,
                    "original_authorized_by": scope.authorized_by,
                    "usage_stats": self.scope_usage.get(scope_id, {})
                }
            )
            
            # Remove from active scopes
            del self.active_scopes[scope_id]
            
            self.logger.info(f"Authorization scope {scope_id} revoked by {revoked_by}: {reason}")
    
    def get_scope_status(self, scope_id: str) -> Dict[str, Any]:
        """Get detailed status of authorization scope"""
        scope = self.active_scopes.get(scope_id)
        if not scope:
            return {"error": "Scope not found"}
        
        usage = self.scope_usage.get(scope_id, {})
        
        return {
            "scope_id": scope_id,
            "status": "expired" if scope.is_expired() else "active",
            "authorization_level": scope.authorization_level.value,
            "target_count": len(scope.targets),
            "expires_at": scope.expires_at.isoformat(),
            "usage_stats": usage,
            "compliance_requirements": scope.compliance_requirements
        }
    
    def _generate_scope_id(self) -> str:
        """Generate unique scope identifier"""
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        random_hash = hashlib.md5(f"{timestamp}{len(self.active_scopes)}".encode()).hexdigest()[:8]
        return f"scope_{timestamp}_{random_hash}"
    
    def _check_rate_limits(self, scope_id: str, scope: AuthorizationScope) -> bool:
        """Check if operation is within rate limits"""
        # Implementation would check actual rate limiting
        # For now, return True as placeholder
        return True
    
    def _check_concurrent_limits(self, scope_id: str, scope: AuthorizationScope) -> bool:
        """Check if operation is within concurrent scan limits"""
        # Implementation would check actual concurrent operations
        # For now, return True as placeholder
        return True
    
    def _update_scope_usage(self, scope_id: str):
        """Update scope usage statistics"""
        if scope_id in self.scope_usage:
            self.scope_usage[scope_id]['scan_count'] += 1
            self.scope_usage[scope_id]['last_used'] = datetime.utcnow()
    
    def _log_operation_failure(self, scope_id: str, target: str, operation: str,
                              user_id: str, reason: str):
        """Log operation failure for security monitoring"""
        self.audit_logger.log_security_event(
            event_type="operation_denied",
            severity="warning",
            details={
                "scope_id": scope_id,
                "target": target,
                "operation": operation,
                "user_id": user_id,
                "reason": reason,
                "timestamp": datetime.utcnow().isoformat()
            }
        )