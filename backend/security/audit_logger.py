"""
Audit Logger Module

Comprehensive security event logging with structured data, timestamps,
and compliance-ready audit trails for the CyberCortex platform.
"""

import json
import logging
import hashlib
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field
from enum import Enum
import os
import gzip
import threading
from pathlib import Path
from queue import Queue, Empty
import time


class EventSeverity(Enum):
    """Security event severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EventCategory(Enum):
    """Security event categories"""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_ACCESS = "data_access"
    SYSTEM_SECURITY = "system_security"
    NETWORK_SECURITY = "network_security"
    COMPLIANCE = "compliance"
    INCIDENT = "incident"
    AUDIT = "audit"


@dataclass
class SecurityEvent:
    """Structured security event data"""
    event_id: str
    timestamp: datetime
    event_type: str
    severity: EventSeverity
    category: EventCategory
    source: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None
    result: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    correlation_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['severity'] = self.severity.value
        data['category'] = self.category.value
        return data
    
    def to_json(self) -> str:
        """Convert event to JSON string"""
        return json.dumps(self.to_dict(), default=str, separators=(',', ':'))


class AuditLogger:
    """Comprehensive audit logging system with structured events"""
    
    def __init__(self, log_directory: str = "/var/log/cybercortex", 
                 max_file_size: int = 100 * 1024 * 1024,  # 100MB
                 max_files: int = 30,
                 compress_old_files: bool = True):
        
        self.log_directory = Path(log_directory)
        self.max_file_size = max_file_size
        self.max_files = max_files
        self.compress_old_files = compress_old_files
        
        # Create log directory if it doesn't exist
        self.log_directory.mkdir(parents=True, exist_ok=True)
        
        # Initialize logging
        self.logger = logging.getLogger('cybercortex.audit')
        self._setup_logging()
        
        # Event queue for async processing
        self.event_queue = Queue(maxsize=10000)
        self.processing_thread = None
        self.shutdown_event = threading.Event()
        
        # Event counters for monitoring
        self.event_counters = {
            'total': 0,
            'by_severity': {severity.value: 0 for severity in EventSeverity},
            'by_category': {category.value: 0 for category in EventCategory},
            'errors': 0
        }
        
        # Start background processing
        self._start_background_processing()
    
    def _setup_logging(self):
        """Setup structured logging configuration"""
        # Create formatter for structured logs
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(name)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S UTC'
        )
        
        # File handler with rotation
        log_file = self.log_directory / "security_audit.log"
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=self.max_file_size,
            backupCount=self.max_files
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.INFO)
        
        # Console handler for development
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(logging.WARNING)
        
        # Configure logger
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        # Prevent duplicate logs
        self.logger.propagate = False
    
    def log_security_event(self, event_type: str, severity: str, 
                          details: Dict[str, Any], **kwargs) -> str:
        """
        Log a security event with structured data
        
        Args:
            event_type: Type of security event
            severity: Event severity level
            details: Event details and context
            **kwargs: Additional event fields
            
        Returns:
            Event ID for correlation
        """
        try:
            # Generate unique event ID
            event_id = self._generate_event_id(event_type, details)
            
            # Create security event
            event = SecurityEvent(
                event_id=event_id,
                timestamp=datetime.now(timezone.utc),
                event_type=event_type,
                severity=EventSeverity(severity.lower()),
                category=self._determine_category(event_type),
                source=kwargs.get('source', 'cybercortex'),
                user_id=kwargs.get('user_id'),
                session_id=kwargs.get('session_id'),
                ip_address=kwargs.get('ip_address'),
                user_agent=kwargs.get('user_agent'),
                resource=kwargs.get('resource'),
                action=kwargs.get('action'),
                result=kwargs.get('result'),
                details=details,
                tags=kwargs.get('tags', []),
                correlation_id=kwargs.get('correlation_id')
            )
            
            # Queue event for processing
            try:
                self.event_queue.put_nowait(event)
            except:
                # If queue is full, process synchronously
                self._process_event(event)
            
            # Update counters
            self.event_counters['total'] += 1
            self.event_counters['by_severity'][event.severity.value] += 1
            self.event_counters['by_category'][event.category.value] += 1
            
            return event_id
            
        except Exception as e:
            self.event_counters['errors'] += 1
            self.logger.error(f"Failed to log security event: {str(e)}")
            return ""
    
    def log_authentication_event(self, user_id: str, action: str, result: str,
                                ip_address: str, details: Dict[str, Any] = None):
        """Log authentication-related events"""
        severity = "warning" if result == "failed" else "info"
        
        event_details = {
            "action": action,
            "result": result,
            "ip_address": ip_address,
            **(details or {})
        }
        
        return self.log_security_event(
            event_type="authentication",
            severity=severity,
            details=event_details,
            user_id=user_id,
            ip_address=ip_address,
            action=action,
            result=result
        )
    
    def log_authorization_event(self, user_id: str, resource: str, action: str,
                               result: str, details: Dict[str, Any] = None):
        """Log authorization-related events"""
        severity = "warning" if result == "denied" else "info"
        
        event_details = {
            "resource": resource,
            "action": action,
            "result": result,
            **(details or {})
        }
        
        return self.log_security_event(
            event_type="authorization",
            severity=severity,
            details=event_details,
            user_id=user_id,
            resource=resource,
            action=action,
            result=result
        )
    
    def log_data_access_event(self, user_id: str, resource: str, action: str,
                             details: Dict[str, Any] = None):
        """Log data access events"""
        event_details = {
            "resource": resource,
            "action": action,
            **(details or {})
        }
        
        return self.log_security_event(
            event_type="data_access",
            severity="info",
            details=event_details,
            user_id=user_id,
            resource=resource,
            action=action
        )
    
    def log_security_scan_event(self, scan_id: str, target: str, scan_type: str,
                               status: str, findings: int, details: Dict[str, Any] = None):
        """Log security scan events"""
        severity = "high" if findings > 10 else "medium" if findings > 0 else "info"
        
        event_details = {
            "scan_id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "status": status,
            "findings_count": findings,
            **(details or {})
        }
        
        return self.log_security_event(
            event_type="security_scan",
            severity=severity,
            details=event_details,
            resource=target,
            action=scan_type
        )
    
    def log_compliance_event(self, framework: str, control: str, status: str,
                            details: Dict[str, Any] = None):
        """Log compliance-related events"""
        severity = "high" if status == "failed" else "info"
        
        event_details = {
            "framework": framework,
            "control": control,
            "status": status,
            **(details or {})
        }
        
        return self.log_security_event(
            event_type="compliance_check",
            severity=severity,
            details=event_details,
            resource=f"{framework}:{control}",
            action="compliance_check",
            result=status
        )
    
    def log_incident_event(self, incident_id: str, incident_type: str, severity: str,
                          details: Dict[str, Any] = None):
        """Log security incident events"""
        event_details = {
            "incident_id": incident_id,
            "incident_type": incident_type,
            **(details or {})
        }
        
        return self.log_security_event(
            event_type="security_incident",
            severity=severity,
            details=event_details,
            correlation_id=incident_id
        )
    
    def get_event_statistics(self) -> Dict[str, Any]:
        """Get audit logging statistics"""
        return {
            "total_events": self.event_counters['total'],
            "events_by_severity": self.event_counters['by_severity'].copy(),
            "events_by_category": self.event_counters['by_category'].copy(),
            "processing_errors": self.event_counters['errors'],
            "queue_size": self.event_queue.qsize(),
            "log_directory": str(self.log_directory),
            "uptime": time.time() - getattr(self, '_start_time', time.time())
        }
    
    def search_events(self, filters: Dict[str, Any], limit: int = 100) -> List[Dict[str, Any]]:
        """Search audit events (simplified implementation)"""
        # This would typically query a database or search index
        # For now, return empty list as placeholder
        return []
    
    def export_events(self, start_date: datetime, end_date: datetime,
                     format: str = "json") -> str:
        """Export events for compliance reporting"""
        # This would typically generate compliance reports
        # For now, return placeholder
        return f"Export from {start_date} to {end_date} in {format} format"
    
    def _generate_event_id(self, event_type: str, details: Dict[str, Any]) -> str:
        """Generate unique event identifier"""
        timestamp = datetime.now(timezone.utc).isoformat()
        content = f"{event_type}:{timestamp}:{json.dumps(details, sort_keys=True)}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _determine_category(self, event_type: str) -> EventCategory:
        """Determine event category based on event type"""
        category_mapping = {
            'authentication': EventCategory.AUTHENTICATION,
            'authorization': EventCategory.AUTHORIZATION,
            'login': EventCategory.AUTHENTICATION,
            'logout': EventCategory.AUTHENTICATION,
            'session': EventCategory.AUTHENTICATION,
            'data_access': EventCategory.DATA_ACCESS,
            'file_access': EventCategory.DATA_ACCESS,
            'database_access': EventCategory.DATA_ACCESS,
            'security_scan': EventCategory.NETWORK_SECURITY,
            'vulnerability_scan': EventCategory.NETWORK_SECURITY,
            'network_scan': EventCategory.NETWORK_SECURITY,
            'compliance_check': EventCategory.COMPLIANCE,
            'policy_violation': EventCategory.COMPLIANCE,
            'security_incident': EventCategory.INCIDENT,
            'threat_detected': EventCategory.INCIDENT,
            'system_error': EventCategory.SYSTEM_SECURITY,
            'configuration_change': EventCategory.SYSTEM_SECURITY
        }
        
        for key, category in category_mapping.items():
            if key in event_type.lower():
                return category
        
        return EventCategory.AUDIT
    
    def _start_background_processing(self):
        """Start background thread for event processing"""
        self._start_time = time.time()
        self.processing_thread = threading.Thread(
            target=self._process_events_background,
            daemon=True
        )
        self.processing_thread.start()
    
    def _process_events_background(self):
        """Background thread for processing events"""
        while not self.shutdown_event.is_set():
            try:
                # Get event from queue with timeout
                event = self.event_queue.get(timeout=1.0)
                self._process_event(event)
                self.event_queue.task_done()
                
            except Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error processing event: {str(e)}")
                self.event_counters['errors'] += 1
    
    def _process_event(self, event: SecurityEvent):
        """Process individual security event"""
        try:
            # Log to structured log file
            self.logger.info(event.to_json())
            
            # Additional processing based on severity
            if event.severity in [EventSeverity.CRITICAL, EventSeverity.HIGH]:
                self._handle_high_severity_event(event)
            
            # Compliance logging
            if event.category == EventCategory.COMPLIANCE:
                self._handle_compliance_event(event)
                
        except Exception as e:
            self.logger.error(f"Failed to process event {event.event_id}: {str(e)}")
            self.event_counters['errors'] += 1
    
    def _handle_high_severity_event(self, event: SecurityEvent):
        """Handle high severity events with additional alerting"""
        # This would typically trigger alerts, notifications, etc.
        self.logger.warning(f"HIGH SEVERITY EVENT: {event.event_type} - {event.details}")
    
    def _handle_compliance_event(self, event: SecurityEvent):
        """Handle compliance events with special processing"""
        # This would typically update compliance dashboards, reports, etc.
        pass
    
    def shutdown(self):
        """Gracefully shutdown audit logger"""
        self.shutdown_event.set()
        
        # Process remaining events
        while not self.event_queue.empty():
            try:
                event = self.event_queue.get_nowait()
                self._process_event(event)
            except Empty:
                break
        
        # Wait for processing thread
        if self.processing_thread and self.processing_thread.is_alive():
            self.processing_thread.join(timeout=5.0)
        
        self.logger.info("Audit logger shutdown complete")


class SecurityEventLogger:
    """Simplified interface for common security event logging"""
    
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
    
    def log_user_login(self, user_id: str, ip_address: str, success: bool, 
                      details: Dict[str, Any] = None):
        """Log user login attempt"""
        return self.audit_logger.log_authentication_event(
            user_id=user_id,
            action="login",
            result="success" if success else "failed",
            ip_address=ip_address,
            details=details
        )
    
    def log_permission_check(self, user_id: str, resource: str, permission: str,
                           granted: bool, details: Dict[str, Any] = None):
        """Log permission check"""
        return self.audit_logger.log_authorization_event(
            user_id=user_id,
            resource=resource,
            action=f"check_permission:{permission}",
            result="granted" if granted else "denied",
            details=details
        )
    
    def log_scan_started(self, scan_id: str, target: str, scan_type: str,
                        user_id: str, details: Dict[str, Any] = None):
        """Log security scan start"""
        return self.audit_logger.log_security_scan_event(
            scan_id=scan_id,
            target=target,
            scan_type=scan_type,
            status="started",
            findings=0,
            details={**(details or {}), "user_id": user_id}
        )
    
    def log_scan_completed(self, scan_id: str, target: str, scan_type: str,
                          findings: int, details: Dict[str, Any] = None):
        """Log security scan completion"""
        return self.audit_logger.log_security_scan_event(
            scan_id=scan_id,
            target=target,
            scan_type=scan_type,
            status="completed",
            findings=findings,
            details=details
        )
    
    def log_compliance_violation(self, framework: str, control: str, 
                               details: Dict[str, Any] = None):
        """Log compliance violation"""
        return self.audit_logger.log_compliance_event(
            framework=framework,
            control=control,
            status="failed",
            details=details
        )
    
    def log_threat_detected(self, threat_type: str, severity: str, source: str,
                           details: Dict[str, Any] = None):
        """Log threat detection"""
        incident_id = f"threat_{int(time.time())}"
        return self.audit_logger.log_incident_event(
            incident_id=incident_id,
            incident_type=threat_type,
            severity=severity,
            details={**(details or {}), "source": source}
        )