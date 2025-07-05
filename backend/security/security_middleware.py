"""
Security Middleware Module

Implements comprehensive request validation, rate limiting, session management,
and security headers for the CyberCortex platform.
"""

import time
import hashlib
import secrets
import json
from typing import Dict, List, Optional, Set, Any, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import logging
import ipaddress
from functools import wraps

from fastapi import Request, Response, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from .audit_logger import AuditLogger


@dataclass
class SecurityConfig:
    """Security configuration settings"""
    max_requests_per_minute: int = 100
    max_requests_per_hour: int = 1000
    max_concurrent_requests: int = 50
    session_timeout_minutes: int = 30
    max_failed_attempts: int = 5
    lockout_duration_minutes: int = 15
    require_https: bool = True
    allowed_origins: List[str] = None
    blocked_ips: Set[str] = None
    trusted_proxies: Set[str] = None
    
    def __post_init__(self):
        if self.allowed_origins is None:
            self.allowed_origins = []
        if self.blocked_ips is None:
            self.blocked_ips = set()
        if self.trusted_proxies is None:
            self.trusted_proxies = set()


@dataclass
class RateLimitRule:
    """Rate limiting rule configuration"""
    requests_per_window: int
    window_seconds: int
    burst_allowance: int = 0
    
    def __post_init__(self):
        if self.burst_allowance == 0:
            self.burst_allowance = max(1, self.requests_per_window // 10)


class RateLimiter:
    """Advanced rate limiter with sliding window and burst protection"""
    
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
        self.logger = logging.getLogger(__name__)
        
        # Rate limiting storage
        self.request_history: Dict[str, deque] = defaultdict(deque)
        self.burst_tokens: Dict[str, int] = defaultdict(int)
        self.last_refill: Dict[str, float] = defaultdict(float)
        
        # Default rate limit rules
        self.rules = {
            'default': RateLimitRule(100, 60),  # 100 requests per minute
            'auth': RateLimitRule(10, 60),      # 10 auth attempts per minute
            'scan': RateLimitRule(5, 60),       # 5 scans per minute
            'api': RateLimitRule(1000, 3600),   # 1000 API calls per hour
        }
    
    def is_allowed(self, identifier: str, rule_name: str = 'default') -> tuple[bool, Dict[str, Any]]:
        """
        Check if request is allowed under rate limiting rules
        
        Args:
            identifier: Unique identifier (IP, user ID, etc.)
            rule_name: Name of rate limiting rule to apply
            
        Returns:
            Tuple of (is_allowed, rate_limit_info)
        """
        try:
            rule = self.rules.get(rule_name, self.rules['default'])
            current_time = time.time()
            
            # Clean old requests outside window
            self._cleanup_old_requests(identifier, rule, current_time)
            
            # Refill burst tokens
            self._refill_burst_tokens(identifier, rule, current_time)
            
            # Check sliding window limit
            request_count = len(self.request_history[identifier])
            
            # Check if we can use burst tokens
            can_use_burst = self.burst_tokens[identifier] > 0
            
            if request_count < rule.requests_per_window or can_use_burst:
                # Allow request
                self.request_history[identifier].append(current_time)
                
                if request_count >= rule.requests_per_window and can_use_burst:
                    self.burst_tokens[identifier] -= 1
                
                rate_limit_info = {
                    'allowed': True,
                    'requests_remaining': max(0, rule.requests_per_window - request_count),
                    'burst_tokens_remaining': self.burst_tokens[identifier],
                    'reset_time': current_time + rule.window_seconds,
                    'rule_name': rule_name
                }
                
                return True, rate_limit_info
            else:
                # Rate limit exceeded
                rate_limit_info = {
                    'allowed': False,
                    'requests_remaining': 0,
                    'burst_tokens_remaining': self.burst_tokens[identifier],
                    'reset_time': current_time + rule.window_seconds,
                    'rule_name': rule_name,
                    'retry_after': self._calculate_retry_after(identifier, rule, current_time)
                }
                
                # Log rate limit violation
                self.audit_logger.log_security_event(
                    event_type="rate_limit_exceeded",
                    severity="warning",
                    details={
                        "identifier": identifier,
                        "rule_name": rule_name,
                        "request_count": request_count,
                        "limit": rule.requests_per_window,
                        "window_seconds": rule.window_seconds
                    }
                )
                
                return False, rate_limit_info
                
        except Exception as e:
            self.logger.error(f"Rate limiting error: {str(e)}")
            # Fail open for availability
            return True, {'allowed': True, 'error': str(e)}
    
    def _cleanup_old_requests(self, identifier: str, rule: RateLimitRule, current_time: float):
        """Remove requests outside the sliding window"""
        cutoff_time = current_time - rule.window_seconds
        history = self.request_history[identifier]
        
        while history and history[0] < cutoff_time:
            history.popleft()
    
    def _refill_burst_tokens(self, identifier: str, rule: RateLimitRule, current_time: float):
        """Refill burst tokens based on time elapsed"""
        last_refill = self.last_refill[identifier]
        if last_refill == 0:
            self.last_refill[identifier] = current_time
            self.burst_tokens[identifier] = rule.burst_allowance
            return
        
        time_elapsed = current_time - last_refill
        tokens_to_add = int(time_elapsed * rule.burst_allowance / rule.window_seconds)
        
        if tokens_to_add > 0:
            self.burst_tokens[identifier] = min(
                rule.burst_allowance,
                self.burst_tokens[identifier] + tokens_to_add
            )
            self.last_refill[identifier] = current_time
    
    def _calculate_retry_after(self, identifier: str, rule: RateLimitRule, current_time: float) -> int:
        """Calculate retry-after time in seconds"""
        if not self.request_history[identifier]:
            return rule.window_seconds
        
        oldest_request = self.request_history[identifier][0]
        return max(1, int(oldest_request + rule.window_seconds - current_time))


class SessionManager:
    """Secure session management with timeout and validation"""
    
    def __init__(self, audit_logger: AuditLogger, config: SecurityConfig):
        self.audit_logger = audit_logger
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Session storage
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.user_sessions: Dict[str, Set[str]] = defaultdict(set)
        self.failed_attempts: Dict[str, List[datetime]] = defaultdict(list)
        self.locked_accounts: Dict[str, datetime] = {}
    
    def create_session(self, user_id: str, user_data: Dict[str, Any], 
                      request_info: Dict[str, Any]) -> str:
        """Create new authenticated session"""
        try:
            # Check if account is locked
            if self._is_account_locked(user_id):
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail="Account temporarily locked due to failed login attempts"
                )
            
            # Generate secure session token
            session_token = self._generate_session_token()
            
            # Create session data
            session_data = {
                'user_id': user_id,
                'user_data': user_data,
                'created_at': datetime.utcnow(),
                'last_activity': datetime.utcnow(),
                'ip_address': request_info.get('ip_address'),
                'user_agent': request_info.get('user_agent'),
                'permissions': user_data.get('permissions', []),
                'is_admin': user_data.get('is_admin', False),
                'session_id': session_token
            }
            
            # Store session
            self.active_sessions[session_token] = session_data
            self.user_sessions[user_id].add(session_token)
            
            # Clear failed attempts on successful login
            if user_id in self.failed_attempts:
                del self.failed_attempts[user_id]
            
            # Log session creation
            self.audit_logger.log_security_event(
                event_type="session_created",
                severity="info",
                details={
                    "user_id": user_id,
                    "session_id": session_token,
                    "ip_address": request_info.get('ip_address'),
                    "user_agent": request_info.get('user_agent')
                }
            )
            
            return session_token
            
        except Exception as e:
            self.logger.error(f"Session creation failed: {str(e)}")
            raise
    
    def validate_session(self, session_token: str, request_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Validate and refresh session"""
        try:
            session_data = self.active_sessions.get(session_token)
            if not session_data:
                return None
            
            # Check session timeout
            if self._is_session_expired(session_data):
                self._invalidate_session(session_token, "Session timeout")
                return None
            
            # Validate IP address (optional strict checking)
            if self.config.require_https and request_info.get('ip_address') != session_data.get('ip_address'):
                self.audit_logger.log_security_event(
                    event_type="session_ip_mismatch",
                    severity="warning",
                    details={
                        "session_id": session_token,
                        "original_ip": session_data.get('ip_address'),
                        "current_ip": request_info.get('ip_address')
                    }
                )
            
            # Update last activity
            session_data['last_activity'] = datetime.utcnow()
            
            return session_data
            
        except Exception as e:
            self.logger.error(f"Session validation failed: {str(e)}")
            return None
    
    def invalidate_session(self, session_token: str, reason: str = "Manual logout"):
        """Invalidate specific session"""
        self._invalidate_session(session_token, reason)
    
    def invalidate_user_sessions(self, user_id: str, reason: str = "Security policy"):
        """Invalidate all sessions for a user"""
        sessions_to_remove = list(self.user_sessions.get(user_id, set()))
        for session_token in sessions_to_remove:
            self._invalidate_session(session_token, reason)
    
    def record_failed_attempt(self, user_id: str, request_info: Dict[str, Any]):
        """Record failed authentication attempt"""
        current_time = datetime.utcnow()
        
        # Clean old attempts (older than lockout duration)
        cutoff_time = current_time - timedelta(minutes=self.config.lockout_duration_minutes)
        self.failed_attempts[user_id] = [
            attempt for attempt in self.failed_attempts[user_id]
            if attempt > cutoff_time
        ]
        
        # Add new failed attempt
        self.failed_attempts[user_id].append(current_time)
        
        # Check if account should be locked
        if len(self.failed_attempts[user_id]) >= self.config.max_failed_attempts:
            self.locked_accounts[user_id] = current_time + timedelta(
                minutes=self.config.lockout_duration_minutes
            )
            
            self.audit_logger.log_security_event(
                event_type="account_locked",
                severity="warning",
                details={
                    "user_id": user_id,
                    "failed_attempts": len(self.failed_attempts[user_id]),
                    "lockout_until": self.locked_accounts[user_id].isoformat(),
                    "ip_address": request_info.get('ip_address')
                }
            )
        
        # Log failed attempt
        self.audit_logger.log_security_event(
            event_type="authentication_failed",
            severity="warning",
            details={
                "user_id": user_id,
                "attempt_count": len(self.failed_attempts[user_id]),
                "ip_address": request_info.get('ip_address'),
                "user_agent": request_info.get('user_agent')
            }
        )
    
    def _generate_session_token(self) -> str:
        """Generate cryptographically secure session token"""
        return secrets.token_urlsafe(32)
    
    def _is_session_expired(self, session_data: Dict[str, Any]) -> bool:
        """Check if session has expired"""
        last_activity = session_data.get('last_activity')
        if not last_activity:
            return True
        
        timeout = timedelta(minutes=self.config.session_timeout_minutes)
        return datetime.utcnow() - last_activity > timeout
    
    def _is_account_locked(self, user_id: str) -> bool:
        """Check if account is currently locked"""
        if user_id not in self.locked_accounts:
            return False
        
        lockout_until = self.locked_accounts[user_id]
        if datetime.utcnow() > lockout_until:
            # Lockout expired, remove from locked accounts
            del self.locked_accounts[user_id]
            return False
        
        return True
    
    def _invalidate_session(self, session_token: str, reason: str):
        """Internal method to invalidate session"""
        session_data = self.active_sessions.get(session_token)
        if session_data:
            user_id = session_data.get('user_id')
            
            # Remove from active sessions
            del self.active_sessions[session_token]
            
            # Remove from user sessions
            if user_id and user_id in self.user_sessions:
                self.user_sessions[user_id].discard(session_token)
                if not self.user_sessions[user_id]:
                    del self.user_sessions[user_id]
            
            # Log session invalidation
            self.audit_logger.log_security_event(
                event_type="session_invalidated",
                severity="info",
                details={
                    "session_id": session_token,
                    "user_id": user_id,
                    "reason": reason
                }
            )


class SecurityMiddleware(BaseHTTPMiddleware):
    """Comprehensive security middleware for request validation and protection"""
    
    def __init__(self, app, config: SecurityConfig, audit_logger: AuditLogger):
        super().__init__(app)
        self.config = config
        self.audit_logger = audit_logger
        self.rate_limiter = RateLimiter(audit_logger)
        self.session_manager = SessionManager(audit_logger, config)
        self.logger = logging.getLogger(__name__)
        
        # Request tracking
        self.active_requests: Dict[str, int] = defaultdict(int)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Main middleware dispatch method"""
        start_time = time.time()
        client_ip = self._get_client_ip(request)
        
        try:
            # Security validations
            security_check = await self._perform_security_checks(request, client_ip)
            if security_check:
                return security_check
            
            # Track concurrent requests
            self.active_requests[client_ip] += 1
            
            try:
                # Process request
                response = await call_next(request)
                
                # Add security headers
                self._add_security_headers(response)
                
                # Log successful request
                self._log_request(request, response, client_ip, time.time() - start_time)
                
                return response
                
            finally:
                # Cleanup request tracking
                self.active_requests[client_ip] -= 1
                if self.active_requests[client_ip] <= 0:
                    del self.active_requests[client_ip]
                
        except Exception as e:
            self.logger.error(f"Security middleware error: {str(e)}")
            
            # Log security error
            self.audit_logger.log_security_event(
                event_type="middleware_error",
                severity="error",
                details={
                    "error": str(e),
                    "client_ip": client_ip,
                    "path": str(request.url.path),
                    "method": request.method
                }
            )
            
            return JSONResponse(
                status_code=500,
                content={"error": "Internal security error"}
            )
    
    async def _perform_security_checks(self, request: Request, client_ip: str) -> Optional[Response]:
        """Perform comprehensive security checks"""
        
        # Check blocked IPs
        if client_ip in self.config.blocked_ips:
            self.audit_logger.log_security_event(
                event_type="blocked_ip_access",
                severity="warning",
                details={"client_ip": client_ip, "path": str(request.url.path)}
            )
            return JSONResponse(
                status_code=403,
                content={"error": "Access denied"}
            )
        
        # Check HTTPS requirement
        if self.config.require_https and request.url.scheme != "https":
            return JSONResponse(
                status_code=400,
                content={"error": "HTTPS required"}
            )
        
        # Check concurrent request limits
        if self.active_requests[client_ip] >= self.config.max_concurrent_requests:
            self.audit_logger.log_security_event(
                event_type="concurrent_limit_exceeded",
                severity="warning",
                details={
                    "client_ip": client_ip,
                    "concurrent_requests": self.active_requests[client_ip],
                    "limit": self.config.max_concurrent_requests
                }
            )
            return JSONResponse(
                status_code=429,
                content={"error": "Too many concurrent requests"}
            )
        
        # Rate limiting
        rule_name = self._get_rate_limit_rule(request)
        is_allowed, rate_info = self.rate_limiter.is_allowed(client_ip, rule_name)
        
        if not is_allowed:
            headers = {
                "X-RateLimit-Limit": str(rate_info.get('limit', 0)),
                "X-RateLimit-Remaining": str(rate_info.get('requests_remaining', 0)),
                "X-RateLimit-Reset": str(int(rate_info.get('reset_time', 0))),
                "Retry-After": str(rate_info.get('retry_after', 60))
            }
            
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded"},
                headers=headers
            )
        
        # Validate request size
        content_length = request.headers.get('content-length')
        if content_length and int(content_length) > 10 * 1024 * 1024:  # 10MB limit
            return JSONResponse(
                status_code=413,
                content={"error": "Request too large"}
            )
        
        return None
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address considering trusted proxies"""
        # Check X-Forwarded-For header from trusted proxies
        forwarded_for = request.headers.get('x-forwarded-for')
        if forwarded_for:
            # Take the first IP in the chain
            client_ip = forwarded_for.split(',')[0].strip()
            try:
                ipaddress.ip_address(client_ip)
                return client_ip
            except ValueError:
                pass
        
        # Check X-Real-IP header
        real_ip = request.headers.get('x-real-ip')
        if real_ip:
            try:
                ipaddress.ip_address(real_ip)
                return real_ip
            except ValueError:
                pass
        
        # Fallback to direct client IP
        return request.client.host if request.client else "unknown"
    
    def _get_rate_limit_rule(self, request: Request) -> str:
        """Determine appropriate rate limiting rule for request"""
        path = request.url.path.lower()
        
        if '/auth/' in path or '/login' in path:
            return 'auth'
        elif '/scan' in path or '/assessment' in path:
            return 'scan'
        elif '/api/' in path:
            return 'api'
        else:
            return 'default'
    
    def _add_security_headers(self, response: Response):
        """Add comprehensive security headers"""
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
            "X-Permitted-Cross-Domain-Policies": "none",
            "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
            "Pragma": "no-cache",
            "Expires": "0"
        }
        
        for header, value in security_headers.items():
            response.headers[header] = value
    
    def _log_request(self, request: Request, response: Response, client_ip: str, duration: float):
        """Log request for security monitoring"""
        self.audit_logger.log_security_event(
            event_type="http_request",
            severity="info",
            details={
                "method": request.method,
                "path": str(request.url.path),
                "client_ip": client_ip,
                "status_code": response.status_code,
                "duration_ms": round(duration * 1000, 2),
                "user_agent": request.headers.get('user-agent', ''),
                "content_length": request.headers.get('content-length', 0)
            }
        )


def require_auth(session_manager: SessionManager):
    """Decorator for endpoints requiring authentication"""
    def decorator(func):
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            # Extract session token from Authorization header
            auth_header = request.headers.get('authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Missing or invalid authorization header"
                )
            
            session_token = auth_header[7:]  # Remove 'Bearer ' prefix
            
            # Validate session
            request_info = {
                'ip_address': request.client.host if request.client else 'unknown',
                'user_agent': request.headers.get('user-agent', '')
            }
            
            session_data = session_manager.validate_session(session_token, request_info)
            if not session_data:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired session"
                )
            
            # Add session data to request state
            request.state.session = session_data
            request.state.user_id = session_data['user_id']
            
            return await func(request, *args, **kwargs)
        
        return wrapper
    return decorator


def require_permission(permission: str, session_manager: SessionManager):
    """Decorator for endpoints requiring specific permissions"""
    def decorator(func):
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            # First check authentication
            auth_wrapper = require_auth(session_manager)
            await auth_wrapper(lambda r: None)(request)
            
            # Check permission
            session_data = request.state.session
            user_permissions = session_data.get('permissions', [])
            is_admin = session_data.get('is_admin', False)
            
            if not is_admin and permission not in user_permissions:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission '{permission}' required"
                )
            
            return await func(request, *args, **kwargs)
        
        return wrapper
    return decorator