"""
Groq Intelligence Engine

Lightning-fast security analysis using Groq's ultra-fast inference with Llama-3 models.
Provides sub-second threat assessment, real-time security decisions, and intelligent
vulnerability classification with streaming responses and voice integration.
"""

import asyncio
import json
import logging
import time
import hashlib
from typing import Dict, List, Optional, Any, AsyncGenerator, Tuple, Union
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict, field
from enum import Enum
import aiohttp
import redis.asyncio as redis
from groq import AsyncGroq
import speech_recognition as sr
import pyttsx3
from concurrent.futures import ThreadPoolExecutor
import threading
from abc import ABC, abstractmethod


class ThreatLevel(Enum):
    """Threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SecurityAction(Enum):
    """Recommended security actions"""
    IMMEDIATE_BLOCK = "immediate_block"
    QUARANTINE = "quarantine"
    MONITOR = "monitor"
    INVESTIGATE = "investigate"
    ALLOW = "allow"
    REMEDIATE = "remediate"


class AnalysisType(Enum):
    """Types of security analysis"""
    THREAT_ASSESSMENT = "threat_assessment"
    VULNERABILITY_SCAN = "vulnerability_scan"
    INCIDENT_RESPONSE = "incident_response"
    COMPLIANCE_CHECK = "compliance_check"
    RISK_EVALUATION = "risk_evaluation"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"


@dataclass
class ThreatAnalysisResult:
    """Result of threat analysis"""
    threat_id: str
    threat_level: ThreatLevel
    confidence: float  # 0.0 to 1.0
    threat_type: str
    description: str
    indicators: List[str]
    recommended_action: SecurityAction
    analysis_time_ms: float
    evidence: List[Dict[str, Any]]
    mitre_tactics: List[str]
    kill_chain_phase: str
    timestamp: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['threat_level'] = self.threat_level.value
        data['recommended_action'] = self.recommended_action.value
        data['timestamp'] = self.timestamp.isoformat()
        return data


@dataclass
class SecurityDecision:
    """Security decision with reasoning"""
    decision_id: str
    decision: SecurityAction
    confidence: float
    reasoning: str
    risk_score: float  # 0.0 to 10.0
    factors: List[Dict[str, Any]]
    alternatives: List[Dict[str, Any]]
    decision_time_ms: float
    valid_until: datetime
    auto_executable: bool
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['decision'] = self.decision.value
        data['valid_until'] = self.valid_until.isoformat()
        return data


@dataclass
class VulnerabilityClassification:
    """Vulnerability classification result"""
    vuln_id: str
    category: str
    severity: ThreatLevel
    cvss_score: Optional[float]
    cve_id: Optional[str]
    description: str
    affected_systems: List[str]
    exploit_complexity: str  # low, medium, high
    remediation_priority: int  # 1-5
    estimated_fix_time: str
    business_impact: str
    classification_time_ms: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['severity'] = self.severity.value
        return data


@dataclass
class RemediationPlan:
    """Intelligent remediation plan"""
    plan_id: str
    vulnerability_id: str
    priority: int
    estimated_effort: str
    steps: List[Dict[str, Any]]
    code_fixes: List[Dict[str, str]]
    configuration_changes: List[Dict[str, Any]]
    verification_steps: List[str]
    rollback_plan: List[str]
    automation_available: bool
    cost_estimate: Optional[float]
    timeline: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class GroqConfiguration:
    """Configuration for Groq engine"""
    api_key: str
    model: str = "llama3-70b-8192"  # Groq's fastest model
    temperature: float = 0.1
    max_tokens: int = 2048
    timeout: int = 10  # Aggressive timeout for speed
    stream: bool = True
    cache_ttl: int = 300  # 5 minutes cache
    performance_target_ms: int = 500  # Target response time
    
    # Redis cache configuration
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    
    # Speech configuration
    speech_enabled: bool = False
    voice_rate: int = 200
    voice_volume: float = 0.9


class PerformanceMonitor:
    """Monitor and optimize performance metrics"""
    
    def __init__(self):
        self.metrics = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'average_response_time': 0.0,
            'cache_hits': 0,
            'cache_misses': 0,
            'sub_500ms_responses': 0,
            'streaming_sessions': 0
        }
        self.response_times = []
        self.lock = threading.Lock()
    
    def record_request(self, response_time_ms: float, success: bool, cache_hit: bool = False):
        """Record request metrics"""
        with self.lock:
            self.metrics['total_requests'] += 1
            
            if success:
                self.metrics['successful_requests'] += 1
                self.response_times.append(response_time_ms)
                
                # Keep only last 1000 response times for rolling average
                if len(self.response_times) > 1000:
                    self.response_times = self.response_times[-1000:]
                
                self.metrics['average_response_time'] = sum(self.response_times) / len(self.response_times)
                
                if response_time_ms < 500:
                    self.metrics['sub_500ms_responses'] += 1
            else:
                self.metrics['failed_requests'] += 1
            
            if cache_hit:
                self.metrics['cache_hits'] += 1
            else:
                self.metrics['cache_misses'] += 1
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get current performance statistics"""
        with self.lock:
            total = self.metrics['total_requests']
            if total == 0:
                return self.metrics.copy()
            
            stats = self.metrics.copy()
            stats.update({
                'success_rate': (self.metrics['successful_requests'] / total) * 100,
                'cache_hit_rate': (self.metrics['cache_hits'] / total) * 100 if total > 0 else 0,
                'sub_500ms_rate': (self.metrics['sub_500ms_responses'] / self.metrics['successful_requests']) * 100 if self.metrics['successful_requests'] > 0 else 0,
                'p95_response_time': self._calculate_percentile(95) if self.response_times else 0,
                'p99_response_time': self._calculate_percentile(99) if self.response_times else 0
            })
            
            return stats
    
    def _calculate_percentile(self, percentile: int) -> float:
        """Calculate response time percentile"""
        if not self.response_times:
            return 0.0
        
        sorted_times = sorted(self.response_times)
        index = int((percentile / 100) * len(sorted_times))
        return sorted_times[min(index, len(sorted_times) - 1)]


class ResponseCache:
    """High-performance response caching with Redis"""
    
    def __init__(self, config: GroqConfiguration):
        self.config = config
        self.redis_client: Optional[redis.Redis] = None
        self.logger = logging.getLogger(__name__)
    
    async def initialize(self):
        """Initialize Redis connection"""
        try:
            self.redis_client = redis.Redis(
                host=self.config.redis_host,
                port=self.config.redis_port,
                db=self.config.redis_db,
                decode_responses=True
            )
            await self.redis_client.ping()
            self.logger.info("Redis cache initialized successfully")
        except Exception as e:
            self.logger.warning(f"Redis cache initialization failed: {str(e)}")
            self.redis_client = None
    
    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Get cached response"""
        if not self.redis_client:
            return None
        
        try:
            cached = await self.redis_client.get(key)
            if cached:
                return json.loads(cached)
        except Exception as e:
            self.logger.error(f"Cache get error: {str(e)}")
        
        return None
    
    async def set(self, key: str, value: Dict[str, Any], ttl: Optional[int] = None):
        """Cache response"""
        if not self.redis_client:
            return
        
        try:
            ttl = ttl or self.config.cache_ttl
            await self.redis_client.setex(
                key, 
                ttl, 
                json.dumps(value, default=str)
            )
        except Exception as e:
            self.logger.error(f"Cache set error: {str(e)}")
    
    def generate_cache_key(self, prompt: str, context: Dict[str, Any]) -> str:
        """Generate cache key for request"""
        content = f"{prompt}:{json.dumps(context, sort_keys=True)}"
        return f"groq_cache:{hashlib.sha256(content.encode()).hexdigest()}"


class BaseGroqAnalyzer(ABC):
    """Base class for Groq-powered security analyzers"""
    
    def __init__(self, config: GroqConfiguration):
        self.config = config
        self.client = AsyncGroq(api_key=config.api_key)
        self.cache = ResponseCache(config)
        self.performance = PerformanceMonitor()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
    async def initialize(self):
        """Initialize analyzer"""
        await self.cache.initialize()
        self.logger.info(f"{self.__class__.__name__} initialized")
    
    @abstractmethod
    def get_system_prompt(self) -> str:
        """Get system prompt for this analyzer"""
        pass
    
    async def _make_groq_request(self, prompt: str, context: Dict[str, Any], stream: bool = None) -> Union[Dict[str, Any], AsyncGenerator[str, None]]:
        """Make optimized request to Groq API"""
        start_time = time.time()
        
        # Check cache first
        cache_key = self.cache.generate_cache_key(prompt, context)
        cached_response = await self.cache.get(cache_key)
        
        if cached_response and not (stream if stream is not None else self.config.stream):
            self.performance.record_request(
                (time.time() - start_time) * 1000, 
                True, 
                cache_hit=True
            )
            return cached_response
        
        try:
            messages = [
                {"role": "system", "content": self.get_system_prompt()},
                {"role": "user", "content": self._build_prompt(prompt, context)}
            ]
            
            use_stream = stream if stream is not None else self.config.stream
            
            if use_stream:
                return self._stream_response(messages, start_time)
            else:
                response = await self.client.chat.completions.create(
                    model=self.config.model,
                    messages=messages,
                    temperature=self.config.temperature,
                    max_tokens=self.config.max_tokens,
                    stream=False
                )
                
                result = {
                    'content': response.choices[0].message.content,
                    'usage': response.usage.dict() if response.usage else {},
                    'model': response.model
                }
                
                # Cache non-streaming responses
                await self.cache.set(cache_key, result)
                
                response_time = (time.time() - start_time) * 1000
                self.performance.record_request(response_time, True, cache_hit=False)
                
                return result
                
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            self.performance.record_request(response_time, False)
            self.logger.error(f"Groq API request failed: {str(e)}")
            raise
    
    async def _stream_response(self, messages: List[Dict[str, str]], start_time: float) -> AsyncGenerator[str, None]:
        """Stream response from Groq API"""
        try:
            self.performance.metrics['streaming_sessions'] += 1
            
            stream = await self.client.chat.completions.create(
                model=self.config.model,
                messages=messages,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                stream=True
            )
            
            first_token_time = None
            full_content = ""
            
            async for chunk in stream:
                if chunk.choices[0].delta.content:
                    content = chunk.choices[0].delta.content
                    full_content += content
                    
                    if first_token_time is None:
                        first_token_time = time.time()
                        # Record time to first token
                        ttft = (first_token_time - start_time) * 1000
                        self.logger.debug(f"Time to first token: {ttft:.2f}ms")
                    
                    yield content
            
            # Record final metrics
            total_time = (time.time() - start_time) * 1000
            self.performance.record_request(total_time, True, cache_hit=False)
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            self.performance.record_request(response_time, False)
            self.logger.error(f"Groq streaming failed: {str(e)}")
            raise
    
    def _build_prompt(self, prompt: str, context: Dict[str, Any]) -> str:
        """Build optimized prompt with context"""
        return f"""
SECURITY ANALYSIS REQUEST

Context: {json.dumps(context, indent=2)}

Analysis Request: {prompt}

PERFORMANCE REQUIREMENTS:
- Provide immediate, actionable analysis
- Focus on high-confidence findings
- Prioritize critical security issues
- Include specific remediation steps

RESPONSE FORMAT: JSON with structured analysis results
"""
    
    def _parse_json_response(self, content: str) -> Dict[str, Any]:
        """Parse JSON from Groq response"""
        try:
            # Extract JSON from response if wrapped in markdown
            if '```json' in content:
                start = content.find('```json') + 7
                end = content.find('```', start)
                json_content = content[start:end].strip()
            else:
                json_content = content.strip()
            
            return json.loads(json_content)
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse JSON response: {str(e)}")
            return {"error": "Invalid JSON response", "raw_content": content}


class ThreatAnalysisEngine(BaseGroqAnalyzer):
    """Lightning-fast threat analysis using Groq Llama-3"""
    
    def get_system_prompt(self) -> str:
        return """You are an elite cybersecurity threat analyst with expertise in:
- Real-time threat detection and classification
- MITRE ATT&CK framework mapping
- Cyber kill chain analysis
- Threat intelligence correlation
- Incident response prioritization

Analyze security events with sub-second response time. Focus on:
1. Immediate threat level assessment
2. Attack vector identification
3. Recommended security actions
4. Evidence correlation
5. MITRE ATT&CK technique mapping

Provide JSON responses with threat_level, confidence, threat_type, description, indicators, recommended_action, evidence, mitre_tactics, and kill_chain_phase."""
    
    async def analyze_threat(self, indicators: List[str], context: Dict[str, Any]) -> ThreatAnalysisResult:
        """Perform lightning-fast threat analysis"""
        start_time = time.time()
        
        prompt = f"""
Analyze the following security indicators for threats:

INDICATORS:
{json.dumps(indicators, indent=2)}

Provide immediate threat assessment including:
1. Threat level (critical/high/medium/low/info)
2. Confidence score (0.0-1.0)
3. Threat type and description
4. Key indicators of compromise
5. Recommended security action
6. Supporting evidence
7. MITRE ATT&CK tactics
8. Cyber kill chain phase

Focus on actionable intelligence for immediate response.
"""
        
        try:
            response = await self._make_groq_request(prompt, context, stream=False)
            analysis_data = self._parse_json_response(response['content'])
            
            analysis_time = (time.time() - start_time) * 1000
            
            return ThreatAnalysisResult(
                threat_id=self._generate_threat_id(indicators),
                threat_level=ThreatLevel(analysis_data.get('threat_level', 'medium')),
                confidence=analysis_data.get('confidence', 0.5),
                threat_type=analysis_data.get('threat_type', 'Unknown'),
                description=analysis_data.get('description', ''),
                indicators=analysis_data.get('indicators', indicators),
                recommended_action=SecurityAction(analysis_data.get('recommended_action', 'investigate')),
                analysis_time_ms=analysis_time,
                evidence=analysis_data.get('evidence', []),
                mitre_tactics=analysis_data.get('mitre_tactics', []),
                kill_chain_phase=analysis_data.get('kill_chain_phase', 'unknown'),
                timestamp=datetime.now(timezone.utc)
            )
            
        except Exception as e:
            self.logger.error(f"Threat analysis failed: {str(e)}")
            return self._create_fallback_threat_result(indicators, time.time() - start_time)
    
    async def stream_threat_analysis(self, indicators: List[str], context: Dict[str, Any]) -> AsyncGenerator[str, None]:
        """Stream real-time threat analysis"""
        prompt = f"""
Perform streaming threat analysis for indicators: {indicators}

Provide real-time analysis updates as you process each indicator.
"""
        
        async for chunk in await self._make_groq_request(prompt, context, stream=True):
            yield chunk
    
    def _generate_threat_id(self, indicators: List[str]) -> str:
        """Generate unique threat ID"""
        content = f"{''.join(indicators)}{datetime.now().isoformat()}"
        return f"threat_{hashlib.sha256(content.encode()).hexdigest()[:12]}"
    
    def _create_fallback_threat_result(self, indicators: List[str], elapsed_time: float) -> ThreatAnalysisResult:
        """Create fallback result when analysis fails"""
        return ThreatAnalysisResult(
            threat_id=self._generate_threat_id(indicators),
            threat_level=ThreatLevel.MEDIUM,
            confidence=0.3,
            threat_type="Analysis Failed",
            description="Threat analysis could not be completed",
            indicators=indicators,
            recommended_action=SecurityAction.INVESTIGATE,
            analysis_time_ms=elapsed_time * 1000,
            evidence=[],
            mitre_tactics=[],
            kill_chain_phase="unknown",
            timestamp=datetime.now(timezone.utc)
        )


class SecurityDecisionMaker(BaseGroqAnalyzer):
    """Real-time security decision engine"""
    
    def get_system_prompt(self) -> str:
        return """You are an expert security decision engine that provides real-time security decisions based on:
- Risk assessment and impact analysis
- Business context and operational requirements
- Threat intelligence and attack patterns
- Compliance and regulatory requirements
- Cost-benefit analysis of security actions

Make rapid, well-reasoned security decisions with:
1. Clear recommended action
2. Confidence level and reasoning
3. Risk score assessment
4. Alternative options
5. Implementation considerations

Provide JSON responses with decision, confidence, reasoning, risk_score, factors, alternatives, and auto_executable flag."""
    
    async def make_security_decision(self, scenario: Dict[str, Any], context: Dict[str, Any]) -> SecurityDecision:
        """Make real-time security decision"""
        start_time = time.time()
        
        prompt = f"""
Make an immediate security decision for the following scenario:

SCENARIO:
{json.dumps(scenario, indent=2)}

BUSINESS CONTEXT:
- Environment: {context.get('environment', 'production')}
- Criticality: {context.get('criticality', 'high')}
- Compliance requirements: {context.get('compliance', [])}
- Available resources: {context.get('resources', 'standard')}

Provide immediate decision with:
1. Recommended action (immediate_block/quarantine/monitor/investigate/allow/remediate)
2. Confidence level (0.0-1.0)
3. Clear reasoning
4. Risk score (0.0-10.0)
5. Contributing factors
6. Alternative options
7. Auto-execution feasibility

Focus on balancing security and business continuity.
"""
        
        try:
            response = await self._make_groq_request(prompt, context, stream=False)
            decision_data = self._parse_json_response(response['content'])
            
            decision_time = (time.time() - start_time) * 1000
            
            return SecurityDecision(
                decision_id=self._generate_decision_id(scenario),
                decision=SecurityAction(decision_data.get('decision', 'investigate')),
                confidence=decision_data.get('confidence', 0.5),
                reasoning=decision_data.get('reasoning', ''),
                risk_score=decision_data.get('risk_score', 5.0),
                factors=decision_data.get('factors', []),
                alternatives=decision_data.get('alternatives', []),
                decision_time_ms=decision_time,
                valid_until=datetime.now(timezone.utc) + timedelta(hours=1),
                auto_executable=decision_data.get('auto_executable', False)
            )
            
        except Exception as e:
            self.logger.error(f"Security decision failed: {str(e)}")
            return self._create_fallback_decision(scenario, time.time() - start_time)
    
    def _generate_decision_id(self, scenario: Dict[str, Any]) -> str:
        """Generate unique decision ID"""
        content = f"{json.dumps(scenario, sort_keys=True)}{datetime.now().isoformat()}"
        return f"decision_{hashlib.sha256(content.encode()).hexdigest()[:12]}"
    
    def _create_fallback_decision(self, scenario: Dict[str, Any], elapsed_time: float) -> SecurityDecision:
        """Create fallback decision when analysis fails"""
        return SecurityDecision(
            decision_id=self._generate_decision_id(scenario),
            decision=SecurityAction.INVESTIGATE,
            confidence=0.3,
            reasoning="Decision analysis could not be completed - defaulting to investigation",
            risk_score=5.0,
            factors=[],
            alternatives=[],
            decision_time_ms=elapsed_time * 1000,
            valid_until=datetime.now(timezone.utc) + timedelta(hours=1),
            auto_executable=False
        )


class VulnerabilityClassifier(BaseGroqAnalyzer):
    """Instant vulnerability classification and prioritization"""
    
    def get_system_prompt(self) -> str:
        return """You are an expert vulnerability analyst specializing in:
- Rapid vulnerability classification and scoring
- CVSS assessment and risk prioritization
- Exploit complexity evaluation
- Business impact assessment
- Remediation timeline estimation

Classify vulnerabilities with:
1. Category and severity assessment
2. CVSS score calculation
3. Exploit complexity analysis
4. Affected system identification
5. Remediation priority ranking
6. Business impact evaluation

Provide JSON responses with category, severity, cvss_score, cve_id, description, affected_systems, exploit_complexity, remediation_priority, estimated_fix_time, and business_impact."""
    
    async def classify_vulnerability(self, vulnerability_data: Dict[str, Any], context: Dict[str, Any]) -> VulnerabilityClassification:
        """Classify vulnerability with instant prioritization"""
        start_time = time.time()
        
        prompt = f"""
Classify and prioritize the following vulnerability:

VULNERABILITY DATA:
{json.dumps(vulnerability_data, indent=2)}

SYSTEM CONTEXT:
- Environment: {context.get('environment', 'production')}
- System criticality: {context.get('criticality', 'high')}
- Exposure level: {context.get('exposure', 'internal')}
- Data sensitivity: {context.get('data_sensitivity', 'medium')}

Provide immediate classification with:
1. Vulnerability category
2. Severity level (critical/high/medium/low/info)
3. CVSS score if applicable
4. CVE ID if known
5. Clear description
6. Affected systems list
7. Exploit complexity (low/medium/high)
8. Remediation priority (1-5)
9. Estimated fix time
10. Business impact assessment

Focus on actionable prioritization for remediation planning.
"""
        
        try:
            response = await self._make_groq_request(prompt, context, stream=False)
            classification_data = self._parse_json_response(response['content'])
            
            classification_time = (time.time() - start_time) * 1000
            
            return VulnerabilityClassification(
                vuln_id=self._generate_vuln_id(vulnerability_data),
                category=classification_data.get('category', 'Unknown'),
                severity=ThreatLevel(classification_data.get('severity', 'medium')),
                cvss_score=classification_data.get('cvss_score'),
                cve_id=classification_data.get('cve_id'),
                description=classification_data.get('description', ''),
                affected_systems=classification_data.get('affected_systems', []),
                exploit_complexity=classification_data.get('exploit_complexity', 'medium'),
                remediation_priority=classification_data.get('remediation_priority', 3),
                estimated_fix_time=classification_data.get('estimated_fix_time', 'Unknown'),
                business_impact=classification_data.get('business_impact', 'Medium'),
                classification_time_ms=classification_time
            )
            
        except Exception as e:
            self.logger.error(f"Vulnerability classification failed: {str(e)}")
            return self._create_fallback_classification(vulnerability_data, time.time() - start_time)
    
    def _generate_vuln_id(self, vulnerability_data: Dict[str, Any]) -> str:
        """Generate unique vulnerability ID"""
        content = f"{json.dumps(vulnerability_data, sort_keys=True)}{datetime.now().isoformat()}"
        return f"vuln_{hashlib.sha256(content.encode()).hexdigest()[:12]}"
    
    def _create_fallback_classification(self, vulnerability_data: Dict[str, Any], elapsed_time: float) -> VulnerabilityClassification:
        """Create fallback classification when analysis fails"""
        return VulnerabilityClassification(
            vuln_id=self._generate_vuln_id(vulnerability_data),
            category="Classification Failed",
            severity=ThreatLevel.MEDIUM,
            cvss_score=None,
            cve_id=None,
            description="Vulnerability classification could not be completed",
            affected_systems=[],
            exploit_complexity="unknown",
            remediation_priority=3,
            estimated_fix_time="Unknown",
            business_impact="Unknown",
            classification_time_ms=elapsed_time * 1000
        )


class RemediationAdvisor(BaseGroqAnalyzer):
    """Fast security improvement recommendations"""
    
    def get_system_prompt(self) -> str:
        return """You are an expert security remediation advisor specializing in:
- Rapid remediation planning and prioritization
- Code fix generation and configuration changes
- Automation opportunity identification
- Cost-effective security improvements
- Risk-based remediation strategies

Generate remediation plans with:
1. Step-by-step remediation procedures
2. Code fixes and configuration changes
3. Verification and testing steps
4. Rollback procedures
5. Automation opportunities
6. Cost and timeline estimates

Provide JSON responses with priority, estimated_effort, steps, code_fixes, configuration_changes, verification_steps, rollback_plan, automation_available, cost_estimate, and timeline."""
    
    async def generate_remediation_plan(self, vulnerability: VulnerabilityClassification, context: Dict[str, Any]) -> RemediationPlan:
        """Generate intelligent remediation plan"""
        start_time = time.time()
        
        prompt = f"""
Generate a comprehensive remediation plan for the following vulnerability:

VULNERABILITY:
- ID: {vulnerability.vuln_id}
- Category: {vulnerability.category}
- Severity: {vulnerability.severity.value}
- Description: {vulnerability.description}
- Affected Systems: {vulnerability.affected_systems}
- CVSS Score: {vulnerability.cvss_score}

ENVIRONMENT CONTEXT:
- Technology stack: {context.get('tech_stack', [])}
- Environment type: {context.get('environment', 'production')}
- Available resources: {context.get('resources', 'standard')}
- Compliance requirements: {context.get('compliance', [])}
- Maintenance windows: {context.get('maintenance_windows', [])}

Generate detailed remediation plan with:
1. Priority ranking (1-5)
2. Effort estimation (minimal/moderate/significant/extensive)
3. Step-by-step remediation procedures
4. Specific code fixes with examples
5. Configuration changes required
6. Verification and testing steps
7. Rollback procedures
8. Automation opportunities
9. Cost estimate if applicable
10. Implementation timeline

Focus on practical, implementable solutions with minimal business disruption.
"""
        
        try:
            response = await self._make_groq_request(prompt, context, stream=False)
            plan_data = self._parse_json_response(response['content'])
            
            return RemediationPlan(
                plan_id=self._generate_plan_id(vulnerability),
                vulnerability_id=vulnerability.vuln_id,
                priority=plan_data.get('priority', vulnerability.remediation_priority),
                estimated_effort=plan_data.get('estimated_effort', 'moderate'),
                steps=plan_data.get('steps', []),
                code_fixes=plan_data.get('code_fixes', []),
                configuration_changes=plan_data.get('configuration_changes', []),
                verification_steps=plan_data.get('verification_steps', []),
                rollback_plan=plan_data.get('rollback_plan', []),
                automation_available=plan_data.get('automation_available', False),
                cost_estimate=plan_data.get('cost_estimate'),
                timeline=plan_data.get('timeline', 'Unknown')
            )
            
        except Exception as e:
            self.logger.error(f"Remediation plan generation failed: {str(e)}")
            return self._create_fallback_plan(vulnerability)
    
    def _generate_plan_id(self, vulnerability: VulnerabilityClassification) -> str:
        """Generate unique plan ID"""
        content = f"{vulnerability.vuln_id}{datetime.now().isoformat()}"
        return f"plan_{hashlib.sha256(content.encode()).hexdigest()[:12]}"
    
    def _create_fallback_plan(self, vulnerability: VulnerabilityClassification) -> RemediationPlan:
        """Create fallback plan when generation fails"""
        return RemediationPlan(
            plan_id=self._generate_plan_id(vulnerability),
            vulnerability_id=vulnerability.vuln_id,
            priority=vulnerability.remediation_priority,
            estimated_effort="unknown",
            steps=[{"step": 1, "description": "Manual review required - automated plan generation failed"}],
            code_fixes=[],
            configuration_changes=[],
            verification_steps=["Manual verification required"],
            rollback_plan=["Document current state before changes"],
            automation_available=False,
            cost_estimate=None,
            timeline="Unknown"
        )


class GroqSpeechInterface:
    """Voice-to-security-command interface using Groq Speech"""
    
    def __init__(self, config: GroqConfiguration):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.recognizer = sr.Recognizer()
        self.microphone = sr.Microphone()
        self.tts_engine = pyttsx3.init()
        self.executor = ThreadPoolExecutor(max_workers=2)
        
        # Configure TTS
        self.tts_engine.setProperty('rate', config.voice_rate)
        self.tts_engine.setProperty('volume', config.voice_volume)
        
        # Security command mappings
        self.command_mappings = {
            'scan network': 'initiate_network_scan',
            'check threats': 'threat_assessment',
            'security status': 'get_security_status',
            'block ip': 'block_ip_address',
            'quarantine system': 'quarantine_system',
            'incident response': 'activate_incident_response',
            'vulnerability report': 'generate_vulnerability_report',
            'compliance check': 'run_compliance_check'
        }
    
    async def listen_for_commands(self) -> AsyncGenerator[Dict[str, Any], None]:
        """Listen for voice security commands"""
        if not self.config.speech_enabled:
            return
        
        self.logger.info("Starting voice command listener...")
        
        while True:
            try:
                # Listen for audio in background thread
                audio_data = await asyncio.get_event_loop().run_in_executor(
                    self.executor, self._capture_audio
                )
                
                if audio_data:
                    # Recognize speech
                    command_text = await asyncio.get_event_loop().run_in_executor(
                        self.executor, self._recognize_speech, audio_data
                    )
                    
                    if command_text:
                        # Parse security command
                        parsed_command = await self._parse_security_command(command_text)
                        
                        if parsed_command:
                            yield parsed_command
                            
                            # Provide voice feedback
                            await self._speak_response(f"Executing {parsed_command['action']}")
                
                # Brief pause between listening cycles
                await asyncio.sleep(0.1)
                
            except Exception as e:
                self.logger.error(f"Voice command processing error: {str(e)}")
                await asyncio.sleep(1)
    
    def _capture_audio(self) -> Optional[sr.AudioData]:
        """Capture audio from microphone"""
        try:
            with self.microphone as source:
                # Adjust for ambient noise
                self.recognizer.adjust_for_ambient_noise(source, duration=0.5)
                
                # Listen for audio with timeout
                audio = self.recognizer.listen(source, timeout=1, phrase_time_limit=5)
                return audio
                
        except sr.WaitTimeoutError:
            return None
        except Exception as e:
            self.logger.error(f"Audio capture error: {str(e)}")
            return None
    
    def _recognize_speech(self, audio_data: sr.AudioData) -> Optional[str]:
        """Recognize speech from audio data"""
        try:
            # Use Google Speech Recognition (can be replaced with Groq Speech when available)
            text = self.recognizer.recognize_google(audio_data, language='en-US')
            self.logger.debug(f"Recognized speech: {text}")
            return text.lower()
            
        except sr.UnknownValueError:
            return None
        except sr.RequestError as e:
            self.logger.error(f"Speech recognition error: {str(e)}")
            return None
    
    async def _parse_security_command(self, command_text: str) -> Optional[Dict[str, Any]]:
        """Parse natural language security command"""
        # Check for direct command mappings
        for phrase, action in self.command_mappings.items():
            if phrase in command_text:
                return {
                    'action': action,
                    'original_text': command_text,
                    'confidence': 0.9,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
        
        # Use Groq for complex command parsing
        try:
            groq_client = AsyncGroq(api_key=self.config.api_key)
            
            response = await groq_client.chat.completions.create(
                model="llama3-8b-8192",  # Faster model for command parsing
                messages=[
                    {
                        "role": "system",
                        "content": """You are a security command parser. Parse natural language into security actions.
                        
Available actions: initiate_network_scan, threat_assessment, get_security_status, block_ip_address, quarantine_system, activate_incident_response, generate_vulnerability_report, run_compliance_check

Return JSON with: action, parameters, confidence"""
                    },
                    {
                        "role": "user",
                        "content": f"Parse this security command: {command_text}"
                    }
                ],
                temperature=0.1,
                max_tokens=200
            )
            
            parsed = json.loads(response.choices[0].message.content)
            parsed['original_text'] = command_text
            parsed['timestamp'] = datetime.now(timezone.utc).isoformat()
            
            return parsed
            
        except Exception as e:
            self.logger.error(f"Command parsing error: {str(e)}")
            return None
    
    async def _speak_response(self, text: str):
        """Provide voice feedback"""
        if not self.config.speech_enabled:
            return
        
        try:
            await asyncio.get_event_loop().run_in_executor(
                self.executor, self._tts_speak, text
            )
        except Exception as e:
            self.logger.error(f"TTS error: {str(e)}")
    
    def _tts_speak(self, text: str):
        """Text-to-speech synthesis"""
        self.tts_engine.say(text)
        self.tts_engine.runAndWait()


class GroqSecurityEngine:
    """Main Groq-powered security intelligence engine"""
    
    def __init__(self, config: GroqConfiguration):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize specialized analyzers
        self.threat_analyzer = ThreatAnalysisEngine(config)
        self.decision_maker = SecurityDecisionMaker(config)
        self.vuln_classifier = VulnerabilityClassifier(config)
        self.remediation_advisor = RemediationAdvisor(config)
        self.speech_interface = GroqSpeechInterface(config)
        
        # Performance monitoring
        self.global_performance = PerformanceMonitor()
        
    async def initialize(self):
        """Initialize all engine components"""
        components = [
            self.threat_analyzer,
            self.decision_maker,
            self.vuln_classifier,
            self.remediation_advisor
        ]
        
        await asyncio.gather(*[component.initialize() for component in components])
        self.logger.info("Groq Security Engine initialized successfully")
    
    async def comprehensive_security_analysis(self, data: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive security analysis with sub-500ms target"""
        start_time = time.time()
        
        try:
            # Run analyses in parallel for maximum speed
            tasks = []
            
            # Threat analysis
            if 'indicators' in data:
                tasks.append(
                    asyncio.create_task(
                        self.threat_analyzer.analyze_threat(data['indicators'], context),
                        name="threat_analysis"
                    )
                )
            
            # Vulnerability classification
            if 'vulnerability' in data:
                tasks.append(
                    asyncio.create_task(
                        self.vuln_classifier.classify_vulnerability(data['vulnerability'], context),
                        name="vulnerability_classification"
                    )
                )
            
            # Security decision
            if 'scenario' in data:
                tasks.append(
                    asyncio.create_task(
                        self.decision_maker.make_security_decision(data['scenario'], context),
                        name="security_decision"
                    )
                )
            
            # Wait for all analyses to complete
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            analysis_results = {}
            for i, result in enumerate(results):
                task_name = tasks[i].get_name()
                if isinstance(result, Exception):
                    self.logger.error(f"{task_name} failed: {str(result)}")
                    analysis_results[task_name] = {"error": str(result)}
                else:
                    analysis_results[task_name] = result.to_dict() if hasattr(result, 'to_dict') else result
            
            # Generate remediation if vulnerability was classified
            if 'vulnerability_classification' in analysis_results and not isinstance(results[1], Exception):
                remediation = await self.remediation_advisor.generate_remediation_plan(results[1], context)
                analysis_results['remediation_plan'] = remediation.to_dict()
            
            total_time = (time.time() - start_time) * 1000
            self.global_performance.record_request(total_time, True)
            
            return {
                'analysis_results': analysis_results,
                'performance': {
                    'total_time_ms': total_time,
                    'target_met': total_time < self.config.performance_target_ms,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                },
                'engine_stats': self.get_performance_statistics()
            }
            
        except Exception as e:
            total_time = (time.time() - start_time) * 1000
            self.global_performance.record_request(total_time, False)
            self.logger.error(f"Comprehensive analysis failed: {str(e)}")
            raise
    
    async def stream_security_analysis(self, data: Dict[str, Any], context: Dict[str, Any]) -> AsyncGenerator[str, None]:
        """Stream real-time security analysis updates"""
        if 'indicators' in data:
            yield "🔍 Starting threat analysis...\n"
            async for chunk in await self.threat_analyzer.stream_threat_analysis(data['indicators'], context):
                yield chunk
    
    def get_performance_statistics(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics"""
        return {
            'global_performance': self.global_performance.get_performance_stats(),
            'component_performance': {
                'threat_analyzer': self.threat_analyzer.performance.get_performance_stats(),
                'decision_maker': self.decision_maker.performance.get_performance_stats(),
                'vuln_classifier': self.vuln_classifier.performance.get_performance_stats(),
                'remediation_advisor': self.remediation_advisor.performance.get_performance_stats()
            },
            'cache_performance': {
                'threat_analyzer': {
                    'cache_hit_rate': getattr(self.threat_analyzer.cache, 'hit_rate', 0),
                },
                'decision_maker': {
                    'cache_hit_rate': getattr(self.decision_maker.cache, 'hit_rate', 0),
                }
            }
        }
    
    async def voice_command_handler(self) -> AsyncGenerator[Dict[str, Any], None]:
        """Handle voice security commands"""
        if not self.config.speech_enabled:
            self.logger.warning("Speech interface not enabled")
            return
        
        async for command in self.speech_interface.listen_for_commands():
            try:
                # Execute security command
                result = await self._execute_voice_command(command)
                yield {
                    'command': command,
                    'result': result,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
            except Exception as e:
                self.logger.error(f"Voice command execution failed: {str(e)}")
                yield {
                    'command': command,
                    'error': str(e),
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
    
    async def _execute_voice_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Execute parsed voice command"""
        action = command.get('action')
        parameters = command.get('parameters', {})
        
        if action == 'threat_assessment':
            # Perform quick threat assessment
            indicators = parameters.get('indicators', ['general_assessment'])
            result = await self.threat_analyzer.analyze_threat(indicators, {})
            return result.to_dict()
        
        elif action == 'get_security_status':
            # Return current security status
            return {
                'status': 'operational',
                'performance': self.get_performance_statistics(),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        else:
            return {
                'message': f"Command {action} queued for execution",
                'parameters': parameters
            }


# Example usage and configuration
async def main():
    """Example usage of Groq Security Engine"""
    
    # Configure Groq engine
    config = GroqConfiguration(
        api_key="your_groq_api_key",
        model="llama3-70b-8192",
        temperature=0.1,
        max_tokens=2048,
        timeout=10,
        stream=True,
        performance_target_ms=500,
        speech_enabled=False  # Enable for voice commands
    )
    
    # Initialize engine
    engine = GroqSecurityEngine(config)
    await engine.initialize()
    
    try:
        # Example: Comprehensive security analysis
        analysis_data = {
            'indicators': ['suspicious_ip_192.168.1.100', 'malware_hash_abc123'],
            'vulnerability': {
                'type': 'sql_injection',
                'location': '/api/users',
                'severity': 'high'
            },
            'scenario': {
                'event': 'multiple_failed_logins',
                'source_ip': '192.168.1.100',
                'user': 'admin',
                'attempts': 10
            }
        }
        
        context = {
            'environment': 'production',
            'criticality': 'high',
            'compliance': ['SOC2', 'ISO27001']
        }
        
        # Perform analysis
        results = await engine.comprehensive_security_analysis(analysis_data, context)
        
        print(f"Analysis completed in {results['performance']['total_time_ms']:.2f}ms")
        print(f"Target met: {results['performance']['target_met']}")
        
        # Example: Streaming analysis
        print("\nStreaming analysis:")
        async for chunk in engine.stream_security_analysis(analysis_data, context):
            print(chunk, end='')
        
        # Performance statistics
        stats = engine.get_performance_statistics()
        print(f"\nPerformance stats: {stats['global_performance']}")
        
    finally:
        # Cleanup would go here
        pass


if __name__ == "__main__":
    asyncio.run(main())