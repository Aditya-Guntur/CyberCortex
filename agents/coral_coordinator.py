"""
Coral Protocol Multi-Agent Coordination System

Advanced multi-agent coordination using Coral Protocol for secure, scalable,
and intelligent security operations with dynamic team formation and encrypted
agent-to-agent communication.
"""

import asyncio
import json
import logging
import time
import hashlib
import secrets
from typing import Dict, List, Optional, Any, Set, Callable, AsyncGenerator, Union, Tuple
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict, field
from enum import Enum
from abc import ABC, abstractmethod
import aiohttp
import redis.asyncio as redis
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import uuid
from concurrent.futures import ThreadPoolExecutor
import threading


class AgentStatus(Enum):
    """Agent operational status"""
    ONLINE = "online"
    OFFLINE = "offline"
    BUSY = "busy"
    ERROR = "error"
    MAINTENANCE = "maintenance"
    INITIALIZING = "initializing"


class MessageType(Enum):
    """Types of inter-agent messages"""
    TASK_REQUEST = "task_request"
    TASK_RESPONSE = "task_response"
    STATUS_UPDATE = "status_update"
    CAPABILITY_ANNOUNCEMENT = "capability_announcement"
    TEAM_FORMATION = "team_formation"
    COORDINATION = "coordination"
    EMERGENCY = "emergency"
    HEARTBEAT = "heartbeat"
    AUTHENTICATION = "authentication"


class TaskPriority(Enum):
    """Task priority levels"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    BACKGROUND = 5


class TeamRole(Enum):
    """Roles within agent teams"""
    LEADER = "leader"
    SPECIALIST = "specialist"
    COORDINATOR = "coordinator"
    EXECUTOR = "executor"
    MONITOR = "monitor"


@dataclass
class AgentCapability:
    """Agent capability definition"""
    name: str
    version: str
    description: str
    parameters: Dict[str, Any]
    performance_metrics: Dict[str, float]
    resource_requirements: Dict[str, Any]
    security_clearance: str
    last_updated: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['last_updated'] = self.last_updated.isoformat()
        return data


@dataclass
class SecurityMessage:
    """Secure inter-agent message"""
    message_id: str
    sender_id: str
    recipient_id: str
    message_type: MessageType
    payload: Dict[str, Any]
    timestamp: datetime
    priority: TaskPriority
    encrypted: bool = True
    signature: Optional[str] = None
    correlation_id: Optional[str] = None
    expires_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['message_type'] = self.message_type.value
        data['priority'] = self.priority.value
        data['timestamp'] = self.timestamp.isoformat()
        if self.expires_at:
            data['expires_at'] = self.expires_at.isoformat()
        return data


@dataclass
class AgentProfile:
    """Comprehensive agent profile"""
    agent_id: str
    name: str
    agent_type: str
    status: AgentStatus
    capabilities: List[AgentCapability]
    current_load: float  # 0.0 to 1.0
    max_concurrent_tasks: int
    security_clearance: str
    trust_score: float  # 0.0 to 1.0
    performance_history: Dict[str, Any]
    last_heartbeat: datetime
    endpoint: str
    public_key: str
    team_memberships: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['status'] = self.status.value
        data['last_heartbeat'] = self.last_heartbeat.isoformat()
        data['capabilities'] = [cap.to_dict() for cap in self.capabilities]
        return data


@dataclass
class TeamConfiguration:
    """Team formation configuration"""
    team_id: str
    mission: str
    required_capabilities: List[str]
    preferred_agents: List[str]
    max_team_size: int
    min_team_size: int
    security_clearance_required: str
    formation_strategy: str  # "optimal", "fast", "redundant"
    coordination_pattern: str  # "hierarchical", "peer-to-peer", "hybrid"
    duration: Optional[timedelta] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        if self.duration:
            data['duration'] = self.duration.total_seconds()
        return data


class SecurityCrypto:
    """Cryptographic utilities for secure agent communication"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._key_cache: Dict[str, Any] = {}
        self._lock = threading.Lock()
    
    def generate_agent_keypair(self) -> Tuple[str, str]:
        """Generate RSA keypair for agent"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        public_key = private_key.public_key()
        
        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return private_pem, public_pem
    
    def encrypt_message(self, message: str, public_key_pem: str) -> str:
        """Encrypt message with recipient's public key"""
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
            
            # Encrypt with RSA-OAEP
            encrypted = public_key.encrypt(
                message.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return base64.b64encode(encrypted).decode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Message encryption failed: {str(e)}")
            raise
    
    def decrypt_message(self, encrypted_message: str, private_key_pem: str) -> str:
        """Decrypt message with private key"""
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None
            )
            
            encrypted_data = base64.b64decode(encrypted_message.encode('utf-8'))
            
            # Decrypt with RSA-OAEP
            decrypted = private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return decrypted.decode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Message decryption failed: {str(e)}")
            raise
    
    def sign_message(self, message: str, private_key_pem: str) -> str:
        """Sign message with private key"""
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None
            )
            
            signature = private_key.sign(
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return base64.b64encode(signature).decode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Message signing failed: {str(e)}")
            raise
    
    def verify_signature(self, message: str, signature: str, public_key_pem: str) -> bool:
        """Verify message signature"""
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
            signature_bytes = base64.b64decode(signature.encode('utf-8'))
            
            public_key.verify(
                signature_bytes,
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
            
        except Exception:
            return False


class SecureMessageBus:
    """Secure message bus for inter-agent communication"""
    
    def __init__(self, redis_config: Dict[str, Any]):
        self.redis_config = redis_config
        self.redis_client: Optional[redis.Redis] = None
        self.crypto = SecurityCrypto()
        self.logger = logging.getLogger(__name__)
        self.message_handlers: Dict[str, Callable] = {}
        self.subscriptions: Dict[str, Set[str]] = {}
        self._running = False
        
    async def initialize(self):
        """Initialize message bus"""
        try:
            self.redis_client = redis.Redis(
                host=self.redis_config.get('host', 'localhost'),
                port=self.redis_config.get('port', 6379),
                db=self.redis_config.get('db', 0),
                decode_responses=True
            )
            
            await self.redis_client.ping()
            self.logger.info("Secure message bus initialized")
            
        except Exception as e:
            self.logger.error(f"Message bus initialization failed: {str(e)}")
            raise
    
    async def send_message(self, message: SecurityMessage, recipient_public_key: str, sender_private_key: str):
        """Send encrypted and signed message"""
        try:
            # Serialize message payload
            payload_json = json.dumps(message.payload)
            
            # Encrypt payload if required
            if message.encrypted:
                encrypted_payload = self.crypto.encrypt_message(payload_json, recipient_public_key)
                message.payload = {"encrypted": encrypted_payload}
            
            # Sign message
            message_content = json.dumps(message.to_dict(), sort_keys=True)
            message.signature = self.crypto.sign_message(message_content, sender_private_key)
            
            # Publish to Redis channel
            channel = f"agent:{message.recipient_id}"
            await self.redis_client.publish(channel, json.dumps(message.to_dict()))
            
            # Store in message queue for reliability
            queue_key = f"queue:{message.recipient_id}"
            await self.redis_client.lpush(queue_key, json.dumps(message.to_dict()))
            
            # Set expiration if specified
            if message.expires_at:
                ttl = int((message.expires_at - datetime.now(timezone.utc)).total_seconds())
                await self.redis_client.expire(queue_key, ttl)
            
            self.logger.debug(f"Message {message.message_id} sent to {message.recipient_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to send message: {str(e)}")
            raise
    
    async def subscribe_to_messages(self, agent_id: str, handler: Callable[[SecurityMessage], None]):
        """Subscribe to messages for an agent"""
        self.message_handlers[agent_id] = handler
        
        if agent_id not in self.subscriptions:
            self.subscriptions[agent_id] = set()
        
        # Start message listener if not running
        if not self._running:
            asyncio.create_task(self._message_listener())
            self._running = True
    
    async def _message_listener(self):
        """Background message listener"""
        try:
            pubsub = self.redis_client.pubsub()
            
            # Subscribe to all agent channels
            for agent_id in self.subscriptions:
                await pubsub.subscribe(f"agent:{agent_id}")
            
            async for message in pubsub.listen():
                if message['type'] == 'message':
                    await self._handle_received_message(message)
                    
        except Exception as e:
            self.logger.error(f"Message listener error: {str(e)}")
    
    async def _handle_received_message(self, redis_message: Dict[str, Any]):
        """Handle received message"""
        try:
            message_data = json.loads(redis_message['data'])
            message = SecurityMessage(**message_data)
            
            # Extract recipient ID from channel
            channel = redis_message['channel']
            recipient_id = channel.split(':')[1]
            
            # Call handler if registered
            if recipient_id in self.message_handlers:
                handler = self.message_handlers[recipient_id]
                await handler(message)
            
        except Exception as e:
            self.logger.error(f"Failed to handle received message: {str(e)}")
    
    async def get_queued_messages(self, agent_id: str, limit: int = 10) -> List[SecurityMessage]:
        """Get queued messages for agent"""
        try:
            queue_key = f"queue:{agent_id}"
            messages = await self.redis_client.lrange(queue_key, 0, limit - 1)
            
            result = []
            for msg_json in messages:
                message_data = json.loads(msg_json)
                message = SecurityMessage(**message_data)
                result.append(message)
                
                # Remove processed message
                await self.redis_client.lrem(queue_key, 1, msg_json)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to get queued messages: {str(e)}")
            return []


class AgentCapabilityRegistry:
    """Registry for agent capabilities and discovery"""
    
    def __init__(self, redis_config: Dict[str, Any]):
        self.redis_config = redis_config
        self.redis_client: Optional[redis.Redis] = None
        self.logger = logging.getLogger(__name__)
        
    async def initialize(self):
        """Initialize capability registry"""
        try:
            self.redis_client = redis.Redis(
                host=self.redis_config.get('host', 'localhost'),
                port=self.redis_config.get('port', 6379),
                db=self.redis_config.get('db', 1),  # Different DB for capabilities
                decode_responses=True
            )
            
            await self.redis_client.ping()
            self.logger.info("Agent capability registry initialized")
            
        except Exception as e:
            self.logger.error(f"Capability registry initialization failed: {str(e)}")
            raise
    
    async def register_agent(self, profile: AgentProfile):
        """Register agent and its capabilities"""
        try:
            # Store agent profile
            profile_key = f"agent:{profile.agent_id}"
            await self.redis_client.hset(
                profile_key,
                mapping={
                    "profile": json.dumps(profile.to_dict()),
                    "last_updated": datetime.now(timezone.utc).isoformat()
                }
            )
            
            # Index capabilities for discovery
            for capability in profile.capabilities:
                capability_key = f"capability:{capability.name}"
                await self.redis_client.sadd(capability_key, profile.agent_id)
            
            # Index by agent type
            type_key = f"type:{profile.agent_type}"
            await self.redis_client.sadd(type_key, profile.agent_id)
            
            # Index by security clearance
            clearance_key = f"clearance:{profile.security_clearance}"
            await self.redis_client.sadd(clearance_key, profile.agent_id)
            
            self.logger.info(f"Agent {profile.agent_id} registered successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to register agent: {str(e)}")
            raise
    
    async def update_agent_status(self, agent_id: str, status: AgentStatus, current_load: float):
        """Update agent status and load"""
        try:
            profile_key = f"agent:{agent_id}"
            
            # Get current profile
            profile_data = await self.redis_client.hget(profile_key, "profile")
            if not profile_data:
                raise ValueError(f"Agent {agent_id} not found")
            
            profile_dict = json.loads(profile_data)
            profile_dict['status'] = status.value
            profile_dict['current_load'] = current_load
            profile_dict['last_heartbeat'] = datetime.now(timezone.utc).isoformat()
            
            # Update profile
            await self.redis_client.hset(
                profile_key,
                mapping={
                    "profile": json.dumps(profile_dict),
                    "last_updated": datetime.now(timezone.utc).isoformat()
                }
            )
            
        except Exception as e:
            self.logger.error(f"Failed to update agent status: {str(e)}")
            raise
    
    async def discover_agents_by_capability(self, capability_name: str, 
                                          security_clearance: Optional[str] = None,
                                          max_load: float = 0.8) -> List[AgentProfile]:
        """Discover agents with specific capability"""
        try:
            capability_key = f"capability:{capability_name}"
            agent_ids = await self.redis_client.smembers(capability_key)
            
            agents = []
            for agent_id in agent_ids:
                profile = await self.get_agent_profile(agent_id)
                if profile:
                    # Filter by security clearance
                    if security_clearance and profile.security_clearance != security_clearance:
                        continue
                    
                    # Filter by load
                    if profile.current_load > max_load:
                        continue
                    
                    # Filter by status
                    if profile.status not in [AgentStatus.ONLINE, AgentStatus.BUSY]:
                        continue
                    
                    agents.append(profile)
            
            # Sort by trust score and load
            agents.sort(key=lambda a: (a.trust_score, -a.current_load), reverse=True)
            
            return agents
            
        except Exception as e:
            self.logger.error(f"Agent discovery failed: {str(e)}")
            return []
    
    async def get_agent_profile(self, agent_id: str) -> Optional[AgentProfile]:
        """Get agent profile by ID"""
        try:
            profile_key = f"agent:{agent_id}"
            profile_data = await self.redis_client.hget(profile_key, "profile")
            
            if profile_data:
                profile_dict = json.loads(profile_data)
                
                # Convert capabilities back to objects
                capabilities = []
                for cap_dict in profile_dict.get('capabilities', []):
                    cap_dict['last_updated'] = datetime.fromisoformat(cap_dict['last_updated'])
                    capabilities.append(AgentCapability(**cap_dict))
                
                profile_dict['capabilities'] = capabilities
                profile_dict['status'] = AgentStatus(profile_dict['status'])
                profile_dict['last_heartbeat'] = datetime.fromisoformat(profile_dict['last_heartbeat'])
                
                return AgentProfile(**profile_dict)
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to get agent profile: {str(e)}")
            return None
    
    async def get_all_agents(self, status_filter: Optional[List[AgentStatus]] = None) -> List[AgentProfile]:
        """Get all registered agents"""
        try:
            # Get all agent keys
            agent_keys = await self.redis_client.keys("agent:*")
            
            agents = []
            for key in agent_keys:
                agent_id = key.split(':')[1]
                profile = await self.get_agent_profile(agent_id)
                
                if profile:
                    if status_filter and profile.status not in status_filter:
                        continue
                    agents.append(profile)
            
            return agents
            
        except Exception as e:
            self.logger.error(f"Failed to get all agents: {str(e)}")
            return []


class TeamFormationEngine:
    """Intelligent team formation for complex security scenarios"""
    
    def __init__(self, capability_registry: AgentCapabilityRegistry):
        self.capability_registry = capability_registry
        self.logger = logging.getLogger(__name__)
        self.formation_strategies = {
            'optimal': self._optimal_formation,
            'fast': self._fast_formation,
            'redundant': self._redundant_formation
        }
    
    async def form_team(self, config: TeamConfiguration) -> Optional['AgentTeam']:
        """Form agent team based on configuration"""
        try:
            strategy = self.formation_strategies.get(config.formation_strategy, self._optimal_formation)
            
            # Get candidate agents
            candidates = await self._get_candidate_agents(config)
            
            if len(candidates) < config.min_team_size:
                self.logger.warning(f"Insufficient agents for team formation: {len(candidates)} < {config.min_team_size}")
                return None
            
            # Apply formation strategy
            selected_agents = await strategy(candidates, config)
            
            if len(selected_agents) < config.min_team_size:
                self.logger.warning(f"Team formation failed: {len(selected_agents)} < {config.min_team_size}")
                return None
            
            # Create team
            team = AgentTeam(
                team_id=config.team_id,
                mission=config.mission,
                members=selected_agents,
                coordination_pattern=config.coordination_pattern,
                created_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + config.duration if config.duration else None
            )
            
            self.logger.info(f"Team {config.team_id} formed with {len(selected_agents)} agents")
            return team
            
        except Exception as e:
            self.logger.error(f"Team formation failed: {str(e)}")
            return None
    
    async def _get_candidate_agents(self, config: TeamConfiguration) -> List[AgentProfile]:
        """Get candidate agents for team formation"""
        candidates = set()
        
        # Get agents by required capabilities
        for capability in config.required_capabilities:
            agents = await self.capability_registry.discover_agents_by_capability(
                capability,
                security_clearance=config.security_clearance_required
            )
            candidates.update(agents)
        
        # Add preferred agents if they meet requirements
        for agent_id in config.preferred_agents:
            agent = await self.capability_registry.get_agent_profile(agent_id)
            if agent and self._agent_meets_requirements(agent, config):
                candidates.add(agent)
        
        return list(candidates)
    
    def _agent_meets_requirements(self, agent: AgentProfile, config: TeamConfiguration) -> bool:
        """Check if agent meets team requirements"""
        # Check security clearance
        if agent.security_clearance != config.security_clearance_required:
            return False
        
        # Check status
        if agent.status not in [AgentStatus.ONLINE, AgentStatus.BUSY]:
            return False
        
        # Check capabilities
        agent_capabilities = {cap.name for cap in agent.capabilities}
        required_capabilities = set(config.required_capabilities)
        
        # Agent should have at least one required capability
        return bool(agent_capabilities.intersection(required_capabilities))
    
    async def _optimal_formation(self, candidates: List[AgentProfile], config: TeamConfiguration) -> List[AgentProfile]:
        """Optimal team formation strategy"""
        # Score agents based on multiple factors
        scored_agents = []
        
        for agent in candidates:
            score = self._calculate_agent_score(agent, config)
            scored_agents.append((agent, score))
        
        # Sort by score (descending)
        scored_agents.sort(key=lambda x: x[1], reverse=True)
        
        # Select top agents ensuring capability coverage
        selected = []
        covered_capabilities = set()
        required_capabilities = set(config.required_capabilities)
        
        # First pass: ensure all required capabilities are covered
        for agent, score in scored_agents:
            if len(selected) >= config.max_team_size:
                break
            
            agent_capabilities = {cap.name for cap in agent.capabilities}
            new_capabilities = agent_capabilities.intersection(required_capabilities) - covered_capabilities
            
            if new_capabilities or len(selected) < config.min_team_size:
                selected.append(agent)
                covered_capabilities.update(agent_capabilities)
        
        return selected
    
    async def _fast_formation(self, candidates: List[AgentProfile], config: TeamConfiguration) -> List[AgentProfile]:
        """Fast team formation strategy"""
        # Simple selection based on availability and basic scoring
        available_agents = [agent for agent in candidates if agent.current_load < 0.7]
        
        # Sort by trust score and select
        available_agents.sort(key=lambda a: a.trust_score, reverse=True)
        
        return available_agents[:config.max_team_size]
    
    async def _redundant_formation(self, candidates: List[AgentProfile], config: TeamConfiguration) -> List[AgentProfile]:
        """Redundant team formation strategy"""
        # Ensure multiple agents for each capability
        capability_agents = {}
        
        for agent in candidates:
            for capability in agent.capabilities:
                if capability.name in config.required_capabilities:
                    if capability.name not in capability_agents:
                        capability_agents[capability.name] = []
                    capability_agents[capability.name].append(agent)
        
        # Select multiple agents per capability
        selected = set()
        for capability, agents in capability_agents.items():
            # Sort by trust score and select top 2-3
            agents.sort(key=lambda a: a.trust_score, reverse=True)
            selected.update(agents[:min(3, len(agents))])
        
        return list(selected)[:config.max_team_size]
    
    def _calculate_agent_score(self, agent: AgentProfile, config: TeamConfiguration) -> float:
        """Calculate agent score for team formation"""
        score = 0.0
        
        # Trust score (0-1)
        score += agent.trust_score * 0.3
        
        # Load factor (lower is better)
        score += (1.0 - agent.current_load) * 0.2
        
        # Capability match
        agent_capabilities = {cap.name for cap in agent.capabilities}
        required_capabilities = set(config.required_capabilities)
        capability_match = len(agent_capabilities.intersection(required_capabilities)) / len(required_capabilities)
        score += capability_match * 0.3
        
        # Performance history
        avg_performance = agent.performance_history.get('average_success_rate', 0.5)
        score += avg_performance * 0.2
        
        return score


@dataclass
class AgentTeam:
    """Agent team for coordinated security operations"""
    team_id: str
    mission: str
    members: List[AgentProfile]
    coordination_pattern: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    leader_id: Optional[str] = None
    status: str = "active"
    
    def __post_init__(self):
        """Initialize team after creation"""
        if not self.leader_id and self.members:
            # Select leader based on trust score
            leader = max(self.members, key=lambda a: a.trust_score)
            self.leader_id = leader.agent_id
    
    def get_member_by_id(self, agent_id: str) -> Optional[AgentProfile]:
        """Get team member by ID"""
        for member in self.members:
            if member.agent_id == agent_id:
                return member
        return None
    
    def get_members_by_capability(self, capability_name: str) -> List[AgentProfile]:
        """Get team members with specific capability"""
        result = []
        for member in self.members:
            for capability in member.capabilities:
                if capability.name == capability_name:
                    result.append(member)
                    break
        return result
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'team_id': self.team_id,
            'mission': self.mission,
            'members': [member.to_dict() for member in self.members],
            'coordination_pattern': self.coordination_pattern,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'leader_id': self.leader_id,
            'status': self.status
        }


class SecurityAgent(ABC):
    """Base class for security agents"""
    
    def __init__(self, agent_id: str, name: str, agent_type: str, 
                 capabilities: List[AgentCapability], security_clearance: str = "standard"):
        self.agent_id = agent_id
        self.name = name
        self.agent_type = agent_type
        self.capabilities = capabilities
        self.security_clearance = security_clearance
        self.status = AgentStatus.INITIALIZING
        self.current_load = 0.0
        self.max_concurrent_tasks = 5
        self.trust_score = 1.0
        self.performance_history = {}
        self.last_heartbeat = datetime.now(timezone.utc)
        self.endpoint = f"agent://{agent_id}"
        self.team_memberships: List[str] = []
        
        # Cryptographic keys
        self.crypto = SecurityCrypto()
        self.private_key, self.public_key = self.crypto.generate_agent_keypair()
        
        # Message handling
        self.message_handlers: Dict[MessageType, Callable] = {}
        self.active_tasks: Dict[str, Any] = {}
        
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Register default message handlers
        self._register_default_handlers()
    
    def _register_default_handlers(self):
        """Register default message handlers"""
        self.message_handlers[MessageType.HEARTBEAT] = self._handle_heartbeat
        self.message_handlers[MessageType.STATUS_UPDATE] = self._handle_status_update
        self.message_handlers[MessageType.TASK_REQUEST] = self._handle_task_request
        self.message_handlers[MessageType.AUTHENTICATION] = self._handle_authentication
    
    async def initialize(self, orchestrator: 'CoralOrchestrator'):
        """Initialize agent with orchestrator"""
        self.orchestrator = orchestrator
        
        # Register with capability registry
        profile = self.get_profile()
        await orchestrator.capability_registry.register_agent(profile)
        
        # Subscribe to messages
        await orchestrator.message_bus.subscribe_to_messages(
            self.agent_id, 
            self._handle_message
        )
        
        self.status = AgentStatus.ONLINE
        self.logger.info(f"Agent {self.agent_id} initialized successfully")
    
    def get_profile(self) -> AgentProfile:
        """Get agent profile"""
        return AgentProfile(
            agent_id=self.agent_id,
            name=self.name,
            agent_type=self.agent_type,
            status=self.status,
            capabilities=self.capabilities,
            current_load=self.current_load,
            max_concurrent_tasks=self.max_concurrent_tasks,
            security_clearance=self.security_clearance,
            trust_score=self.trust_score,
            performance_history=self.performance_history,
            last_heartbeat=self.last_heartbeat,
            endpoint=self.endpoint,
            public_key=self.public_key,
            team_memberships=self.team_memberships
        )
    
    async def _handle_message(self, message: SecurityMessage):
        """Handle received message"""
        try:
            # Verify message signature if present
            if message.signature:
                sender_profile = await self.orchestrator.capability_registry.get_agent_profile(message.sender_id)
                if sender_profile:
                    message_content = json.dumps(message.to_dict(), sort_keys=True)
                    if not self.crypto.verify_signature(message_content, message.signature, sender_profile.public_key):
                        self.logger.warning(f"Invalid signature from {message.sender_id}")
                        return
            
            # Decrypt payload if encrypted
            if message.encrypted and "encrypted" in message.payload:
                decrypted_payload = self.crypto.decrypt_message(
                    message.payload["encrypted"], 
                    self.private_key
                )
                message.payload = json.loads(decrypted_payload)
            
            # Route to appropriate handler
            handler = self.message_handlers.get(message.message_type)
            if handler:
                await handler(message)
            else:
                self.logger.warning(f"No handler for message type: {message.message_type}")
                
        except Exception as e:
            self.logger.error(f"Message handling failed: {str(e)}")
    
    async def _handle_heartbeat(self, message: SecurityMessage):
        """Handle heartbeat message"""
        self.last_heartbeat = datetime.now(timezone.utc)
        
        # Send heartbeat response
        response = SecurityMessage(
            message_id=str(uuid.uuid4()),
            sender_id=self.agent_id,
            recipient_id=message.sender_id,
            message_type=MessageType.HEARTBEAT,
            payload={"status": self.status.value, "load": self.current_load},
            timestamp=datetime.now(timezone.utc),
            priority=TaskPriority.LOW,
            correlation_id=message.message_id
        )
        
        await self._send_message(response, message.sender_id)
    
    async def _handle_status_update(self, message: SecurityMessage):
        """Handle status update message"""
        # Update local status if needed
        pass
    
    async def _handle_task_request(self, message: SecurityMessage):
        """Handle task request message"""
        try:
            task_data = message.payload
            task_id = task_data.get('task_id')
            
            # Check if we can handle this task
            if self.current_load >= 1.0:
                await self._send_task_response(message.sender_id, task_id, "rejected", "Agent at capacity")
                return
            
            # Execute task
            result = await self.execute_task(task_data)
            
            # Send response
            await self._send_task_response(message.sender_id, task_id, "completed", result)
            
        except Exception as e:
            await self._send_task_response(message.sender_id, task_id, "failed", str(e))
    
    async def _handle_authentication(self, message: SecurityMessage):
        """Handle authentication message"""
        # Implement authentication protocol
        pass
    
    async def _send_message(self, message: SecurityMessage, recipient_id: str):
        """Send message to another agent"""
        try:
            recipient_profile = await self.orchestrator.capability_registry.get_agent_profile(recipient_id)
            if recipient_profile:
                await self.orchestrator.message_bus.send_message(
                    message, 
                    recipient_profile.public_key, 
                    self.private_key
                )
            else:
                self.logger.error(f"Recipient {recipient_id} not found")
                
        except Exception as e:
            self.logger.error(f"Failed to send message: {str(e)}")
    
    async def _send_task_response(self, requester_id: str, task_id: str, status: str, result: Any):
        """Send task response"""
        response = SecurityMessage(
            message_id=str(uuid.uuid4()),
            sender_id=self.agent_id,
            recipient_id=requester_id,
            message_type=MessageType.TASK_RESPONSE,
            payload={
                "task_id": task_id,
                "status": status,
                "result": result,
                "timestamp": datetime.now(timezone.utc).isoformat()
            },
            timestamp=datetime.now(timezone.utc),
            priority=TaskPriority.MEDIUM
        )
        
        await self._send_message(response, requester_id)
    
    @abstractmethod
    async def execute_task(self, task_data: Dict[str, Any]) -> Any:
        """Execute assigned task"""
        pass
    
    async def join_team(self, team_id: str):
        """Join agent team"""
        if team_id not in self.team_memberships:
            self.team_memberships.append(team_id)
            self.logger.info(f"Agent {self.agent_id} joined team {team_id}")
    
    async def leave_team(self, team_id: str):
        """Leave agent team"""
        if team_id in self.team_memberships:
            self.team_memberships.remove(team_id)
            self.logger.info(f"Agent {self.agent_id} left team {team_id}")
    
    async def update_status(self, status: AgentStatus, load: Optional[float] = None):
        """Update agent status"""
        self.status = status
        if load is not None:
            self.current_load = load
        
        # Update in registry
        await self.orchestrator.capability_registry.update_agent_status(
            self.agent_id, status, self.current_load
        )


class CoralOrchestrator:
    """Main orchestrator for multi-agent coordination using Coral Protocol"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        redis_config = config.get('redis', {})
        self.message_bus = SecureMessageBus(redis_config)
        self.capability_registry = AgentCapabilityRegistry(redis_config)
        self.team_formation = TeamFormationEngine(self.capability_registry)
        
        # Agent management
        self.agents: Dict[str, SecurityAgent] = {}
        self.teams: Dict[str, AgentTeam] = {}
        
        # Coordination state
        self.coordination_status = {
            'active_teams': 0,
            'total_agents': 0,
            'active_tasks': 0,
            'message_throughput': 0.0
        }
        
        # Background tasks
        self._monitoring_task: Optional[asyncio.Task] = None
        self._heartbeat_task: Optional[asyncio.Task] = None
    
    async def initialize(self):
        """Initialize orchestrator"""
        try:
            # Initialize components
            await self.message_bus.initialize()
            await self.capability_registry.initialize()
            
            # Start background tasks
            self._monitoring_task = asyncio.create_task(self._monitoring_loop())
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
            
            self.logger.info("Coral Orchestrator initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Orchestrator initialization failed: {str(e)}")
            raise
    
    async def register_agent(self, agent: SecurityAgent):
        """Register agent with orchestrator"""
        try:
            await agent.initialize(self)
            self.agents[agent.agent_id] = agent
            
            self.coordination_status['total_agents'] = len(self.agents)
            self.logger.info(f"Agent {agent.agent_id} registered successfully")
            
        except Exception as e:
            self.logger.error(f"Agent registration failed: {str(e)}")
            raise
    
    async def create_team(self, config: TeamConfiguration) -> Optional[AgentTeam]:
        """Create agent team for mission"""
        try:
            team = await self.team_formation.form_team(config)
            
            if team:
                self.teams[team.team_id] = team
                
                # Notify team members
                for member in team.members:
                    if member.agent_id in self.agents:
                        await self.agents[member.agent_id].join_team(team.team_id)
                
                self.coordination_status['active_teams'] = len(self.teams)
                self.logger.info(f"Team {team.team_id} created with {len(team.members)} members")
            
            return team
            
        except Exception as e:
            self.logger.error(f"Team creation failed: {str(e)}")
            return None
    
    async def dissolve_team(self, team_id: str):
        """Dissolve agent team"""
        try:
            if team_id in self.teams:
                team = self.teams[team_id]
                
                # Notify team members
                for member in team.members:
                    if member.agent_id in self.agents:
                        await self.agents[member.agent_id].leave_team(team_id)
                
                del self.teams[team_id]
                self.coordination_status['active_teams'] = len(self.teams)
                
                self.logger.info(f"Team {team_id} dissolved")
            
        except Exception as e:
            self.logger.error(f"Team dissolution failed: {str(e)}")
    
    async def coordinate_team_task(self, team_id: str, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Coordinate task execution across team"""
        try:
            if team_id not in self.teams:
                raise ValueError(f"Team {team_id} not found")
            
            team = self.teams[team_id]
            
            # Distribute task based on coordination pattern
            if team.coordination_pattern == "hierarchical":
                return await self._hierarchical_coordination(team, task_data)
            elif team.coordination_pattern == "peer-to-peer":
                return await self._peer_to_peer_coordination(team, task_data)
            elif team.coordination_pattern == "hybrid":
                return await self._hybrid_coordination(team, task_data)
            else:
                raise ValueError(f"Unknown coordination pattern: {team.coordination_pattern}")
                
        except Exception as e:
            self.logger.error(f"Team task coordination failed: {str(e)}")
            raise
    
    async def _hierarchical_coordination(self, team: AgentTeam, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Hierarchical team coordination"""
        # Leader coordinates and delegates
        leader_id = team.leader_id
        if leader_id and leader_id in self.agents:
            leader = self.agents[leader_id]
            
            # Leader processes task and delegates subtasks
            result = await leader.execute_task(task_data)
            return {"coordination_pattern": "hierarchical", "result": result}
        else:
            raise ValueError("Team leader not available")
    
    async def _peer_to_peer_coordination(self, team: AgentTeam, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Peer-to-peer team coordination"""
        # All agents work on task collaboratively
        tasks = []
        for member in team.members:
            if member.agent_id in self.agents:
                agent = self.agents[member.agent_id]
                tasks.append(agent.execute_task(task_data))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Aggregate results
        successful_results = [r for r in results if not isinstance(r, Exception)]
        
        return {
            "coordination_pattern": "peer-to-peer",
            "results": successful_results,
            "success_rate": len(successful_results) / len(results) if results else 0
        }
    
    async def _hybrid_coordination(self, team: AgentTeam, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Hybrid team coordination"""
        # Combine hierarchical and peer-to-peer approaches
        # Leader coordinates, specialists work in parallel
        
        leader_id = team.leader_id
        if leader_id and leader_id in self.agents:
            leader = self.agents[leader_id]
            
            # Leader creates coordination plan
            coordination_plan = await leader.execute_task({
                **task_data,
                "coordination_role": "planning"
            })
            
            # Specialists execute in parallel
            specialist_tasks = []
            for member in team.members:
                if member.agent_id != leader_id and member.agent_id in self.agents:
                    agent = self.agents[member.agent_id]
                    specialist_tasks.append(agent.execute_task({
                        **task_data,
                        "coordination_plan": coordination_plan
                    }))
            
            specialist_results = await asyncio.gather(*specialist_tasks, return_exceptions=True)
            
            # Leader aggregates results
            final_result = await leader.execute_task({
                **task_data,
                "coordination_role": "aggregation",
                "specialist_results": specialist_results
            })
            
            return {
                "coordination_pattern": "hybrid",
                "coordination_plan": coordination_plan,
                "specialist_results": specialist_results,
                "final_result": final_result
            }
        else:
            raise ValueError("Team leader not available for hybrid coordination")
    
    async def _monitoring_loop(self):
        """Background monitoring loop"""
        while True:
            try:
                # Update coordination status
                await self._update_coordination_status()
                
                # Check team health
                await self._check_team_health()
                
                # Clean up expired teams
                await self._cleanup_expired_teams()
                
                await asyncio.sleep(30)  # Monitor every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Monitoring loop error: {str(e)}")
                await asyncio.sleep(60)
    
    async def _heartbeat_loop(self):
        """Background heartbeat loop"""
        while True:
            try:
                # Send heartbeats to all agents
                for agent_id, agent in self.agents.items():
                    heartbeat = SecurityMessage(
                        message_id=str(uuid.uuid4()),
                        sender_id="orchestrator",
                        recipient_id=agent_id,
                        message_type=MessageType.HEARTBEAT,
                        payload={"timestamp": datetime.now(timezone.utc).isoformat()},
                        timestamp=datetime.now(timezone.utc),
                        priority=TaskPriority.LOW
                    )
                    
                    await agent._handle_message(heartbeat)
                
                await asyncio.sleep(60)  # Heartbeat every minute
                
            except Exception as e:
                self.logger.error(f"Heartbeat loop error: {str(e)}")
                await asyncio.sleep(120)
    
    async def _update_coordination_status(self):
        """Update coordination status metrics"""
        try:
            # Count active agents
            active_agents = await self.capability_registry.get_all_agents([AgentStatus.ONLINE, AgentStatus.BUSY])
            
            # Update status
            self.coordination_status.update({
                'total_agents': len(self.agents),
                'active_agents': len(active_agents),
                'active_teams': len(self.teams),
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
            
        except Exception as e:
            self.logger.error(f"Status update failed: {str(e)}")
    
    async def _check_team_health(self):
        """Check health of active teams"""
        for team_id, team in self.teams.items():
            try:
                # Check if team members are still available
                available_members = 0
                for member in team.members:
                    profile = await self.capability_registry.get_agent_profile(member.agent_id)
                    if profile and profile.status in [AgentStatus.ONLINE, AgentStatus.BUSY]:
                        available_members += 1
                
                # If too few members available, consider team unhealthy
                if available_members < len(team.members) * 0.5:
                    self.logger.warning(f"Team {team_id} health degraded: {available_members}/{len(team.members)} members available")
                
            except Exception as e:
                self.logger.error(f"Team health check failed for {team_id}: {str(e)}")
    
    async def _cleanup_expired_teams(self):
        """Clean up expired teams"""
        now = datetime.now(timezone.utc)
        expired_teams = []
        
        for team_id, team in self.teams.items():
            if team.expires_at and now > team.expires_at:
                expired_teams.append(team_id)
        
        for team_id in expired_teams:
            await self.dissolve_team(team_id)
            self.logger.info(f"Expired team {team_id} cleaned up")
    
    def get_coordination_status(self) -> Dict[str, Any]:
        """Get current coordination status"""
        return self.coordination_status.copy()
    
    def get_team_status(self, team_id: str) -> Optional[Dict[str, Any]]:
        """Get team status"""
        if team_id in self.teams:
            return self.teams[team_id].to_dict()
        return None
    
    async def shutdown(self):
        """Gracefully shutdown orchestrator"""
        try:
            # Cancel background tasks
            if self._monitoring_task:
                self._monitoring_task.cancel()
            if self._heartbeat_task:
                self._heartbeat_task.cancel()
            
            # Dissolve all teams
            for team_id in list(self.teams.keys()):
                await self.dissolve_team(team_id)
            
            # Update agent statuses
            for agent in self.agents.values():
                await agent.update_status(AgentStatus.OFFLINE)
            
            self.logger.info("Coral Orchestrator shutdown complete")
            
        except Exception as e:
            self.logger.error(f"Shutdown error: {str(e)}")


# Example specialized security agents
class NetworkSecurityAgent(SecurityAgent):
    """Specialized agent for network security operations"""
    
    def __init__(self, agent_id: str):
        capabilities = [
            AgentCapability(
                name="network_scanning",
                version="1.0",
                description="Network discovery and port scanning",
                parameters={"max_hosts": 1000, "scan_types": ["tcp", "udp", "syn"]},
                performance_metrics={"avg_scan_time": 30.0, "accuracy": 0.95},
                resource_requirements={"cpu": 2, "memory": "1GB", "network": "high"},
                security_clearance="standard",
                last_updated=datetime.now(timezone.utc)
            ),
            AgentCapability(
                name="vulnerability_detection",
                version="1.0",
                description="Network vulnerability assessment",
                parameters={"cve_database": "latest", "scan_depth": "deep"},
                performance_metrics={"detection_rate": 0.92, "false_positive_rate": 0.05},
                resource_requirements={"cpu": 4, "memory": "2GB", "storage": "10GB"},
                security_clearance="standard",
                last_updated=datetime.now(timezone.utc)
            )
        ]
        
        super().__init__(agent_id, "Network Security Agent", "network_security", capabilities)
    
    async def execute_task(self, task_data: Dict[str, Any]) -> Any:
        """Execute network security task"""
        task_type = task_data.get('type')
        
        if task_type == "network_scan":
            return await self._perform_network_scan(task_data)
        elif task_type == "vulnerability_assessment":
            return await self._perform_vulnerability_assessment(task_data)
        else:
            raise ValueError(f"Unknown task type: {task_type}")
    
    async def _perform_network_scan(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform network scan"""
        # Simulate network scanning
        await asyncio.sleep(2)  # Simulate scan time
        
        return {
            "task_type": "network_scan",
            "target": task_data.get('target'),
            "discovered_hosts": ["192.168.1.1", "192.168.1.100", "192.168.1.200"],
            "open_ports": {"192.168.1.1": [22, 80, 443], "192.168.1.100": [80, 8080]},
            "scan_duration": 2.0,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    async def _perform_vulnerability_assessment(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform vulnerability assessment"""
        # Simulate vulnerability assessment
        await asyncio.sleep(5)  # Simulate assessment time
        
        return {
            "task_type": "vulnerability_assessment",
            "target": task_data.get('target'),
            "vulnerabilities": [
                {"cve": "CVE-2023-1234", "severity": "high", "description": "Remote code execution"},
                {"cve": "CVE-2023-5678", "severity": "medium", "description": "Information disclosure"}
            ],
            "assessment_duration": 5.0,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


# Example usage
async def main():
    """Example usage of Coral Protocol coordination"""
    
    # Configuration
    config = {
        'redis': {
            'host': 'localhost',
            'port': 6379,
            'db': 0
        }
    }
    
    # Initialize orchestrator
    orchestrator = CoralOrchestrator(config)
    await orchestrator.initialize()
    
    try:
        # Create and register agents
        network_agent = NetworkSecurityAgent("network_agent_001")
        await orchestrator.register_agent(network_agent)
        
        # Create team configuration
        team_config = TeamConfiguration(
            team_id="security_team_001",
            mission="Network security assessment",
            required_capabilities=["network_scanning", "vulnerability_detection"],
            preferred_agents=["network_agent_001"],
            max_team_size=3,
            min_team_size=1,
            security_clearance_required="standard",
            formation_strategy="optimal",
            coordination_pattern="hierarchical",
            duration=timedelta(hours=2)
        )
        
        # Form team
        team = await orchestrator.create_team(team_config)
        
        if team:
            print(f"Team formed: {team.team_id} with {len(team.members)} members")
            
            # Coordinate team task
            task_data = {
                "type": "network_scan",
                "target": "192.168.1.0/24",
                "priority": "high"
            }
            
            result = await orchestrator.coordinate_team_task(team.team_id, task_data)
            print(f"Task result: {result}")
            
            # Get coordination status
            status = orchestrator.get_coordination_status()
            print(f"Coordination status: {status}")
        
    finally:
        await orchestrator.shutdown()


if __name__ == "__main__":
    asyncio.run(main())