"""
MCP Coordinator

Central coordinator for managing multiple MCP servers, routing requests,
and providing unified interface for all security tools.
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from pathlib import Path
import aiohttp
from concurrent.futures import ThreadPoolExecutor

from mcp import ClientSession, StdioServerParameters
from mcp.server import Server
from mcp.types import (
    CallToolRequest, 
    CallToolResult, 
    ListToolsRequest, 
    Tool, 
    TextContent
)

from .security_tools_server import SecurityToolsServer
from .vulnerability_db_server import VulnerabilityDBServer
from .compliance_framework_server import ComplianceFrameworkServer
from .threat_intelligence_server import ThreatIntelligenceServer
from .tool_registry import ToolRegistry, ToolCapability


@dataclass
class MCPServerInfo:
    """Information about an MCP server"""
    server_id: str
    name: str
    description: str
    server_instance: Any
    status: str  # running, stopped, error
    tools: List[str]
    last_heartbeat: datetime
    error_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['last_heartbeat'] = self.last_heartbeat.isoformat()
        del data['server_instance']  # Don't serialize the instance
        return data


@dataclass
class ToolExecutionRequest:
    """Tool execution request"""
    request_id: str
    tool_name: str
    arguments: Dict[str, Any]
    server_id: str
    user_id: Optional[str]
    timestamp: datetime
    priority: int = 5  # 1-10, lower is higher priority
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data


@dataclass
class ToolExecutionResult:
    """Tool execution result"""
    request_id: str
    tool_name: str
    server_id: str
    success: bool
    result: Any
    error: Optional[str]
    execution_time: float
    timestamp: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data


class MCPCoordinator:
    """Central coordinator for MCP servers"""
    
    def __init__(self, config_file: str = "mcp_config.json"):
        self.server = Server("mcp-coordinator")
        self.logger = logging.getLogger(__name__)
        
        # Server management
        self.servers: Dict[str, MCPServerInfo] = {}
        self.tool_registry = ToolRegistry()
        self.tool_server_mapping: Dict[str, str] = {}  # tool_name -> server_id
        
        # Request management
        self.request_queue: asyncio.Queue = asyncio.Queue()
        self.active_requests: Dict[str, ToolExecutionRequest] = {}
        self.request_history: List[ToolExecutionResult] = []
        
        # Configuration
        self.config = self._load_config(config_file)
        self.max_concurrent_requests = self.config.get('max_concurrent_requests', 10)
        self.request_timeout = self.config.get('request_timeout', 300)
        
        # Background tasks
        self.background_tasks: Set[asyncio.Task] = set()
        
        self._setup_handlers()
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load coordinator configuration"""
        try:
            config_path = Path(config_file)
            if config_path.exists():
                with open(config_path, 'r') as f:
                    return json.load(f)
            else:
                return self._create_default_config()
        except Exception as e:
            self.logger.error(f"Failed to load config: {str(e)}")
            return self._create_default_config()
    
    def _create_default_config(self) -> Dict[str, Any]:
        """Create default configuration"""
        return {
            'max_concurrent_requests': 10,
            'request_timeout': 300,
            'heartbeat_interval': 30,
            'server_configs': {
                'security-tools': {
                    'enabled': True,
                    'auto_start': True,
                    'config_file': 'security_tools_config.json'
                },
                'vulnerability-db': {
                    'enabled': True,
                    'auto_start': True,
                    'db_path': 'vulnerability_db.sqlite'
                },
                'compliance-framework': {
                    'enabled': True,
                    'auto_start': True,
                    'db_path': 'compliance_db.sqlite'
                },
                'threat-intelligence': {
                    'enabled': True,
                    'auto_start': True,
                    'db_path': 'threat_intelligence.sqlite'
                }
            }
        }
    
    def _setup_handlers(self):
        """Setup MCP request handlers"""
        
        @self.server.list_tools()
        async def handle_list_tools() -> List[Tool]:
            """List all available tools from all servers"""
            all_tools = []
            
            for capability in self.tool_registry.get_all_capabilities():
                server_id = self.tool_server_mapping.get(capability.name, 'unknown')
                
                tool = Tool(
                    name=capability.name,
                    description=f"[{server_id}] {capability.description}",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            param.name: {
                                "type": param.type,
                                "description": param.description,
                                **({"default": param.default_value} if param.default_value is not None else {})
                            }
                            for param in capability.parameters
                        },
                        "required": [param.name for param in capability.parameters if param.required]
                    }
                )
                all_tools.append(tool)
            
            return all_tools
        
        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> CallToolResult:
            """Route tool execution to appropriate server"""
            try:
                # Generate request ID
                request_id = f"req_{int(datetime.now().timestamp())}_{len(self.active_requests)}"
                
                # Find server for tool
                server_id = self.tool_server_mapping.get(name)
                if not server_id:
                    return CallToolResult(
                        content=[TextContent(
                            type="text",
                            text=f"Tool '{name}' not found"
                        )],
                        isError=True
                    )
                
                # Create execution request
                request = ToolExecutionRequest(
                    request_id=request_id,
                    tool_name=name,
                    arguments=arguments,
                    server_id=server_id,
                    user_id=None,  # Could be extracted from context
                    timestamp=datetime.now(timezone.utc)
                )
                
                # Execute tool
                result = await self._execute_tool_request(request)
                
                if result.success:
                    return CallToolResult(
                        content=[TextContent(
                            type="text",
                            text=json.dumps(result.result, indent=2, default=str)
                        )]
                    )
                else:
                    return CallToolResult(
                        content=[TextContent(
                            type="text",
                            text=f"Tool execution failed: {result.error}"
                        )],
                        isError=True
                    )
                    
            except Exception as e:
                self.logger.error(f"Tool routing failed: {str(e)}")
                return CallToolResult(
                    content=[TextContent(
                        type="text",
                        text=f"Tool routing failed: {str(e)}"
                    )],
                    isError=True
                )
    
    async def register_server(self, server_id: str, name: str, description: str, 
                            server_instance: Any) -> bool:
        """Register an MCP server"""
        try:
            # Initialize server
            await server_instance.initialize()
            
            # Get server tools
            tools = []
            if hasattr(server_instance, 'registry'):
                for capability in server_instance.registry.get_all_capabilities():
                    tools.append(capability.name)
                    self.tool_registry.register_tool(capability)
                    self.tool_server_mapping[capability.name] = server_id
            
            # Register server
            server_info = MCPServerInfo(
                server_id=server_id,
                name=name,
                description=description,
                server_instance=server_instance,
                status='running',
                tools=tools,
                last_heartbeat=datetime.now(timezone.utc)
            )
            
            self.servers[server_id] = server_info
            
            self.logger.info(f"Registered MCP server: {server_id} with {len(tools)} tools")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to register server {server_id}: {str(e)}")
            return False
    
    async def unregister_server(self, server_id: str) -> bool:
        """Unregister an MCP server"""
        try:
            if server_id in self.servers:
                server_info = self.servers[server_id]
                
                # Remove tools from registry
                for tool_name in server_info.tools:
                    self.tool_registry.unregister_tool(tool_name)
                    if tool_name in self.tool_server_mapping:
                        del self.tool_server_mapping[tool_name]
                
                # Remove server
                del self.servers[server_id]
                
                self.logger.info(f"Unregistered MCP server: {server_id}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to unregister server {server_id}: {str(e)}")
            return False
    
    async def _execute_tool_request(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        """Execute tool request on appropriate server"""
        start_time = datetime.now()
        
        try:
            # Get server
            server_info = self.servers.get(request.server_id)
            if not server_info:
                return ToolExecutionResult(
                    request_id=request.request_id,
                    tool_name=request.tool_name,
                    server_id=request.server_id,
                    success=False,
                    result=None,
                    error=f"Server {request.server_id} not found",
                    execution_time=0.0,
                    timestamp=datetime.now(timezone.utc)
                )
            
            # Add to active requests
            self.active_requests[request.request_id] = request
            
            try:
                # Route to appropriate server method
                if request.server_id == 'security-tools':
                    result = await self._execute_security_tool(server_info.server_instance, request)
                elif request.server_id == 'vulnerability-db':
                    result = await self._execute_vulnerability_tool(server_info.server_instance, request)
                elif request.server_id == 'compliance-framework':
                    result = await self._execute_compliance_tool(server_info.server_instance, request)
                elif request.server_id == 'threat-intelligence':
                    result = await self._execute_threat_tool(server_info.server_instance, request)
                else:
                    result = None
                    error = f"Unknown server type: {request.server_id}"
                
                execution_time = (datetime.now() - start_time).total_seconds()
                
                if result is not None:
                    execution_result = ToolExecutionResult(
                        request_id=request.request_id,
                        tool_name=request.tool_name,
                        server_id=request.server_id,
                        success=True,
                        result=result,
                        error=None,
                        execution_time=execution_time,
                        timestamp=datetime.now(timezone.utc)
                    )
                else:
                    execution_result = ToolExecutionResult(
                        request_id=request.request_id,
                        tool_name=request.tool_name,
                        server_id=request.server_id,
                        success=False,
                        result=None,
                        error=error,
                        execution_time=execution_time,
                        timestamp=datetime.now(timezone.utc)
                    )
                
                # Store result
                self.request_history.append(execution_result)
                
                # Keep only last 1000 results
                if len(self.request_history) > 1000:
                    self.request_history = self.request_history[-1000:]
                
                return execution_result
                
            finally:
                # Remove from active requests
                if request.request_id in self.active_requests:
                    del self.active_requests[request.request_id]
                    
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return ToolExecutionResult(
                request_id=request.request_id,
                tool_name=request.tool_name,
                server_id=request.server_id,
                success=False,
                result=None,
                error=str(e),
                execution_time=execution_time,
                timestamp=datetime.now(timezone.utc)
            )
    
    async def _execute_security_tool(self, server: SecurityToolsServer, 
                                   request: ToolExecutionRequest) -> Any:
        """Execute security tool"""
        return await server._execute_tool(request.tool_name, request.arguments)
    
    async def _execute_vulnerability_tool(self, server: VulnerabilityDBServer, 
                                        request: ToolExecutionRequest) -> Any:
        """Execute vulnerability database tool"""
        # Route to appropriate method based on tool name
        if request.tool_name == "search_vulnerabilities":
            return await server._search_vulnerabilities(request.arguments)
        elif request.tool_name == "get_vulnerability_details":
            return await server._get_vulnerability_details(request.arguments)
        elif request.tool_name == "check_product_vulnerabilities":
            return await server._check_product_vulnerabilities(request.arguments)
        elif request.tool_name == "update_vulnerability_feeds":
            return await server._update_vulnerability_feeds(request.arguments)
        elif request.tool_name == "vulnerability_statistics":
            return await server._vulnerability_statistics(request.arguments)
        elif request.tool_name == "vulnerability_correlation":
            return await server._vulnerability_correlation(request.arguments)
        else:
            raise ValueError(f"Unknown vulnerability tool: {request.tool_name}")
    
    async def _execute_compliance_tool(self, server: ComplianceFrameworkServer, 
                                     request: ToolExecutionRequest) -> Any:
        """Execute compliance framework tool"""
        # Route to appropriate method based on tool name
        if request.tool_name == "list_frameworks":
            return await server._list_frameworks(request.arguments)
        elif request.tool_name == "get_framework_details":
            return await server._get_framework_details(request.arguments)
        elif request.tool_name == "assess_framework":
            return await server._assess_framework(request.arguments)
        elif request.tool_name == "assess_control":
            return await server._assess_control(request.arguments)
        elif request.tool_name == "get_assessment_results":
            return await server._get_assessment_results(request.arguments)
        elif request.tool_name == "generate_compliance_report":
            return await server._generate_compliance_report(request.arguments)
        elif request.tool_name == "track_compliance_trends":
            return await server._track_compliance_trends(request.arguments)
        else:
            raise ValueError(f"Unknown compliance tool: {request.tool_name}")
    
    async def _execute_threat_tool(self, server: ThreatIntelligenceServer, 
                                 request: ToolExecutionRequest) -> Any:
        """Execute threat intelligence tool"""
        # Route to appropriate method based on tool name
        if request.tool_name == "search_indicators":
            return await server._search_indicators(request.arguments)
        elif request.tool_name == "lookup_indicator":
            return await server._lookup_indicator(request.arguments)
        elif request.tool_name == "correlate_indicators":
            return await server._correlate_indicators(request.arguments)
        elif request.tool_name == "update_threat_feeds":
            return await server._update_threat_feeds(request.arguments)
        elif request.tool_name == "threat_statistics":
            return await server._threat_statistics(request.arguments)
        elif request.tool_name == "enrich_indicators":
            return await server._enrich_indicators(request.arguments)
        elif request.tool_name == "generate_threat_report":
            return await server._generate_threat_report(request.arguments)
        else:
            raise ValueError(f"Unknown threat intelligence tool: {request.tool_name}")
    
    async def start_background_tasks(self):
        """Start background tasks"""
        # Heartbeat monitoring
        heartbeat_task = asyncio.create_task(self._heartbeat_monitor())
        self.background_tasks.add(heartbeat_task)
        heartbeat_task.add_done_callback(self.background_tasks.discard)
        
        # Request queue processor
        queue_task = asyncio.create_task(self._process_request_queue())
        self.background_tasks.add(queue_task)
        queue_task.add_done_callback(self.background_tasks.discard)
        
        self.logger.info("Started background tasks")
    
    async def _heartbeat_monitor(self):
        """Monitor server heartbeats"""
        while True:
            try:
                current_time = datetime.now(timezone.utc)
                
                for server_id, server_info in self.servers.items():
                    # Check if server is responsive
                    time_since_heartbeat = (current_time - server_info.last_heartbeat).total_seconds()
                    
                    if time_since_heartbeat > self.config.get('heartbeat_interval', 30) * 2:
                        if server_info.status == 'running':
                            server_info.status = 'error'
                            server_info.error_count += 1
                            self.logger.warning(f"Server {server_id} appears unresponsive")
                    
                    # Update heartbeat
                    server_info.last_heartbeat = current_time
                
                await asyncio.sleep(self.config.get('heartbeat_interval', 30))
                
            except Exception as e:
                self.logger.error(f"Heartbeat monitor error: {str(e)}")
                await asyncio.sleep(5)
    
    async def _process_request_queue(self):
        """Process queued requests"""
        while True:
            try:
                # Get request from queue
                request = await self.request_queue.get()
                
                # Check if we have capacity
                if len(self.active_requests) >= self.max_concurrent_requests:
                    # Put request back and wait
                    await self.request_queue.put(request)
                    await asyncio.sleep(1)
                    continue
                
                # Execute request
                asyncio.create_task(self._execute_tool_request(request))
                
            except Exception as e:
                self.logger.error(f"Request queue processor error: {str(e)}")
                await asyncio.sleep(1)
    
    async def get_server_status(self) -> Dict[str, Any]:
        """Get status of all servers"""
        status = {
            'coordinator': {
                'active_requests': len(self.active_requests),
                'queue_size': self.request_queue.qsize(),
                'total_tools': len(self.tool_server_mapping),
                'request_history_size': len(self.request_history)
            },
            'servers': {}
        }
        
        for server_id, server_info in self.servers.items():
            status['servers'][server_id] = server_info.to_dict()
        
        return status
    
    async def get_tool_statistics(self) -> Dict[str, Any]:
        """Get tool usage statistics"""
        tool_stats = {}
        
        for result in self.request_history:
            tool_name = result.tool_name
            if tool_name not in tool_stats:
                tool_stats[tool_name] = {
                    'total_executions': 0,
                    'successful_executions': 0,
                    'failed_executions': 0,
                    'average_execution_time': 0.0,
                    'total_execution_time': 0.0
                }
            
            stats = tool_stats[tool_name]
            stats['total_executions'] += 1
            stats['total_execution_time'] += result.execution_time
            
            if result.success:
                stats['successful_executions'] += 1
            else:
                stats['failed_executions'] += 1
            
            stats['average_execution_time'] = stats['total_execution_time'] / stats['total_executions']
        
        return tool_stats
    
    async def initialize(self):
        """Initialize the MCP coordinator"""
        try:
            # Start background tasks
            await self.start_background_tasks()
            
            # Auto-start configured servers
            await self._auto_start_servers()
            
            self.logger.info("MCP Coordinator initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize MCP Coordinator: {str(e)}")
            raise
    
    async def _auto_start_servers(self):
        """Auto-start configured servers"""
        server_configs = self.config.get('server_configs', {})
        
        for server_id, config in server_configs.items():
            if config.get('enabled', True) and config.get('auto_start', True):
                try:
                    await self._start_server(server_id, config)
                except Exception as e:
                    self.logger.error(f"Failed to auto-start server {server_id}: {str(e)}")
    
    async def _start_server(self, server_id: str, config: Dict[str, Any]):
        """Start a specific server"""
        try:
            if server_id == 'security-tools':
                server = SecurityToolsServer(config.get('config_file', 'security_tools_config.json'))
                await self.register_server(server_id, 'Security Tools Server', 
                                         'Security scanning tools integration', server)
            
            elif server_id == 'vulnerability-db':
                server = VulnerabilityDBServer(config.get('db_path', 'vulnerability_db.sqlite'))
                await self.register_server(server_id, 'Vulnerability Database Server', 
                                         'Vulnerability database operations', server)
            
            elif server_id == 'compliance-framework':
                server = ComplianceFrameworkServer(config.get('db_path', 'compliance_db.sqlite'))
                await self.register_server(server_id, 'Compliance Framework Server', 
                                         'Compliance framework operations', server)
            
            elif server_id == 'threat-intelligence':
                server = ThreatIntelligenceServer(config.get('db_path', 'threat_intelligence.sqlite'))
                await self.register_server(server_id, 'Threat Intelligence Server', 
                                         'Threat intelligence operations', server)
            
            else:
                self.logger.warning(f"Unknown server type: {server_id}")
                
        except Exception as e:
            self.logger.error(f"Failed to start server {server_id}: {str(e)}")
            raise
    
    async def run(self):
        """Run the MCP coordinator"""
        await self.initialize()
        
        async with ClientSession(StdioServerParameters()) as session:
            await session.initialize()
            
            self.logger.info("MCP Coordinator running...")
            
            try:
                while True:
                    await asyncio.sleep(1)
            except KeyboardInterrupt:
                self.logger.info("Shutting down MCP Coordinator...")
                
                # Cancel background tasks
                for task in self.background_tasks:
                    task.cancel()
                
                # Wait for tasks to complete
                if self.background_tasks:
                    await asyncio.gather(*self.background_tasks, return_exceptions=True)


# Example usage
async def main():
    """Example usage of MCP Coordinator"""
    coordinator = MCPCoordinator()
    await coordinator.run()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())