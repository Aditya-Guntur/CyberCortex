"""
Security Tools MCP Server

Provides unified interface for security scanning tools including Nmap, Nessus, 
Burp Suite, Metasploit, and Wireshark with secure execution and result parsing.
"""

import asyncio
import json
import logging
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any, Union, Tuple
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, asdict
import docker
import nmap
import requests
from cryptography.fernet import Fernet
import redis.asyncio as redis

from mcp import ClientSession, StdioServerParameters
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.types import (
    CallToolRequest, 
    CallToolResult, 
    ListToolsRequest, 
    Tool, 
    TextContent,
    ImageContent,
    EmbeddedResource
)

from .tool_registry import ToolRegistry, ToolCapability, ToolParameter
from .secure_executor import SecureExecutor


@dataclass
class ScanResult:
    """Standardized scan result format"""
    tool_name: str
    scan_id: str
    target: str
    status: str
    start_time: datetime
    end_time: Optional[datetime]
    findings: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    raw_output: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['start_time'] = self.start_time.isoformat()
        if self.end_time:
            data['end_time'] = self.end_time.isoformat()
        return data


@dataclass
class ToolConfiguration:
    """Tool-specific configuration"""
    tool_name: str
    executable_path: str
    config_file: Optional[str]
    environment_vars: Dict[str, str]
    docker_image: Optional[str]
    timeout: int
    max_concurrent: int
    requires_root: bool
    network_access: bool


class SecurityToolsServer:
    """MCP Server for security scanning tools integration"""
    
    def __init__(self, config_file: str = "security_tools_config.json"):
        self.server = Server("security-tools")
        self.logger = logging.getLogger(__name__)
        self.executor = SecureExecutor()
        self.registry = ToolRegistry()
        
        # Tool configurations
        self.tool_configs: Dict[str, ToolConfiguration] = {}
        self.active_scans: Dict[str, ScanResult] = {}
        
        # Docker client for containerized tools
        self.docker_client = docker.from_env()
        
        # Redis for scan state management
        self.redis_client: Optional[redis.Redis] = None
        
        # Load configurations
        self._load_tool_configurations(config_file)
        self._register_tools()
        self._setup_handlers()
    
    def _load_tool_configurations(self, config_file: str):
        """Load tool configurations from file"""
        try:
            config_path = Path(config_file)
            if config_path.exists():
                with open(config_path, 'r') as f:
                    config_data = json.load(f)
                    
                for tool_name, config in config_data.get('tools', {}).items():
                    self.tool_configs[tool_name] = ToolConfiguration(
                        tool_name=tool_name,
                        executable_path=config.get('executable_path', ''),
                        config_file=config.get('config_file'),
                        environment_vars=config.get('environment_vars', {}),
                        docker_image=config.get('docker_image'),
                        timeout=config.get('timeout', 300),
                        max_concurrent=config.get('max_concurrent', 3),
                        requires_root=config.get('requires_root', False),
                        network_access=config.get('network_access', True)
                    )
            else:
                self._create_default_configurations()
                
        except Exception as e:
            self.logger.error(f"Failed to load tool configurations: {str(e)}")
            self._create_default_configurations()
    
    def _create_default_configurations(self):
        """Create default tool configurations"""
        self.tool_configs = {
            'nmap': ToolConfiguration(
                tool_name='nmap',
                executable_path='/usr/bin/nmap',
                config_file=None,
                environment_vars={},
                docker_image='instrumentisto/nmap',
                timeout=600,
                max_concurrent=5,
                requires_root=False,
                network_access=True
            ),
            'nessus': ToolConfiguration(
                tool_name='nessus',
                executable_path='/opt/nessus/bin/nessuscli',
                config_file='/opt/nessus/etc/nessus/nessus.conf',
                environment_vars={},
                docker_image=None,
                timeout=3600,
                max_concurrent=2,
                requires_root=True,
                network_access=True
            ),
            'burp': ToolConfiguration(
                tool_name='burp',
                executable_path='/opt/burpsuite/burpsuite_community.jar',
                config_file=None,
                environment_vars={'JAVA_HOME': '/usr/lib/jvm/java-11-openjdk'},
                docker_image='securecodebox/burp-enterprise',
                timeout=1800,
                max_concurrent=3,
                requires_root=False,
                network_access=True
            ),
            'metasploit': ToolConfiguration(
                tool_name='metasploit',
                executable_path='/usr/bin/msfconsole',
                config_file='/usr/share/metasploit-framework/config/database.yml',
                environment_vars={},
                docker_image='metasploitframework/metasploit-framework',
                timeout=1800,
                max_concurrent=2,
                requires_root=True,
                network_access=True
            ),
            'wireshark': ToolConfiguration(
                tool_name='wireshark',
                executable_path='/usr/bin/tshark',
                config_file=None,
                environment_vars={},
                docker_image='linuxserver/wireshark',
                timeout=300,
                max_concurrent=3,
                requires_root=True,
                network_access=True
            )
        }
    
    def _register_tools(self):
        """Register available security tools with MCP"""
        
        # Nmap tools
        self.registry.register_tool(ToolCapability(
            name="nmap_host_discovery",
            description="Discover live hosts on network using Nmap",
            parameters=[
                ToolParameter("target", "string", "Target network or host", True),
                ToolParameter("technique", "string", "Discovery technique (ping, arp, syn)", False, "ping"),
                ToolParameter("timeout", "integer", "Scan timeout in seconds", False, 300)
            ],
            category="network_discovery",
            requires_auth=False,
            risk_level="low"
        ))
        
        self.registry.register_tool(ToolCapability(
            name="nmap_port_scan",
            description="Perform port scanning using Nmap",
            parameters=[
                ToolParameter("target", "string", "Target host or network", True),
                ToolParameter("ports", "string", "Port range (e.g., 1-1000, 80,443)", False, "1-1000"),
                ToolParameter("scan_type", "string", "Scan type (tcp, udp, syn)", False, "tcp"),
                ToolParameter("timing", "string", "Timing template (T0-T5)", False, "T3")
            ],
            category="port_scanning",
            requires_auth=False,
            risk_level="medium"
        ))
        
        self.registry.register_tool(ToolCapability(
            name="nmap_service_detection",
            description="Detect services and versions using Nmap",
            parameters=[
                ToolParameter("target", "string", "Target host", True),
                ToolParameter("ports", "string", "Specific ports to scan", False, "top-1000"),
                ToolParameter("aggressive", "boolean", "Enable aggressive detection", False, False)
            ],
            category="service_detection",
            requires_auth=False,
            risk_level="medium"
        ))
        
        # Nessus tools
        self.registry.register_tool(ToolCapability(
            name="nessus_vulnerability_scan",
            description="Perform vulnerability assessment using Nessus",
            parameters=[
                ToolParameter("target", "string", "Target host or network", True),
                ToolParameter("policy", "string", "Scan policy template", False, "basic"),
                ToolParameter("credentials", "object", "Authentication credentials", False),
                ToolParameter("exclude_ports", "string", "Ports to exclude", False)
            ],
            category="vulnerability_assessment",
            requires_auth=True,
            risk_level="high"
        ))
        
        # Burp Suite tools
        self.registry.register_tool(ToolCapability(
            name="burp_web_scan",
            description="Perform web application security scan using Burp Suite",
            parameters=[
                ToolParameter("target_url", "string", "Target web application URL", True),
                ToolParameter("scan_type", "string", "Scan type (crawl, audit, both)", False, "both"),
                ToolParameter("authentication", "object", "Authentication configuration", False),
                ToolParameter("scope", "array", "URL scope patterns", False)
            ],
            category="web_application_security",
            requires_auth=False,
            risk_level="high"
        ))
        
        # Metasploit tools
        self.registry.register_tool(ToolCapability(
            name="metasploit_exploit_search",
            description="Search for exploits using Metasploit",
            parameters=[
                ToolParameter("search_term", "string", "Search term (CVE, service, etc.)", True),
                ToolParameter("platform", "string", "Target platform filter", False),
                ToolParameter("type", "string", "Exploit type filter", False)
            ],
            category="exploit_research",
            requires_auth=False,
            risk_level="low"
        ))
        
        self.registry.register_tool(ToolCapability(
            name="metasploit_auxiliary_scan",
            description="Run auxiliary scanner modules",
            parameters=[
                ToolParameter("module", "string", "Auxiliary module name", True),
                ToolParameter("target", "string", "Target host or network", True),
                ToolParameter("options", "object", "Module-specific options", False)
            ],
            category="auxiliary_scanning",
            requires_auth=True,
            risk_level="medium"
        ))
        
        # Wireshark/TShark tools
        self.registry.register_tool(ToolCapability(
            name="wireshark_packet_capture",
            description="Capture network packets using TShark",
            parameters=[
                ToolParameter("interface", "string", "Network interface", True),
                ToolParameter("duration", "integer", "Capture duration in seconds", False, 60),
                ToolParameter("filter", "string", "Capture filter expression", False),
                ToolParameter("output_format", "string", "Output format (pcap, json)", False, "pcap")
            ],
            category="packet_capture",
            requires_auth=True,
            risk_level="high"
        ))
        
        self.registry.register_tool(ToolCapability(
            name="wireshark_packet_analysis",
            description="Analyze packet capture files",
            parameters=[
                ToolParameter("pcap_file", "string", "Path to PCAP file", True),
                ToolParameter("analysis_type", "string", "Analysis type (protocols, conversations, endpoints)", False, "protocols"),
                ToolParameter("filter", "string", "Display filter", False)
            ],
            category="packet_analysis",
            requires_auth=False,
            risk_level="low"
        ))
    
    def _setup_handlers(self):
        """Setup MCP request handlers"""
        
        @self.server.list_tools()
        async def handle_list_tools() -> List[Tool]:
            """List available security tools"""
            tools = []
            
            for capability in self.registry.get_all_capabilities():
                tools.append(Tool(
                    name=capability.name,
                    description=capability.description,
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
                ))
            
            return tools
        
        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> CallToolResult:
            """Execute security tool"""
            try:
                self.logger.info(f"Executing tool: {name} with arguments: {arguments}")
                
                # Validate tool exists
                capability = self.registry.get_capability(name)
                if not capability:
                    return CallToolResult(
                        content=[TextContent(
                            type="text",
                            text=f"Tool '{name}' not found"
                        )],
                        isError=True
                    )
                
                # Validate arguments
                validation_result = self._validate_arguments(capability, arguments)
                if not validation_result[0]:
                    return CallToolResult(
                        content=[TextContent(
                            type="text",
                            text=f"Invalid arguments: {validation_result[1]}"
                        )],
                        isError=True
                    )
                
                # Execute tool
                result = await self._execute_tool(name, arguments)
                
                return CallToolResult(
                    content=[TextContent(
                        type="text",
                        text=json.dumps(result.to_dict(), indent=2)
                    )]
                )
                
            except Exception as e:
                self.logger.error(f"Tool execution failed: {str(e)}")
                return CallToolResult(
                    content=[TextContent(
                        type="text",
                        text=f"Tool execution failed: {str(e)}"
                    )],
                    isError=True
                )
    
    def _validate_arguments(self, capability: ToolCapability, arguments: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate tool arguments"""
        try:
            # Check required parameters
            for param in capability.parameters:
                if param.required and param.name not in arguments:
                    return False, f"Missing required parameter: {param.name}"
                
                # Type validation
                if param.name in arguments:
                    value = arguments[param.name]
                    if param.type == "string" and not isinstance(value, str):
                        return False, f"Parameter {param.name} must be a string"
                    elif param.type == "integer" and not isinstance(value, int):
                        return False, f"Parameter {param.name} must be an integer"
                    elif param.type == "boolean" and not isinstance(value, bool):
                        return False, f"Parameter {param.name} must be a boolean"
                    elif param.type == "array" and not isinstance(value, list):
                        return False, f"Parameter {param.name} must be an array"
                    elif param.type == "object" and not isinstance(value, dict):
                        return False, f"Parameter {param.name} must be an object"
            
            return True, "Valid"
            
        except Exception as e:
            return False, f"Validation error: {str(e)}"
    
    async def _execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> ScanResult:
        """Execute security tool with given arguments"""
        scan_id = f"{tool_name}_{int(datetime.now().timestamp())}"
        start_time = datetime.now(timezone.utc)
        
        try:
            # Route to appropriate tool handler
            if tool_name.startswith('nmap_'):
                result = await self._execute_nmap_tool(tool_name, arguments, scan_id, start_time)
            elif tool_name.startswith('nessus_'):
                result = await self._execute_nessus_tool(tool_name, arguments, scan_id, start_time)
            elif tool_name.startswith('burp_'):
                result = await self._execute_burp_tool(tool_name, arguments, scan_id, start_time)
            elif tool_name.startswith('metasploit_'):
                result = await self._execute_metasploit_tool(tool_name, arguments, scan_id, start_time)
            elif tool_name.startswith('wireshark_'):
                result = await self._execute_wireshark_tool(tool_name, arguments, scan_id, start_time)
            else:
                raise ValueError(f"Unknown tool category for: {tool_name}")
            
            # Store scan result
            self.active_scans[scan_id] = result
            
            return result
            
        except Exception as e:
            self.logger.error(f"Tool execution failed: {str(e)}")
            return ScanResult(
                tool_name=tool_name,
                scan_id=scan_id,
                target=arguments.get('target', 'unknown'),
                status='failed',
                start_time=start_time,
                end_time=datetime.now(timezone.utc),
                findings=[],
                metadata={'error': str(e)}
            )
    
    async def _execute_nmap_tool(self, tool_name: str, arguments: Dict[str, Any], 
                                scan_id: str, start_time: datetime) -> ScanResult:
        """Execute Nmap-based tools"""
        target = arguments['target']
        
        try:
            nm = nmap.PortScanner()
            
            if tool_name == 'nmap_host_discovery':
                technique = arguments.get('technique', 'ping')
                
                if technique == 'ping':
                    scan_args = '-sn'
                elif technique == 'arp':
                    scan_args = '-sn -PR'
                elif technique == 'syn':
                    scan_args = '-sn -PS'
                else:
                    scan_args = '-sn'
                
                result = nm.scan(hosts=target, arguments=scan_args)
                
                findings = []
                for host in nm.all_hosts():
                    if nm[host].state() == 'up':
                        findings.append({
                            'type': 'host_discovery',
                            'host': host,
                            'status': 'up',
                            'hostnames': nm[host].hostnames(),
                            'addresses': nm[host]['addresses']
                        })
            
            elif tool_name == 'nmap_port_scan':
                ports = arguments.get('ports', '1-1000')
                scan_type = arguments.get('scan_type', 'tcp')
                timing = arguments.get('timing', 'T3')
                
                if scan_type == 'tcp':
                    scan_args = f'-sS -{timing}'
                elif scan_type == 'udp':
                    scan_args = f'-sU -{timing}'
                elif scan_type == 'syn':
                    scan_args = f'-sS -{timing}'
                else:
                    scan_args = f'-sS -{timing}'
                
                result = nm.scan(hosts=target, ports=ports, arguments=scan_args)
                
                findings = []
                for host in nm.all_hosts():
                    for protocol in nm[host].all_protocols():
                        ports_list = nm[host][protocol].keys()
                        for port in ports_list:
                            port_info = nm[host][protocol][port]
                            if port_info['state'] == 'open':
                                findings.append({
                                    'type': 'open_port',
                                    'host': host,
                                    'port': port,
                                    'protocol': protocol,
                                    'state': port_info['state'],
                                    'service': port_info.get('name', 'unknown'),
                                    'version': port_info.get('version', ''),
                                    'product': port_info.get('product', '')
                                })
            
            elif tool_name == 'nmap_service_detection':
                ports = arguments.get('ports', 'top-1000')
                aggressive = arguments.get('aggressive', False)
                
                if aggressive:
                    scan_args = '-sV -A -T4'
                else:
                    scan_args = '-sV -T3'
                
                if ports == 'top-1000':
                    scan_args += ' --top-ports 1000'
                else:
                    result = nm.scan(hosts=target, ports=ports, arguments=scan_args)
                
                if ports == 'top-1000':
                    result = nm.scan(hosts=target, arguments=scan_args)
                
                findings = []
                for host in nm.all_hosts():
                    for protocol in nm[host].all_protocols():
                        ports_list = nm[host][protocol].keys()
                        for port in ports_list:
                            port_info = nm[host][protocol][port]
                            findings.append({
                                'type': 'service_detection',
                                'host': host,
                                'port': port,
                                'protocol': protocol,
                                'state': port_info['state'],
                                'service': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', ''),
                                'extrainfo': port_info.get('extrainfo', ''),
                                'cpe': port_info.get('cpe', '')
                            })
            
            return ScanResult(
                tool_name=tool_name,
                scan_id=scan_id,
                target=target,
                status='completed',
                start_time=start_time,
                end_time=datetime.now(timezone.utc),
                findings=findings,
                metadata={
                    'nmap_version': nm.nmap_version(),
                    'scan_info': result.get('nmap', {}).get('scaninfo', {}),
                    'scan_stats': result.get('nmap', {}).get('scanstats', {})
                },
                raw_output=str(result)
            )
            
        except Exception as e:
            raise Exception(f"Nmap execution failed: {str(e)}")
    
    async def _execute_nessus_tool(self, tool_name: str, arguments: Dict[str, Any], 
                                  scan_id: str, start_time: datetime) -> ScanResult:
        """Execute Nessus-based tools"""
        target = arguments['target']
        
        # Note: This is a simplified implementation
        # In production, you would integrate with Nessus API
        
        try:
            if tool_name == 'nessus_vulnerability_scan':
                policy = arguments.get('policy', 'basic')
                
                # Simulate Nessus scan (replace with actual API calls)
                await asyncio.sleep(2)  # Simulate scan time
                
                # Mock findings for demonstration
                findings = [
                    {
                        'type': 'vulnerability',
                        'plugin_id': '12345',
                        'plugin_name': 'SSL Certificate Signed Using Weak Hashing Algorithm',
                        'severity': 'medium',
                        'cvss_score': 5.0,
                        'description': 'The remote service uses a certificate signed with a weak hashing algorithm.',
                        'solution': 'Replace the certificate with one signed using a stronger hashing algorithm.',
                        'host': target,
                        'port': 443,
                        'protocol': 'tcp'
                    },
                    {
                        'type': 'vulnerability',
                        'plugin_id': '67890',
                        'plugin_name': 'SSH Weak Encryption Algorithms Supported',
                        'severity': 'low',
                        'cvss_score': 2.6,
                        'description': 'The remote SSH server supports weak encryption algorithms.',
                        'solution': 'Configure SSH to use only strong encryption algorithms.',
                        'host': target,
                        'port': 22,
                        'protocol': 'tcp'
                    }
                ]
                
                return ScanResult(
                    tool_name=tool_name,
                    scan_id=scan_id,
                    target=target,
                    status='completed',
                    start_time=start_time,
                    end_time=datetime.now(timezone.utc),
                    findings=findings,
                    metadata={
                        'policy': policy,
                        'scan_type': 'vulnerability_assessment',
                        'total_vulnerabilities': len(findings)
                    }
                )
            
        except Exception as e:
            raise Exception(f"Nessus execution failed: {str(e)}")
    
    async def _execute_burp_tool(self, tool_name: str, arguments: Dict[str, Any], 
                                scan_id: str, start_time: datetime) -> ScanResult:
        """Execute Burp Suite-based tools"""
        target_url = arguments['target_url']
        
        try:
            if tool_name == 'burp_web_scan':
                scan_type = arguments.get('scan_type', 'both')
                
                # Simulate Burp scan (replace with actual API calls)
                await asyncio.sleep(3)  # Simulate scan time
                
                # Mock findings for demonstration
                findings = [
                    {
                        'type': 'web_vulnerability',
                        'issue_type': 'SQL injection',
                        'severity': 'high',
                        'confidence': 'certain',
                        'url': f"{target_url}/login.php",
                        'parameter': 'username',
                        'description': 'SQL injection vulnerability in login form',
                        'remediation': 'Use parameterized queries to prevent SQL injection'
                    },
                    {
                        'type': 'web_vulnerability',
                        'issue_type': 'Cross-site scripting (reflected)',
                        'severity': 'medium',
                        'confidence': 'firm',
                        'url': f"{target_url}/search.php",
                        'parameter': 'q',
                        'description': 'Reflected XSS vulnerability in search functionality',
                        'remediation': 'Implement proper input validation and output encoding'
                    }
                ]
                
                return ScanResult(
                    tool_name=tool_name,
                    scan_id=scan_id,
                    target=target_url,
                    status='completed',
                    start_time=start_time,
                    end_time=datetime.now(timezone.utc),
                    findings=findings,
                    metadata={
                        'scan_type': scan_type,
                        'total_issues': len(findings),
                        'crawled_urls': 45
                    }
                )
            
        except Exception as e:
            raise Exception(f"Burp Suite execution failed: {str(e)}")
    
    async def _execute_metasploit_tool(self, tool_name: str, arguments: Dict[str, Any], 
                                      scan_id: str, start_time: datetime) -> ScanResult:
        """Execute Metasploit-based tools"""
        
        try:
            if tool_name == 'metasploit_exploit_search':
                search_term = arguments['search_term']
                platform = arguments.get('platform')
                
                # Simulate Metasploit search (replace with actual msfconsole integration)
                await asyncio.sleep(1)  # Simulate search time
                
                # Mock search results
                findings = [
                    {
                        'type': 'exploit',
                        'name': 'exploit/windows/smb/ms17_010_eternalblue',
                        'description': 'MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption',
                        'platform': 'windows',
                        'targets': ['Windows 7 and Windows Server 2008 R2'],
                        'rank': 'average',
                        'disclosure_date': '2017-03-14'
                    },
                    {
                        'type': 'exploit',
                        'name': 'exploit/linux/http/apache_struts_rce',
                        'description': 'Apache Struts 2 Remote Code Execution',
                        'platform': 'linux',
                        'targets': ['Linux x86', 'Linux x64'],
                        'rank': 'excellent',
                        'disclosure_date': '2017-03-06'
                    }
                ]
                
                # Filter by platform if specified
                if platform:
                    findings = [f for f in findings if f['platform'] == platform.lower()]
                
                return ScanResult(
                    tool_name=tool_name,
                    scan_id=scan_id,
                    target=search_term,
                    status='completed',
                    start_time=start_time,
                    end_time=datetime.now(timezone.utc),
                    findings=findings,
                    metadata={
                        'search_term': search_term,
                        'platform_filter': platform,
                        'total_results': len(findings)
                    }
                )
            
            elif tool_name == 'metasploit_auxiliary_scan':
                module = arguments['module']
                target = arguments['target']
                options = arguments.get('options', {})
                
                # Simulate auxiliary scan
                await asyncio.sleep(2)  # Simulate scan time
                
                # Mock auxiliary scan results
                findings = [
                    {
                        'type': 'auxiliary_result',
                        'module': module,
                        'host': target,
                        'result': 'Service detected',
                        'details': {
                            'service': 'SSH',
                            'version': 'OpenSSH 7.4',
                            'banner': 'SSH-2.0-OpenSSH_7.4'
                        }
                    }
                ]
                
                return ScanResult(
                    tool_name=tool_name,
                    scan_id=scan_id,
                    target=target,
                    status='completed',
                    start_time=start_time,
                    end_time=datetime.now(timezone.utc),
                    findings=findings,
                    metadata={
                        'module': module,
                        'options': options
                    }
                )
            
        except Exception as e:
            raise Exception(f"Metasploit execution failed: {str(e)}")
    
    async def _execute_wireshark_tool(self, tool_name: str, arguments: Dict[str, Any], 
                                     scan_id: str, start_time: datetime) -> ScanResult:
        """Execute Wireshark/TShark-based tools"""
        
        try:
            if tool_name == 'wireshark_packet_capture':
                interface = arguments['interface']
                duration = arguments.get('duration', 60)
                capture_filter = arguments.get('filter', '')
                output_format = arguments.get('output_format', 'pcap')
                
                # Create temporary file for capture
                with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as temp_file:
                    temp_path = temp_file.name
                
                # Build tshark command
                cmd = [
                    'tshark',
                    '-i', interface,
                    '-a', f'duration:{duration}',
                    '-w', temp_path
                ]
                
                if capture_filter:
                    cmd.extend(['-f', capture_filter])
                
                # Execute capture using secure executor
                result = await self.executor.execute_command(
                    cmd,
                    timeout=duration + 30,
                    requires_root=True
                )
                
                if result['returncode'] == 0:
                    # Analyze captured packets
                    analysis_cmd = [
                        'tshark',
                        '-r', temp_path,
                        '-q', '-z', 'conv,ip'
                    ]
                    
                    analysis_result = await self.executor.execute_command(analysis_cmd)
                    
                    findings = [{
                        'type': 'packet_capture',
                        'interface': interface,
                        'duration': duration,
                        'capture_file': temp_path,
                        'packet_count': result['stdout'].count('\n') if result['stdout'] else 0,
                        'analysis': analysis_result['stdout'] if analysis_result['returncode'] == 0 else ''
                    }]
                    
                    return ScanResult(
                        tool_name=tool_name,
                        scan_id=scan_id,
                        target=interface,
                        status='completed',
                        start_time=start_time,
                        end_time=datetime.now(timezone.utc),
                        findings=findings,
                        metadata={
                            'interface': interface,
                            'duration': duration,
                            'filter': capture_filter,
                            'output_format': output_format
                        }
                    )
                else:
                    raise Exception(f"Packet capture failed: {result['stderr']}")
            
            elif tool_name == 'wireshark_packet_analysis':
                pcap_file = arguments['pcap_file']
                analysis_type = arguments.get('analysis_type', 'protocols')
                display_filter = arguments.get('filter', '')
                
                # Build analysis command
                if analysis_type == 'protocols':
                    cmd = ['tshark', '-r', pcap_file, '-q', '-z', 'io,phs']
                elif analysis_type == 'conversations':
                    cmd = ['tshark', '-r', pcap_file, '-q', '-z', 'conv,ip']
                elif analysis_type == 'endpoints':
                    cmd = ['tshark', '-r', pcap_file, '-q', '-z', 'endpoints,ip']
                else:
                    cmd = ['tshark', '-r', pcap_file, '-q', '-z', 'io,phs']
                
                if display_filter:
                    cmd.extend(['-Y', display_filter])
                
                # Execute analysis
                result = await self.executor.execute_command(cmd)
                
                if result['returncode'] == 0:
                    findings = [{
                        'type': 'packet_analysis',
                        'pcap_file': pcap_file,
                        'analysis_type': analysis_type,
                        'results': result['stdout']
                    }]
                    
                    return ScanResult(
                        tool_name=tool_name,
                        scan_id=scan_id,
                        target=pcap_file,
                        status='completed',
                        start_time=start_time,
                        end_time=datetime.now(timezone.utc),
                        findings=findings,
                        metadata={
                            'analysis_type': analysis_type,
                            'filter': display_filter
                        }
                    )
                else:
                    raise Exception(f"Packet analysis failed: {result['stderr']}")
            
        except Exception as e:
            raise Exception(f"Wireshark execution failed: {str(e)}")
    
    async def get_scan_status(self, scan_id: str) -> Optional[ScanResult]:
        """Get status of active scan"""
        return self.active_scans.get(scan_id)
    
    async def list_active_scans(self) -> List[ScanResult]:
        """List all active scans"""
        return list(self.active_scans.values())
    
    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel active scan"""
        if scan_id in self.active_scans:
            # Implementation would cancel the actual scan process
            scan = self.active_scans[scan_id]
            scan.status = 'cancelled'
            scan.end_time = datetime.now(timezone.utc)
            return True
        return False
    
    async def initialize(self):
        """Initialize the MCP server"""
        try:
            # Initialize Redis connection
            self.redis_client = redis.Redis(
                host='localhost',
                port=6379,
                db=0,
                decode_responses=True
            )
            await self.redis_client.ping()
            
            self.logger.info("Security Tools MCP Server initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Security Tools MCP Server: {str(e)}")
            raise
    
    async def run(self):
        """Run the MCP server"""
        await self.initialize()
        
        # Start the server
        async with ClientSession(StdioServerParameters()) as session:
            await session.initialize()
            
            self.logger.info("Security Tools MCP Server running...")
            
            # Keep server running
            try:
                while True:
                    await asyncio.sleep(1)
            except KeyboardInterrupt:
                self.logger.info("Shutting down Security Tools MCP Server...")


# Example usage
async def main():
    """Example usage of Security Tools MCP Server"""
    server = SecurityToolsServer()
    await server.run()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())