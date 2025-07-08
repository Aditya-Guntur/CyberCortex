#!/usr/bin/env python3
"""
Fetch.ai Network Agents for CyberCortex

Implements autonomous network scanning agents using the Fetch.ai uAgents
framework for distributed security assessment.
"""

import os
import sys
import json
import logging
import asyncio
import time
from typing import Dict, List, Optional, Any
from datetime import datetime
from uagents import Agent, Context, Protocol, Model
from uagents.setup import fund_agent_if_low

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("FetchNetworkAgents")

# Models for agent communication
class ScanRequest(Model):
    target: str
    scan_type: str
    parameters: Dict[str, Any] = {}
    request_id: str

class ScanResult(Model):
    request_id: str
    target: str
    scan_type: str
    status: str
    findings: List[Dict[str, Any]] = []
    timestamp: str
    error: Optional[str] = None

class NetworkDiscoveryResult(Model):
    request_id: str
    hosts: List[Dict[str, Any]] = []
    timestamp: str

class VulnerabilityResult(Model):
    request_id: str
    vulnerabilities: List[Dict[str, Any]] = []
    timestamp: str

class CoordinationMessage(Model):
    message_type: str
    content: Dict[str, Any]
    timestamp: str

api_url = os.environ.get("NEXT_PUBLIC_API_URL", "http://127.0.0.1:10000")
port = int(os.environ.get("PORT", 10000))

# Network Scanner Agent
network_scanner = Agent(
    name="network_scanner",
    seed="network_scanner_seed_phrase",
    port=port,
    endpoint=[f"{api_url}/submit"],
)

# Service Discovery Agent
service_discovery = Agent(
    name="service_discovery",
    seed="service_discovery_seed_phrase",
    port=port,
    endpoint=[f"{api_url}/submit"],
)

# Vulnerability Scanner Agent
vulnerability_scanner = Agent(
    name="vulnerability_scanner",
    seed="vulnerability_scanner_seed_phrase",
    port=port,
    endpoint=[f"{api_url}/submit"],
)

# Coordinator Agent
coordinator = Agent(
    name="coordinator",
    seed="coordinator_seed_phrase",
    port=port,
    endpoint=[f"{api_url}/submit"],
)

# Network Scanner Protocol
network_scan_protocol = Protocol("network_scan")

@network_scan_protocol.on_message(model=ScanRequest, replies={ScanResult})
async def handle_network_scan(ctx: Context, sender: str, msg: ScanRequest):
    """Handle network scan requests"""
    logger.info(f"Network scanner received request: {msg.target} ({msg.scan_type})")
    
    try:
        # Simulate network scanning
        await asyncio.sleep(2)
        
        # Generate simulated results based on scan type
        if msg.scan_type == "host_discovery":
            # Simulate host discovery
            hosts = []
            
            # Parse target network (assuming CIDR notation)
            network_parts = msg.target.split('.')
            base_network = f"{network_parts[0]}.{network_parts[1]}.{network_parts[2]}"
            
            # Generate some hosts
            for i in range(2, 8):
                ip = f"{base_network}.{i}"
                hosts.append({
                    "ip_address": ip,
                    "status": "up",
                    "hostname": f"host-{i}",
                    "last_seen": datetime.now().isoformat()
                })
            
            # Send results
            await ctx.send(
                sender,
                ScanResult(
                    request_id=msg.request_id,
                    target=msg.target,
                    scan_type=msg.scan_type,
                    status="completed",
                    findings=hosts,
                    timestamp=datetime.now().isoformat()
                )
            )
            
        elif msg.scan_type == "port_scan":
            # Simulate port scanning
            ports = []
            
            # Generate some open ports
            for port in [22, 80, 443, 3306, 8080, 8888]:
                if port % (int(msg.target.split('.')[-1]) + 1) != 0:  # Vary by host
                    ports.append({
                        "port": port,
                        "protocol": "tcp",
                        "state": "open",
                        "service": self._get_service_name(port)
                    })
            
            # Send results
            await ctx.send(
                sender,
                ScanResult(
                    request_id=msg.request_id,
                    target=msg.target,
                    scan_type=msg.scan_type,
                    status="completed",
                    findings=ports,
                    timestamp=datetime.now().isoformat()
                )
            )
        
        else:
            # Unknown scan type
            await ctx.send(
                sender,
                ScanResult(
                    request_id=msg.request_id,
                    target=msg.target,
                    scan_type=msg.scan_type,
                    status="failed",
                    timestamp=datetime.now().isoformat(),
                    error=f"Unknown scan type: {msg.scan_type}"
                )
            )
    
    except Exception as e:
        logger.error(f"Error in network scan: {str(e)}")
        
        # Send error response
        await ctx.send(
            sender,
            ScanResult(
                request_id=msg.request_id,
                target=msg.target,
                scan_type=msg.scan_type,
                status="failed",
                timestamp=datetime.now().isoformat(),
                error=str(e)
            )
        )

# Service Discovery Protocol
service_discovery_protocol = Protocol("service_discovery")

@service_discovery_protocol.on_message(model=ScanRequest, replies={ScanResult})
async def handle_service_discovery(ctx: Context, sender: str, msg: ScanRequest):
    """Handle service discovery requests"""
    logger.info(f"Service discovery received request: {msg.target} ({msg.scan_type})")
    
    try:
        # Simulate service discovery
        await asyncio.sleep(2)
        
        # Generate simulated results
        services = []
        
        # Determine host type based on IP
        last_octet = int(msg.target.split('.')[-1])
        
        if last_octet == 2:  # Web server
            services.append({
                "name": "http",
                "port": 80,
                "protocol": "tcp",
                "product": "Apache httpd",
                "version": "2.4.38"
            })
        elif last_octet == 3:  # SSH server
            services.append({
                "name": "ssh",
                "port": 22,
                "protocol": "tcp",
                "product": "OpenSSH",
                "version": "7.9p1"
            })
        elif last_octet == 4:  # Database server
            services.append({
                "name": "mysql",
                "port": 3306,
                "protocol": "tcp",
                "product": "MySQL",
                "version": "5.7.32"
            })
        elif last_octet == 5:  # Router
            services.append({
                "name": "http",
                "port": 80,
                "protocol": "tcp",
                "product": "Router Admin Interface",
                "version": "1.0"
            })
        elif last_octet == 6:  # IoT device
            services.append({
                "name": "http",
                "port": 8888,
                "protocol": "tcp",
                "product": "IoT Control Interface",
                "version": "1.0.2"
            })
        elif last_octet == 7:  # Monitoring server
            services.append({
                "name": "http",
                "port": 80,
                "protocol": "tcp",
                "product": "Monitoring Dashboard",
                "version": "2.1"
            })
        
        # Send results
        await ctx.send(
            sender,
            ScanResult(
                request_id=msg.request_id,
                target=msg.target,
                scan_type=msg.scan_type,
                status="completed",
                findings=services,
                timestamp=datetime.now().isoformat()
            )
        )
    
    except Exception as e:
        logger.error(f"Error in service discovery: {str(e)}")
        
        # Send error response
        await ctx.send(
            sender,
            ScanResult(
                request_id=msg.request_id,
                target=msg.target,
                scan_type=msg.scan_type,
                status="failed",
                timestamp=datetime.now().isoformat(),
                error=str(e)
            )
        )

# Vulnerability Scanner Protocol
vulnerability_scan_protocol = Protocol("vulnerability_scan")

@vulnerability_scan_protocol.on_message(model=ScanRequest, replies={ScanResult})
async def handle_vulnerability_scan(ctx: Context, sender: str, msg: ScanRequest):
    """Handle vulnerability scan requests"""
    logger.info(f"Vulnerability scanner received request: {msg.target} ({msg.scan_type})")
    
    try:
        # Simulate vulnerability scanning
        await asyncio.sleep(3)
        
        # Generate simulated results
        vulnerabilities = []
        
        # Determine vulnerabilities based on target and scan type
        target_parts = msg.target.split(':')
        ip = target_parts[0]
        port = int(target_parts[1]) if len(target_parts) > 1 else None
        
        # Get service from parameters
        service = msg.parameters.get("service", "unknown")
        
        # Generate vulnerabilities based on service and host
        last_octet = int(ip.split('.')[-1])
        
        if service == "http" and last_octet == 2:  # Web server
            vulnerabilities.extend([
                {
                    "id": f"vuln_{ip}_80_sql_injection",
                    "host": ip,
                    "port": 80,
                    "service": "http",
                    "type": "sql_injection",
                    "severity": "high",
                    "description": "SQL injection vulnerability in login form",
                    "cve": "CVE-2020-12345",
                    "cvss_score": 8.5,
                    "discovered_at": datetime.now().isoformat(),
                    "details": {
                        "url": f"http://{ip}:80/login.php",
                        "parameter": "username",
                        "proof_of_concept": "' OR 1=1 --"
                    }
                },
                {
                    "id": f"vuln_{ip}_80_xss",
                    "host": ip,
                    "port": 80,
                    "service": "http",
                    "type": "xss",
                    "severity": "medium",
                    "description": "Cross-site scripting vulnerability in search function",
                    "cve": "CVE-2020-54321",
                    "cvss_score": 6.5,
                    "discovered_at": datetime.now().isoformat(),
                    "details": {
                        "url": f"http://{ip}:80/search.php",
                        "parameter": "q",
                        "proof_of_concept": "<script>alert('XSS')</script>"
                    }
                }
            ])
        
        elif service == "ssh" and last_octet == 3:  # SSH server
            vulnerabilities.append({
                "id": f"vuln_{ip}_22_weak_password",
                "host": ip,
                "port": 22,
                "service": "ssh",
                "type": "weak_password",
                "severity": "high",
                "description": "Weak password for SSH user 'testuser'",
                "cve": None,
                "cvss_score": 7.5,
                "discovered_at": datetime.now().isoformat(),
                "details": {
                    "username": "testuser",
                    "password": "testpassword"
                }
            })
        
        elif service == "mysql" and last_octet == 4:  # Database server
            vulnerabilities.append({
                "id": f"vuln_{ip}_3306_mysql_weak_password",
                "host": ip,
                "port": 3306,
                "service": "mysql",
                "type": "weak_password",
                "severity": "critical",
                "description": "Weak password for MySQL root user",
                "cve": None,
                "cvss_score": 9.0,
                "discovered_at": datetime.now().isoformat(),
                "details": {
                    "username": "root",
                    "password": "insecure_root_password"
                }
            })
        
        elif service == "http" and last_octet == 6:  # IoT device
            vulnerabilities.extend([
                {
                    "id": f"vuln_{ip}_8888_command_injection",
                    "host": ip,
                    "port": 8888,
                    "service": "http",
                    "type": "command_injection",
                    "severity": "critical",
                    "description": "Command injection in ping functionality",
                    "cve": "CVE-2021-98765",
                    "cvss_score": 9.8,
                    "discovered_at": datetime.now().isoformat(),
                    "details": {
                        "url": f"http://{ip}:8888/system/ping",
                        "parameter": "host",
                        "proof_of_concept": "127.0.0.1; id"
                    }
                },
                {
                    "id": f"vuln_{ip}_8888_path_traversal",
                    "host": ip,
                    "port": 8888,
                    "service": "http",
                    "type": "path_traversal",
                    "severity": "high",
                    "description": "Path traversal in firmware download",
                    "cve": "CVE-2021-87654",
                    "cvss_score": 8.2,
                    "discovered_at": datetime.now().isoformat(),
                    "details": {
                        "url": f"http://{ip}:8888/firmware/../../etc/passwd",
                        "parameter": "path",
                        "proof_of_concept": "../../etc/passwd"
                    }
                }
            ])
        
        # Send results
        await ctx.send(
            sender,
            ScanResult(
                request_id=msg.request_id,
                target=msg.target,
                scan_type=msg.scan_type,
                status="completed",
                findings=vulnerabilities,
                timestamp=datetime.now().isoformat()
            )
        )
    
    except Exception as e:
        logger.error(f"Error in vulnerability scan: {str(e)}")
        
        # Send error response
        await ctx.send(
            sender,
            ScanResult(
                request_id=msg.request_id,
                target=msg.target,
                scan_type=msg.scan_type,
                status="failed",
                timestamp=datetime.now().isoformat(),
                error=str(e)
            )
        )

# Coordinator Protocol
coordination_protocol = Protocol("coordination")

@coordination_protocol.on_message(model=CoordinationMessage)
async def handle_coordination(ctx: Context, sender: str, msg: CoordinationMessage):
    """Handle coordination messages"""
    logger.info(f"Coordinator received message: {msg.message_type}")
    
    if msg.message_type == "start_scan":
        # Start a coordinated scan
        network = msg.content.get("network", "172.20.0.0/16")
        
        # Generate request ID
        request_id = f"req_{int(time.time())}"
        
        # Send network scan request
        await ctx.send(
            network_scanner.address,
            ScanRequest(
                request_id=request_id,
                target=network,
                scan_type="host_discovery",
                parameters={}
            )
        )
        
        logger.info(f"Sent host discovery request to network scanner: {request_id}")

@network_scanner.on_interval(period=60.0)
async def periodic_network_scan(ctx: Context):
    """Perform periodic network scans"""
    # This would be used for continuous monitoring
    pass

@service_discovery.on_interval(period=120.0)
async def periodic_service_scan(ctx: Context):
    """Perform periodic service scans"""
    # This would be used for continuous monitoring
    pass

@vulnerability_scanner.on_interval(period=300.0)
async def periodic_vulnerability_scan(ctx: Context):
    """Perform periodic vulnerability scans"""
    # This would be used for continuous monitoring
    pass

# Helper method for network scanner
def _get_service_name(port: int) -> str:
    """Get service name for a port"""
    service_map = {
        22: "ssh",
        80: "http",
        443: "https",
        3306: "mysql",
        5432: "postgresql",
        8080: "http-alt",
        8888: "http-alt"
    }
    
    return service_map.get(port, "unknown")

# Register protocols
network_scanner.include(network_scan_protocol)
service_discovery.include(service_discovery_protocol)
vulnerability_scanner.include(vulnerability_scan_protocol)
coordinator.include(coordination_protocol)

async def main():
    """Main function to run the Fetch.ai agents"""
    # Fund agents if needed
    await fund_agent_if_low(network_scanner.wallet.address())
    await fund_agent_if_low(service_discovery.wallet.address())
    await fund_agent_if_low(vulnerability_scanner.wallet.address())
    await fund_agent_if_low(coordinator.wallet.address())
    
    # Start agents
    await network_scanner.start()
    await service_discovery.start()
    await vulnerability_scanner.start()
    await coordinator.start()
    
    logger.info("All Fetch.ai agents started")
    
    # Keep running
    while True:
        await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())