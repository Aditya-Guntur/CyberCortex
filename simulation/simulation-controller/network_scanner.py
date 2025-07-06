#!/usr/bin/env python3
"""
Network Scanner for CyberCortex Simulation

Implements network discovery and service enumeration for the simulation
environment using Fetch.ai agents for distributed scanning.
"""

import os
import sys
import json
import logging
import asyncio
import ipaddress
import nmap
from typing import Dict, List, Optional, Any
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("NetworkScanner")

class NetworkScanner:
    """
    Network scanner that discovers hosts and services in the
    simulation environment using Fetch.ai agents.
    """
    
    def __init__(self):
        self.nmap_scanner = nmap.PortScanner()
        self.discovered_hosts = []
        self.scan_results = {}
        
        # Fetch.ai agent configuration (simulated)
        self.fetch_agents = {
            "discovery_agent": {"status": "ready", "capabilities": ["host_discovery", "port_scanning"]},
            "service_agent": {"status": "ready", "capabilities": ["service_detection", "os_detection"]},
            "vulnerability_agent": {"status": "ready", "capabilities": ["vuln_detection"]}
        }
        
        logger.info("Network Scanner initialized")
    
    async def scan_network(self, target_network: str) -> List[Dict[str, Any]]:
        """
        Scan a network range for hosts and services.
        
        Args:
            target_network: Network range in CIDR notation (e.g., 172.20.0.0/16)
            
        Returns:
            discovered_hosts: List of discovered hosts with their services
        """
        logger.info(f"Starting network scan on {target_network}")
        
        # Simulate Fetch.ai agent coordination
        await self._coordinate_fetch_agents()
        
        discovered_hosts = []
        
        try:
            # Perform host discovery
            logger.info("Performing host discovery")
            self.nmap_scanner.scan(hosts=target_network, arguments='-sn')
            
            # Process discovered hosts
            for host in self.nmap_scanner.all_hosts():
                host_info = {
                    "ip_address": host,
                    "status": self.nmap_scanner[host].state(),
                    "hostname": self._get_hostname(host),
                    "last_seen": datetime.now().isoformat(),
                    "ports": [],
                    "services": [],
                    "os_info": None
                }
                
                # If host is up, scan for open ports and services
                if self.nmap_scanner[host].state() == 'up':
                    # Simulate service detection
                    await self._detect_services(host_info)
                    
                    # Simulate OS detection
                    await self._detect_os(host_info)
                
                discovered_hosts.append(host_info)
                logger.info(f"Discovered host: {host}")
            
            # Store scan results
            self.discovered_hosts = discovered_hosts
            self.scan_results = {
                "scan_id": f"scan_{datetime.now().strftime('%Y%m%d%H%M%S')}",
                "target_network": target_network,
                "timestamp": datetime.now().isoformat(),
                "hosts_count": len(discovered_hosts),
                "hosts": discovered_hosts
            }
            
            logger.info(f"Network scan completed. Discovered {len(discovered_hosts)} hosts.")
            
            return discovered_hosts
            
        except Exception as e:
            logger.error(f"Error during network scan: {str(e)}")
            return []
    
    async def scan_host(self, host_ip: str) -> Optional[Dict[str, Any]]:
        """
        Perform a detailed scan of a specific host.
        
        Args:
            host_ip: IP address of the host to scan
            
        Returns:
            host_info: Detailed information about the host
        """
        logger.info(f"Starting detailed scan of host {host_ip}")
        
        try:
            # Perform port scan
            self.nmap_scanner.scan(hosts=host_ip, arguments='-sS -sV -O')
            
            if host_ip not in self.nmap_scanner.all_hosts():
                logger.warning(f"Host {host_ip} not found")
                return None
            
            host_info = {
                "ip_address": host_ip,
                "status": self.nmap_scanner[host_ip].state(),
                "hostname": self._get_hostname(host_ip),
                "last_seen": datetime.now().isoformat(),
                "ports": [],
                "services": [],
                "os_info": None
            }
            
            # Get open ports and services
            if self.nmap_scanner[host_ip].state() == 'up':
                for proto in self.nmap_scanner[host_ip].all_protocols():
                    ports = sorted(self.nmap_scanner[host_ip][proto].keys())
                    for port in ports:
                        port_info = self.nmap_scanner[host_ip][proto][port]
                        host_info["ports"].append({
                            "port": port,
                            "protocol": proto,
                            "state": port_info["state"],
                            "service": port_info["name"],
                            "product": port_info.get("product", ""),
                            "version": port_info.get("version", "")
                        })
                        
                        if port_info["state"] == "open":
                            host_info["services"].append({
                                "name": port_info["name"],
                                "port": port,
                                "protocol": proto,
                                "product": port_info.get("product", ""),
                                "version": port_info.get("version", "")
                            })
                
                # Get OS information if available
                if "osmatch" in self.nmap_scanner[host_ip]:
                    os_matches = self.nmap_scanner[host_ip]["osmatch"]
                    if os_matches and len(os_matches) > 0:
                        host_info["os_info"] = {
                            "name": os_matches[0]["name"],
                            "accuracy": os_matches[0]["accuracy"],
                            "type": os_matches[0].get("osclass", [{}])[0].get("type", "")
                        }
            
            logger.info(f"Detailed scan of host {host_ip} completed")
            return host_info
            
        except Exception as e:
            logger.error(f"Error during host scan: {str(e)}")
            return None
    
    async def _coordinate_fetch_agents(self):
        """Simulate coordination of Fetch.ai agents for distributed scanning"""
        logger.info("Coordinating Fetch.ai agents for network scanning")
        
        # Simulate agent coordination
        for agent_name, agent_info in self.fetch_agents.items():
            agent_info["status"] = "scanning"
            logger.info(f"Agent {agent_name} is now {agent_info['status']}")
            await asyncio.sleep(0.5)  # Simulate coordination delay
        
        logger.info("Fetch.ai agents coordinated successfully")
    
    async def _detect_services(self, host_info: Dict[str, Any]):
        """
        Simulate service detection for a host using Fetch.ai service agent.
        
        Args:
            host_info: Host information dictionary to update with service data
        """
        ip = host_info["ip_address"]
        logger.info(f"Detecting services on {ip}")
        
        # Simulate service detection delay
        await asyncio.sleep(1)
        
        # Simulate different services based on the last octet of the IP
        last_octet = int(ip.split('.')[-1])
        
        # Web server (DVWA)
        if last_octet == 2:
            host_info["ports"].append({"port": 80, "protocol": "tcp", "state": "open"})
            host_info["services"].append({
                "name": "http",
                "port": 80,
                "protocol": "tcp",
                "product": "Apache httpd",
                "version": "2.4.38"
            })
        
        # SSH server
        elif last_octet == 3:
            host_info["ports"].append({"port": 22, "protocol": "tcp", "state": "open"})
            host_info["services"].append({
                "name": "ssh",
                "port": 22,
                "protocol": "tcp",
                "product": "OpenSSH",
                "version": "7.9p1"
            })
        
        # Database server
        elif last_octet == 4:
            host_info["ports"].append({"port": 3306, "protocol": "tcp", "state": "open"})
            host_info["services"].append({
                "name": "mysql",
                "port": 3306,
                "protocol": "tcp",
                "product": "MySQL",
                "version": "5.7.32"
            })
        
        # Router
        elif last_octet == 5:
            host_info["ports"].append({"port": 80, "protocol": "tcp", "state": "open"})
            host_info["services"].append({
                "name": "http",
                "port": 80,
                "protocol": "tcp",
                "product": "Router Admin Interface",
                "version": "1.0"
            })
        
        # IoT device
        elif last_octet == 6:
            host_info["ports"].append({"port": 8888, "protocol": "tcp", "state": "open"})
            host_info["services"].append({
                "name": "http",
                "port": 8888,
                "protocol": "tcp",
                "product": "IoT Control Interface",
                "version": "1.0.2"
            })
        
        # Monitoring server
        elif last_octet == 7:
            host_info["ports"].append({"port": 80, "protocol": "tcp", "state": "open"})
            host_info["services"].append({
                "name": "http",
                "port": 80,
                "protocol": "tcp",
                "product": "Monitoring Dashboard",
                "version": "2.1"
            })
        
        logger.info(f"Detected {len(host_info['services'])} services on {ip}")
    
    async def _detect_os(self, host_info: Dict[str, Any]):
        """
        Simulate OS detection for a host using Fetch.ai service agent.
        
        Args:
            host_info: Host information dictionary to update with OS data
        """
        ip = host_info["ip_address"]
        logger.info(f"Detecting OS on {ip}")
        
        # Simulate OS detection delay
        await asyncio.sleep(0.5)
        
        # Simulate different OS based on the last octet of the IP
        last_octet = int(ip.split('.')[-1])
        
        if last_octet == 2:
            host_info["os_info"] = {
                "name": "Linux 4.15",
                "accuracy": "95",
                "type": "Linux"
            }
        elif last_octet == 3:
            host_info["os_info"] = {
                "name": "Ubuntu 20.04",
                "accuracy": "98",
                "type": "Linux"
            }
        elif last_octet == 4:
            host_info["os_info"] = {
                "name": "Debian 10",
                "accuracy": "92",
                "type": "Linux"
            }
        elif last_octet == 5:
            host_info["os_info"] = {
                "name": "Alpine Linux 3.14",
                "accuracy": "90",
                "type": "Linux"
            }
        elif last_octet == 6:
            host_info["os_info"] = {
                "name": "Embedded Linux",
                "accuracy": "85",
                "type": "Linux"
            }
        elif last_octet == 7:
            host_info["os_info"] = {
                "name": "Ubuntu 20.04",
                "accuracy": "96",
                "type": "Linux"
            }
        
        logger.info(f"Detected OS on {ip}: {host_info['os_info']['name']}")
    
    def _get_hostname(self, ip: str) -> str:
        """Get hostname for an IP address"""
        try:
            if ip in self.nmap_scanner.all_hosts():
                hostnames = self.nmap_scanner[ip].hostnames()
                if hostnames and len(hostnames) > 0:
                    return hostnames[0]
            
            # Simulate hostnames based on IP
            last_octet = ip.split('.')[-1]
            if last_octet == '2':
                return "web-server"
            elif last_octet == '3':
                return "ssh-server"
            elif last_octet == '4':
                return "db-server"
            elif last_octet == '5':
                return "router"
            elif last_octet == '6':
                return "iot-device"
            elif last_octet == '7':
                return "monitoring"
            else:
                return f"host-{last_octet}"
                
        except Exception:
            return f"unknown-{ip}"

async def main():
    """Test the network scanner"""
    scanner = NetworkScanner()
    hosts = await scanner.scan_network("172.20.0.0/16")
    print(json.dumps(hosts, indent=2))
    
    if hosts:
        host_detail = await scanner.scan_host(hosts[0]["ip_address"])
        print(json.dumps(host_detail, indent=2))

if __name__ == "__main__":
    asyncio.run(main())