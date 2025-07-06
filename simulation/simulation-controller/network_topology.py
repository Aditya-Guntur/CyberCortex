#!/usr/bin/env python3
"""
Network Topology Generator for CyberCortex Simulation

Generates and visualizes the network topology of the simulation environment,
including hosts, services, and discovered vulnerabilities.
"""

import os
import sys
import json
import logging
import asyncio
import networkx as nx
import matplotlib.pyplot as plt
from typing import Dict, List, Optional, Any
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("NetworkTopology")

class NetworkTopologyGenerator:
    """
    Generates and visualizes the network topology of the simulation environment.
    """
    
    def __init__(self):
        self.graph = nx.Graph()
        self.node_positions = {}
        self.node_colors = {}
        self.node_sizes = {}
        self.edge_colors = {}
        self.last_update = None
        
        logger.info("Network Topology Generator initialized")
    
    async def initialize(self):
        """Initialize the network topology with default structure"""
        logger.info("Initializing network topology")
        
        # Clear existing graph
        self.graph.clear()
        
        # Add router as central node
        self.graph.add_node("router", type="router", ip="172.20.0.5")
        
        # Set initial positions
        self.node_positions = {
            "router": (0, 0)
        }
        
        # Set node colors based on type
        self.node_colors = {
            "router": "orange"
        }
        
        # Set node sizes based on type
        self.node_sizes = {
            "router": 1500
        }
        
        self.last_update = datetime.now()
        
        logger.info("Network topology initialized")
    
    async def generate_topology(self, hosts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate network topology based on discovered hosts.
        
        Args:
            hosts: List of discovered hosts
            
        Returns:
            topology: Network topology data for visualization
        """
        logger.info(f"Generating network topology for {len(hosts)} hosts")
        
        # Update graph with discovered hosts
        for host in hosts:
            ip_address = host.get("ip_address")
            hostname = host.get("hostname", ip_address)
            host_type = self._determine_host_type(host)
            
            # Add node if it doesn't exist
            if hostname not in self.graph:
                self.graph.add_node(hostname, type=host_type, ip=ip_address)
                
                # Add edge to router
                self.graph.add_edge("router", hostname)
                
                # Set node position (radial layout around router)
                angle = len(self.graph.nodes) * (360 / (len(hosts) + 1))
                radius = 5
                x = radius * nx.utils.cos(angle)
                y = radius * nx.utils.sin(angle)
                self.node_positions[hostname] = (x, y)
                
                # Set node color based on type
                self.node_colors[hostname] = self._get_node_color(host_type)
                
                # Set node size based on type
                self.node_sizes[hostname] = self._get_node_size(host_type)
                
                # Set edge color
                self.edge_colors[("router", hostname)] = "gray"
            
            # Update node attributes
            self.graph.nodes[hostname]["services"] = host.get("services", [])
            self.graph.nodes[hostname]["os_info"] = host.get("os_info")
            self.graph.nodes[hostname]["last_seen"] = host.get("last_seen")
            
            # Update node color based on vulnerabilities
            if "vulnerabilities" in host:
                vuln_count = len(host["vulnerabilities"])
                if vuln_count > 0:
                    max_severity = max([v.get("severity", "low") for v in host["vulnerabilities"]], 
                                      key=self._severity_to_value)
                    self.node_colors[hostname] = self._get_severity_color(max_severity)
        
        self.last_update = datetime.now()
        
        # Generate topology data
        topology = {
            "nodes": self._get_nodes_data(),
            "edges": self._get_edges_data(),
            "timestamp": self.last_update.isoformat(),
            "node_count": len(self.graph.nodes),
            "edge_count": len(self.graph.edges)
        }
        
        logger.info(f"Network topology generated with {topology['node_count']} nodes and {topology['edge_count']} edges")
        
        return topology
    
    async def visualize_topology(self, output_file: str = "network_topology.png"):
        """
        Visualize the network topology and save to a file.
        
        Args:
            output_file: Path to save the visualization
        """
        logger.info(f"Visualizing network topology to {output_file}")
        
        plt.figure(figsize=(12, 10))
        
        # Draw nodes
        nx.draw_networkx_nodes(
            self.graph,
            pos=self.node_positions,
            node_color=list(self.node_colors.values()),
            node_size=list(self.node_sizes.values())
        )
        
        # Draw edges
        nx.draw_networkx_edges(
            self.graph,
            pos=self.node_positions,
            edge_color="gray",
            width=1.5
        )
        
        # Draw labels
        nx.draw_networkx_labels(
            self.graph,
            pos=self.node_positions,
            font_size=10,
            font_weight="bold"
        )
        
        plt.title("CyberCortex Simulation Network Topology")
        plt.axis("off")
        
        # Save to file
        plt.savefig(output_file, dpi=300, bbox_inches="tight")
        plt.close()
        
        logger.info(f"Network topology visualization saved to {output_file}")
    
    def _get_nodes_data(self) -> List[Dict[str, Any]]:
        """Get node data for visualization"""
        nodes = []
        
        for node_name in self.graph.nodes:
            node = self.graph.nodes[node_name]
            position = self.node_positions.get(node_name, (0, 0))
            
            nodes.append({
                "id": node_name,
                "label": node_name,
                "type": node.get("type", "unknown"),
                "ip": node.get("ip", ""),
                "services": node.get("services", []),
                "os_info": node.get("os_info"),
                "last_seen": node.get("last_seen"),
                "x": position[0],
                "y": position[1],
                "color": self.node_colors.get(node_name, "gray"),
                "size": self.node_sizes.get(node_name, 500)
            })
        
        return nodes
    
    def _get_edges_data(self) -> List[Dict[str, Any]]:
        """Get edge data for visualization"""
        edges = []
        
        for source, target in self.graph.edges:
            edges.append({
                "from": source,
                "to": target,
                "color": self.edge_colors.get((source, target), "gray"),
                "width": 1
            })
        
        return edges
    
    def _determine_host_type(self, host: Dict[str, Any]) -> str:
        """Determine the type of host based on its services and characteristics"""
        ip_address = host.get("ip_address", "")
        services = host.get("services", [])
        
        # Check based on IP address (for simulation)
        last_octet = ip_address.split(".")[-1]
        
        if last_octet == "2":
            return "web_server"
        elif last_octet == "3":
            return "ssh_server"
        elif last_octet == "4":
            return "database"
        elif last_octet == "5":
            return "router"
        elif last_octet == "6":
            return "iot_device"
        elif last_octet == "7":
            return "monitoring"
        
        # Check based on services
        service_names = [s.get("name", "").lower() for s in services]
        
        if "http" in service_names or "https" in service_names:
            return "web_server"
        elif "ssh" in service_names:
            return "ssh_server"
        elif "mysql" in service_names or "postgresql" in service_names:
            return "database"
        elif "snmp" in service_names:
            return "network_device"
        
        return "unknown"
    
    def _get_node_color(self, node_type: str) -> str:
        """Get color for a node based on its type"""
        color_map = {
            "router": "orange",
            "web_server": "blue",
            "ssh_server": "green",
            "database": "purple",
            "iot_device": "red",
            "monitoring": "cyan",
            "network_device": "yellow"
        }
        
        return color_map.get(node_type, "gray")
    
    def _get_node_size(self, node_type: str) -> int:
        """Get size for a node based on its type"""
        size_map = {
            "router": 1500,
            "web_server": 1000,
            "ssh_server": 1000,
            "database": 1000,
            "iot_device": 800,
            "monitoring": 1000,
            "network_device": 800
        }
        
        return size_map.get(node_type, 500)
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for a node based on vulnerability severity"""
        severity_colors = {
            "critical": "darkred",
            "high": "red",
            "medium": "orange",
            "low": "yellow",
            "info": "blue"
        }
        
        return severity_colors.get(severity, "gray")
    
    def _severity_to_value(self, severity: str) -> int:
        """Convert severity string to numeric value for comparison"""
        severity_values = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "info": 0
        }
        
        return severity_values.get(severity.lower(), 0)

async def main():
    """Test the network topology generator"""
    generator = NetworkTopologyGenerator()
    await generator.initialize()
    
    # Sample hosts
    hosts = [
        {
            "ip_address": "172.20.0.2",
            "hostname": "web-server",
            "status": "up",
            "services": [
                {"name": "http", "port": 80, "protocol": "tcp"}
            ],
            "os_info": {"name": "Linux 4.15", "type": "Linux"},
            "vulnerabilities": [
                {"id": "vuln-1", "severity": "high", "type": "sql_injection"}
            ]
        },
        {
            "ip_address": "172.20.0.3",
            "hostname": "ssh-server",
            "status": "up",
            "services": [
                {"name": "ssh", "port": 22, "protocol": "tcp"}
            ],
            "os_info": {"name": "Ubuntu 20.04", "type": "Linux"}
        },
        {
            "ip_address": "172.20.0.4",
            "hostname": "db-server",
            "status": "up",
            "services": [
                {"name": "mysql", "port": 3306, "protocol": "tcp"}
            ],
            "os_info": {"name": "Debian 10", "type": "Linux"},
            "vulnerabilities": [
                {"id": "vuln-2", "severity": "critical", "type": "weak_password"}
            ]
        },
        {
            "ip_address": "172.20.0.6",
            "hostname": "iot-device",
            "status": "up",
            "services": [
                {"name": "http", "port": 8888, "protocol": "tcp"}
            ],
            "os_info": {"name": "Embedded Linux", "type": "Linux"},
            "vulnerabilities": [
                {"id": "vuln-3", "severity": "critical", "type": "command_injection"}
            ]
        }
    ]
    
    # Generate topology
    topology = await generator.generate_topology(hosts)
    print(json.dumps(topology, indent=2))
    
    # Visualize topology
    await generator.visualize_topology()

if __name__ == "__main__":
    asyncio.run(main())