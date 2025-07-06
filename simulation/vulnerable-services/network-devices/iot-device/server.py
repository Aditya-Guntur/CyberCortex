#!/usr/bin/env python3
"""
Vulnerable IoT Device Simulation
This script simulates a vulnerable IoT device with multiple security issues:
- Default credentials
- Command injection vulnerability
- Insecure data storage
- Unencrypted communication
"""

import os
import json
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

# Default credentials (hardcoded)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"

# Insecure data storage
device_data = {
    "device_id": "IOT-DEVICE-001",
    "firmware_version": "1.0.2",
    "wifi_password": "SuperSecret123",
    "api_key": "a1b2c3d4e5f6g7h8i9j0",
    "settings": {
        "temperature": 72,
        "humidity": 50,
        "auto_update": True,
        "remote_access": True
    },
    "connected_users": []
}

class VulnerableIoTHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle GET requests with multiple vulnerabilities"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        # Basic authentication (but with default credentials)
        if "Authorization" not in self.headers:
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Basic realm=\"IoT Device\"")
            self.end_headers()
            return
        
        # Serve device info (information disclosure)
        if path == "/device/info":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(device_data).encode())
            return
            
        # Vulnerable firmware endpoint (path traversal)
        elif path.startswith("/firmware/"):
            firmware_file = path.replace("/firmware/", "")
            try:
                # Vulnerable to path traversal
                with open(firmware_file, "rb") as f:
                    self.send_response(200)
                    self.send_header("Content-type", "application/octet-stream")
                    self.end_headers()
                    self.wfile.write(f.read())
            except:
                self.send_response(404)
                self.end_headers()
            return
            
        # Command injection vulnerability
        elif path.startswith("/system/ping"):
            query = parse_qs(parsed_path.query)
            if "host" in query:
                host = query["host"][0]
                # Command injection vulnerability
                try:
                    # Vulnerable command execution
                    output = subprocess.check_output(f"ping -c 1 {host}", shell=True)
                    self.send_response(200)
                    self.send_header("Content-type", "text/plain")
                    self.end_headers()
                    self.wfile.write(output)
                except:
                    self.send_response(500)
                    self.end_headers()
                return
        
        # Default response
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"""
        <html>
        <head><title>IoT Device Control Panel</title></head>
        <body>
            <h1>IoT Device Control Panel</h1>
            <p>Welcome to the IoT device control panel. Available endpoints:</p>
            <ul>
                <li>/device/info - Get device information</li>
                <li>/firmware/[filename] - Download firmware files</li>
                <li>/system/ping?host=[hostname] - Ping a host</li>
            </ul>
        </body>
        </html>
        """)

    def do_POST(self):
        """Handle POST requests with multiple vulnerabilities"""
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode("utf-8")
        
        # Update settings (no input validation)
        if self.path == "/device/settings/update":
            try:
                new_settings = json.loads(post_data)
                # No validation, directly update settings
                device_data["settings"].update(new_settings)
                
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "success"}).encode())
            except:
                self.send_response(400)
                self.end_headers()
            return
            
        # Insecure login mechanism
        elif self.path == "/login":
            try:
                credentials = json.loads(post_data)
                username = credentials.get("username", "")
                password = credentials.get("password", "")
                
                # Hardcoded credentials check
                if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
                    # No session management, just return success
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "status": "success",
                        "message": "Login successful",
                        "api_key": device_data["api_key"]  # Exposing API key
                    }).encode())
                else:
                    self.send_response(401)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "status": "error",
                        "message": "Invalid credentials"
                    }).encode())
            except:
                self.send_response(400)
                self.end_headers()
            return
        
        # Default response
        self.send_response(404)
        self.end_headers()

def run_server(port=8888):
    """Run the vulnerable IoT device server"""
    server_address = ('', port)
    httpd = HTTPServer(server_address, VulnerableIoTHandler)
    print(f"Starting vulnerable IoT device simulation on port {port}")
    httpd.serve_forever()

if __name__ == "__main__":
    run_server()