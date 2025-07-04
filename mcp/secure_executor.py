"""
Secure Executor for MCP Tools

Provides secure execution environment for security tools with sandboxing,
resource limits, and comprehensive logging.
"""

import asyncio
import subprocess
import tempfile
import shutil
import os
import signal
import psutil
import logging
import time
import json
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, asdict
import docker
import resource
from contextlib import contextmanager


@dataclass
class ExecutionResult:
    """Result of command execution"""
    command: List[str]
    returncode: int
    stdout: str
    stderr: str
    execution_time: float
    resource_usage: Dict[str, Any]
    security_violations: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class SecurityPolicy:
    """Security policy for command execution"""
    max_execution_time: int = 300  # seconds
    max_memory_mb: int = 1024
    max_cpu_percent: float = 80.0
    allowed_network_access: bool = False
    allowed_file_paths: List[str] = None
    blocked_file_paths: List[str] = None
    allowed_commands: List[str] = None
    blocked_commands: List[str] = None
    require_sandbox: bool = True
    max_processes: int = 10
    
    def __post_init__(self):
        if self.allowed_file_paths is None:
            self.allowed_file_paths = ['/tmp', '/var/tmp']
        if self.blocked_file_paths is None:
            self.blocked_file_paths = ['/etc/passwd', '/etc/shadow', '/root']
        if self.allowed_commands is None:
            self.allowed_commands = []
        if self.blocked_commands is None:
            self.blocked_commands = ['rm', 'dd', 'mkfs', 'fdisk']


class ResourceMonitor:
    """Monitor resource usage during execution"""
    
    def __init__(self, pid: int, policy: SecurityPolicy):
        self.pid = pid
        self.policy = policy
        self.process: Optional[psutil.Process] = None
        self.violations: List[str] = []
        self.peak_memory = 0
        self.peak_cpu = 0.0
        self.logger = logging.getLogger(__name__)
        
    async def start_monitoring(self):
        """Start resource monitoring"""
        try:
            self.process = psutil.Process(self.pid)
            
            while self.process.is_running():
                try:
                    # Check memory usage
                    memory_info = self.process.memory_info()
                    memory_mb = memory_info.rss / 1024 / 1024
                    self.peak_memory = max(self.peak_memory, memory_mb)
                    
                    if memory_mb > self.policy.max_memory_mb:
                        violation = f"Memory limit exceeded: {memory_mb:.1f}MB > {self.policy.max_memory_mb}MB"
                        self.violations.append(violation)
                        self.logger.warning(violation)
                        self._terminate_process()
                        break
                    
                    # Check CPU usage
                    cpu_percent = self.process.cpu_percent()
                    self.peak_cpu = max(self.peak_cpu, cpu_percent)
                    
                    if cpu_percent > self.policy.max_cpu_percent:
                        violation = f"CPU limit exceeded: {cpu_percent:.1f}% > {self.policy.max_cpu_percent}%"
                        self.violations.append(violation)
                        self.logger.warning(violation)
                    
                    # Check number of child processes
                    children = self.process.children(recursive=True)
                    if len(children) > self.policy.max_processes:
                        violation = f"Process limit exceeded: {len(children)} > {self.policy.max_processes}"
                        self.violations.append(violation)
                        self.logger.warning(violation)
                        self._terminate_process()
                        break
                    
                    # Check network connections if not allowed
                    if not self.policy.allowed_network_access:
                        connections = self.process.connections()
                        if connections:
                            violation = "Network access detected but not allowed"
                            self.violations.append(violation)
                            self.logger.warning(violation)
                    
                    await asyncio.sleep(0.5)  # Check every 500ms
                    
                except psutil.NoSuchProcess:
                    break
                except Exception as e:
                    self.logger.error(f"Error monitoring process: {str(e)}")
                    break
                    
        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {str(e)}")
    
    def _terminate_process(self):
        """Terminate the monitored process"""
        try:
            if self.process and self.process.is_running():
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except psutil.TimeoutExpired:
                    self.process.kill()
        except Exception as e:
            self.logger.error(f"Failed to terminate process: {str(e)}")
    
    def get_resource_usage(self) -> Dict[str, Any]:
        """Get resource usage statistics"""
        return {
            'peak_memory_mb': self.peak_memory,
            'peak_cpu_percent': self.peak_cpu,
            'violations': self.violations
        }


class SandboxManager:
    """Manages sandboxed execution environments"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.docker_client = None
        
        try:
            self.docker_client = docker.from_env()
        except Exception as e:
            self.logger.warning(f"Docker not available: {str(e)}")
    
    async def create_sandbox(self, policy: SecurityPolicy) -> Optional[str]:
        """Create a sandbox environment"""
        if not self.docker_client or not policy.require_sandbox:
            return None
        
        try:
            # Create a minimal container for sandboxing
            container = self.docker_client.containers.run(
                'alpine:latest',
                command='sleep 3600',  # Keep container alive
                detach=True,
                mem_limit=f"{policy.max_memory_mb}m",
                cpu_period=100000,
                cpu_quota=int(policy.max_cpu_percent * 1000),
                network_mode='none' if not policy.allowed_network_access else 'bridge',
                remove=True,
                security_opt=['no-new-privileges'],
                cap_drop=['ALL'],
                read_only=True,
                tmpfs={'/tmp': 'rw,noexec,nosuid,size=100m'}
            )
            
            self.logger.info(f"Created sandbox container: {container.id[:12]}")
            return container.id
            
        except Exception as e:
            self.logger.error(f"Failed to create sandbox: {str(e)}")
            return None
    
    async def execute_in_sandbox(self, container_id: str, command: List[str], 
                                working_dir: str = '/tmp') -> ExecutionResult:
        """Execute command in sandbox"""
        try:
            container = self.docker_client.containers.get(container_id)
            
            start_time = time.time()
            
            # Execute command in container
            exec_result = container.exec_run(
                command,
                workdir=working_dir,
                user='nobody',
                environment={'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'}
            )
            
            execution_time = time.time() - start_time
            
            return ExecutionResult(
                command=command,
                returncode=exec_result.exit_code,
                stdout=exec_result.output.decode('utf-8', errors='replace'),
                stderr='',  # Docker exec_run combines stdout/stderr
                execution_time=execution_time,
                resource_usage={'sandboxed': True},
                security_violations=[]
            )
            
        except Exception as e:
            self.logger.error(f"Sandbox execution failed: {str(e)}")
            return ExecutionResult(
                command=command,
                returncode=-1,
                stdout='',
                stderr=f"Sandbox execution failed: {str(e)}",
                execution_time=0.0,
                resource_usage={},
                security_violations=[f"Sandbox execution failed: {str(e)}"]
            )
    
    async def cleanup_sandbox(self, container_id: str):
        """Clean up sandbox environment"""
        try:
            container = self.docker_client.containers.get(container_id)
            container.stop(timeout=5)
            self.logger.info(f"Cleaned up sandbox container: {container_id[:12]}")
        except Exception as e:
            self.logger.error(f"Failed to cleanup sandbox: {str(e)}")


class SecureExecutor:
    """Secure executor for running security tools"""
    
    def __init__(self, default_policy: SecurityPolicy = None):
        self.default_policy = default_policy or SecurityPolicy()
        self.sandbox_manager = SandboxManager()
        self.logger = logging.getLogger(__name__)
        
        # Command whitelist for security tools
        self.security_tools = {
            'nmap': {
                'executable': '/usr/bin/nmap',
                'allowed_args': ['-sn', '-sS', '-sU', '-sV', '-A', '-O', '-T0', '-T1', '-T2', '-T3', '-T4', '-T5'],
                'blocked_args': ['--script=*exploit*', '--script=*brute*'],
                'requires_root': False
            },
            'tshark': {
                'executable': '/usr/bin/tshark',
                'allowed_args': ['-i', '-r', '-w', '-f', '-Y', '-q', '-z'],
                'blocked_args': [],
                'requires_root': True
            },
            'dig': {
                'executable': '/usr/bin/dig',
                'allowed_args': ['+short', '+trace', '+noall', '+answer'],
                'blocked_args': [],
                'requires_root': False
            },
            'curl': {
                'executable': '/usr/bin/curl',
                'allowed_args': ['-s', '-I', '-L', '--max-time', '--connect-timeout'],
                'blocked_args': ['--upload-file', '--data-binary'],
                'requires_root': False
            }
        }
    
    async def execute_command(self, command: List[str], policy: SecurityPolicy = None,
                            working_dir: str = None, timeout: int = None,
                            requires_root: bool = False) -> ExecutionResult:
        """Execute command with security controls"""
        
        policy = policy or self.default_policy
        timeout = timeout or policy.max_execution_time
        working_dir = working_dir or '/tmp'
        
        # Validate command
        validation_result = self._validate_command(command, policy)
        if not validation_result[0]:
            return ExecutionResult(
                command=command,
                returncode=-1,
                stdout='',
                stderr=f"Command validation failed: {validation_result[1]}",
                execution_time=0.0,
                resource_usage={},
                security_violations=[validation_result[1]]
            )
        
        # Check if sandboxing is required and available
        if policy.require_sandbox and self.sandbox_manager.docker_client:
            return await self._execute_sandboxed(command, policy, working_dir, timeout)
        else:
            return await self._execute_native(command, policy, working_dir, timeout, requires_root)
    
    def _validate_command(self, command: List[str], policy: SecurityPolicy) -> Tuple[bool, str]:
        """Validate command against security policy"""
        if not command:
            return False, "Empty command"
        
        executable = command[0]
        
        # Check if command is in allowed list
        if policy.allowed_commands and executable not in policy.allowed_commands:
            return False, f"Command '{executable}' not in allowed list"
        
        # Check if command is in blocked list
        if executable in policy.blocked_commands:
            return False, f"Command '{executable}' is blocked"
        
        # Validate security tool usage
        if executable in self.security_tools:
            tool_config = self.security_tools[executable]
            
            # Check arguments
            for arg in command[1:]:
                # Check for blocked arguments
                for blocked_pattern in tool_config['blocked_args']:
                    if blocked_pattern.replace('*', '') in arg:
                        return False, f"Blocked argument pattern: {blocked_pattern}"
        
        # Check for dangerous patterns
        dangerous_patterns = [
            '&&', '||', ';', '|', '>', '>>', '<', '`', '$(',
            'rm -rf', 'dd if=', 'mkfs', 'fdisk', 'format'
        ]
        
        command_str = ' '.join(command)
        for pattern in dangerous_patterns:
            if pattern in command_str:
                return False, f"Dangerous pattern detected: {pattern}"
        
        return True, "Valid"
    
    async def _execute_sandboxed(self, command: List[str], policy: SecurityPolicy,
                                working_dir: str, timeout: int) -> ExecutionResult:
        """Execute command in sandbox"""
        container_id = None
        
        try:
            # Create sandbox
            container_id = await self.sandbox_manager.create_sandbox(policy)
            if not container_id:
                return await self._execute_native(command, policy, working_dir, timeout, False)
            
            # Execute in sandbox with timeout
            try:
                result = await asyncio.wait_for(
                    self.sandbox_manager.execute_in_sandbox(container_id, command, working_dir),
                    timeout=timeout
                )
                return result
                
            except asyncio.TimeoutError:
                return ExecutionResult(
                    command=command,
                    returncode=-1,
                    stdout='',
                    stderr='Command timed out',
                    execution_time=timeout,
                    resource_usage={},
                    security_violations=['Execution timeout']
                )
                
        finally:
            # Cleanup sandbox
            if container_id:
                await self.sandbox_manager.cleanup_sandbox(container_id)
    
    async def _execute_native(self, command: List[str], policy: SecurityPolicy,
                             working_dir: str, timeout: int, requires_root: bool) -> ExecutionResult:
        """Execute command natively with monitoring"""
        
        start_time = time.time()
        process = None
        monitor = None
        
        try:
            # Create secure working directory
            with self._create_secure_workdir(working_dir) as secure_workdir:
                
                # Prepare environment
                env = os.environ.copy()
                env['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
                
                # Start process
                process = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=secure_workdir,
                    env=env,
                    preexec_fn=self._setup_process_limits if not requires_root else None
                )
                
                # Start monitoring
                monitor = ResourceMonitor(process.pid, policy)
                monitor_task = asyncio.create_task(monitor.start_monitoring())
                
                try:
                    # Wait for completion with timeout
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=timeout
                    )
                    
                    execution_time = time.time() - start_time
                    
                    # Cancel monitoring
                    monitor_task.cancel()
                    
                    return ExecutionResult(
                        command=command,
                        returncode=process.returncode,
                        stdout=stdout.decode('utf-8', errors='replace'),
                        stderr=stderr.decode('utf-8', errors='replace'),
                        execution_time=execution_time,
                        resource_usage=monitor.get_resource_usage(),
                        security_violations=monitor.violations
                    )
                    
                except asyncio.TimeoutError:
                    # Kill process on timeout
                    if process:
                        process.terminate()
                        try:
                            await asyncio.wait_for(process.wait(), timeout=5)
                        except asyncio.TimeoutError:
                            process.kill()
                    
                    monitor_task.cancel()
                    
                    return ExecutionResult(
                        command=command,
                        returncode=-1,
                        stdout='',
                        stderr='Command timed out',
                        execution_time=time.time() - start_time,
                        resource_usage=monitor.get_resource_usage() if monitor else {},
                        security_violations=['Execution timeout']
                    )
                    
        except Exception as e:
            execution_time = time.time() - start_time
            
            return ExecutionResult(
                command=command,
                returncode=-1,
                stdout='',
                stderr=f"Execution failed: {str(e)}",
                execution_time=execution_time,
                resource_usage={},
                security_violations=[f"Execution failed: {str(e)}"]
            )
    
    def _setup_process_limits(self):
        """Setup resource limits for child process"""
        try:
            # Set memory limit
            resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024))  # 1GB
            
            # Set CPU time limit
            resource.setrlimit(resource.RLIMIT_CPU, (300, 300))  # 5 minutes
            
            # Set file size limit
            resource.setrlimit(resource.RLIMIT_FSIZE, (100 * 1024 * 1024, 100 * 1024 * 1024))  # 100MB
            
            # Set process limit
            resource.setrlimit(resource.RLIMIT_NPROC, (10, 10))
            
        except Exception as e:
            logging.getLogger(__name__).warning(f"Failed to set resource limits: {str(e)}")
    
    @contextmanager
    def _create_secure_workdir(self, base_dir: str):
        """Create secure temporary working directory"""
        temp_dir = None
        try:
            # Create temporary directory
            temp_dir = tempfile.mkdtemp(dir=base_dir, prefix='secure_exec_')
            
            # Set restrictive permissions
            os.chmod(temp_dir, 0o700)
            
            yield temp_dir
            
        finally:
            # Cleanup
            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                except Exception as e:
                    logging.getLogger(__name__).warning(f"Failed to cleanup temp dir: {str(e)}")
    
    async def execute_security_tool(self, tool_name: str, args: List[str], 
                                   target: str = None, policy: SecurityPolicy = None) -> ExecutionResult:
        """Execute a specific security tool with predefined configuration"""
        
        if tool_name not in self.security_tools:
            return ExecutionResult(
                command=[tool_name] + args,
                returncode=-1,
                stdout='',
                stderr=f"Unknown security tool: {tool_name}",
                execution_time=0.0,
                resource_usage={},
                security_violations=[f"Unknown security tool: {tool_name}"]
            )
        
        tool_config = self.security_tools[tool_name]
        
        # Build command
        command = [tool_config['executable']] + args
        if target:
            command.append(target)
        
        # Use tool-specific policy if not provided
        if not policy:
            policy = SecurityPolicy(
                max_execution_time=600,  # 10 minutes for security tools
                max_memory_mb=2048,      # 2GB for security tools
                allowed_network_access=True,  # Security tools often need network access
                require_sandbox=True
            )
        
        return await self.execute_command(
            command=command,
            policy=policy,
            requires_root=tool_config['requires_root']
        )
    
    def get_supported_tools(self) -> List[str]:
        """Get list of supported security tools"""
        return list(self.security_tools.keys())
    
    def get_tool_info(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific tool"""
        if tool_name in self.security_tools:
            return self.security_tools[tool_name].copy()
        return None


# Example usage
async def main():
    """Example usage of SecureExecutor"""
    
    # Create executor with custom policy
    policy = SecurityPolicy(
        max_execution_time=60,
        max_memory_mb=512,
        allowed_network_access=True,
        require_sandbox=False  # Disable for testing
    )
    
    executor = SecureExecutor(policy)
    
    # Test basic command execution
    print("Testing basic command execution:")
    result = await executor.execute_command(['echo', 'Hello, World!'])
    print(f"Return code: {result.returncode}")
    print(f"Output: {result.stdout.strip()}")
    print(f"Execution time: {result.execution_time:.2f}s")
    print(f"Violations: {result.security_violations}")
    
    # Test security tool execution
    print("\nTesting security tool execution:")
    result = await executor.execute_security_tool('nmap', ['-sn'], '127.0.0.1')
    print(f"Return code: {result.returncode}")
    print(f"Output length: {len(result.stdout)} characters")
    print(f"Execution time: {result.execution_time:.2f}s")
    print(f"Violations: {result.security_violations}")
    
    # Test blocked command
    print("\nTesting blocked command:")
    result = await executor.execute_command(['rm', '-rf', '/tmp/test'])
    print(f"Return code: {result.returncode}")
    print(f"Error: {result.stderr}")
    print(f"Violations: {result.security_violations}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())