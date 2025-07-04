"""
Tool Registry for MCP Servers

Centralized registry for tool capabilities, parameters, and metadata
with validation and discovery features.
"""

from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import json
import logging


class ParameterType(Enum):
    """Parameter types for tool validation"""
    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    ARRAY = "array"
    OBJECT = "object"


class RiskLevel(Enum):
    """Risk levels for tool operations"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ToolParameter:
    """Tool parameter definition"""
    name: str
    type: str
    description: str
    required: bool = False
    default_value: Any = None
    enum_values: List[str] = field(default_factory=list)
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    pattern: Optional[str] = None
    
    def validate(self, value: Any) -> tuple[bool, str]:
        """Validate parameter value"""
        try:
            # Check required
            if self.required and value is None:
                return False, f"Parameter '{self.name}' is required"
            
            if value is None:
                return True, "Valid"
            
            # Type validation
            if self.type == "string" and not isinstance(value, str):
                return False, f"Parameter '{self.name}' must be a string"
            elif self.type == "integer" and not isinstance(value, int):
                return False, f"Parameter '{self.name}' must be an integer"
            elif self.type == "number" and not isinstance(value, (int, float)):
                return False, f"Parameter '{self.name}' must be a number"
            elif self.type == "boolean" and not isinstance(value, bool):
                return False, f"Parameter '{self.name}' must be a boolean"
            elif self.type == "array" and not isinstance(value, list):
                return False, f"Parameter '{self.name}' must be an array"
            elif self.type == "object" and not isinstance(value, dict):
                return False, f"Parameter '{self.name}' must be an object"
            
            # Enum validation
            if self.enum_values and value not in self.enum_values:
                return False, f"Parameter '{self.name}' must be one of: {', '.join(self.enum_values)}"
            
            # Range validation for numbers
            if self.type in ["integer", "number"] and isinstance(value, (int, float)):
                if self.min_value is not None and value < self.min_value:
                    return False, f"Parameter '{self.name}' must be >= {self.min_value}"
                if self.max_value is not None and value > self.max_value:
                    return False, f"Parameter '{self.name}' must be <= {self.max_value}"
            
            # Pattern validation for strings
            if self.type == "string" and self.pattern and isinstance(value, str):
                import re
                if not re.match(self.pattern, value):
                    return False, f"Parameter '{self.name}' does not match required pattern"
            
            return True, "Valid"
            
        except Exception as e:
            return False, f"Validation error for parameter '{self.name}': {str(e)}"


@dataclass
class ToolCapability:
    """Tool capability definition"""
    name: str
    description: str
    parameters: List[ToolParameter]
    category: str
    requires_auth: bool = False
    risk_level: RiskLevel = RiskLevel.LOW
    tags: List[str] = field(default_factory=list)
    version: str = "1.0.0"
    deprecated: bool = False
    rate_limit: Optional[int] = None  # requests per minute
    timeout: Optional[int] = None  # seconds
    
    def validate_arguments(self, arguments: Dict[str, Any]) -> tuple[bool, List[str]]:
        """Validate tool arguments against parameters"""
        errors = []
        
        # Validate each parameter
        for param in self.parameters:
            value = arguments.get(param.name)
            is_valid, error_msg = param.validate(value)
            
            if not is_valid:
                errors.append(error_msg)
        
        # Check for unexpected parameters
        expected_params = {param.name for param in self.parameters}
        provided_params = set(arguments.keys())
        unexpected_params = provided_params - expected_params
        
        if unexpected_params:
            errors.append(f"Unexpected parameters: {', '.join(unexpected_params)}")
        
        return len(errors) == 0, errors
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'description': self.description,
            'parameters': [
                {
                    'name': param.name,
                    'type': param.type,
                    'description': param.description,
                    'required': param.required,
                    'default_value': param.default_value,
                    'enum_values': param.enum_values,
                    'min_value': param.min_value,
                    'max_value': param.max_value,
                    'pattern': param.pattern
                }
                for param in self.parameters
            ],
            'category': self.category,
            'requires_auth': self.requires_auth,
            'risk_level': self.risk_level.value,
            'tags': self.tags,
            'version': self.version,
            'deprecated': self.deprecated,
            'rate_limit': self.rate_limit,
            'timeout': self.timeout
        }


class ToolRegistry:
    """Registry for managing tool capabilities"""
    
    def __init__(self):
        self.capabilities: Dict[str, ToolCapability] = {}
        self.categories: Set[str] = set()
        self.logger = logging.getLogger(__name__)
    
    def register_tool(self, capability: ToolCapability):
        """Register a tool capability"""
        if capability.name in self.capabilities:
            self.logger.warning(f"Tool '{capability.name}' already registered, overwriting")
        
        self.capabilities[capability.name] = capability
        self.categories.add(capability.category)
        
        self.logger.debug(f"Registered tool: {capability.name} (category: {capability.category})")
    
    def unregister_tool(self, tool_name: str) -> bool:
        """Unregister a tool capability"""
        if tool_name in self.capabilities:
            del self.capabilities[tool_name]
            self.logger.debug(f"Unregistered tool: {tool_name}")
            return True
        return False
    
    def get_capability(self, tool_name: str) -> Optional[ToolCapability]:
        """Get tool capability by name"""
        return self.capabilities.get(tool_name)
    
    def get_all_capabilities(self) -> List[ToolCapability]:
        """Get all registered capabilities"""
        return list(self.capabilities.values())
    
    def get_capabilities_by_category(self, category: str) -> List[ToolCapability]:
        """Get capabilities by category"""
        return [cap for cap in self.capabilities.values() if cap.category == category]
    
    def get_capabilities_by_risk_level(self, risk_level: RiskLevel) -> List[ToolCapability]:
        """Get capabilities by risk level"""
        return [cap for cap in self.capabilities.values() if cap.risk_level == risk_level]
    
    def search_capabilities(self, query: str) -> List[ToolCapability]:
        """Search capabilities by name or description"""
        query_lower = query.lower()
        results = []
        
        for capability in self.capabilities.values():
            if (query_lower in capability.name.lower() or 
                query_lower in capability.description.lower() or
                any(query_lower in tag.lower() for tag in capability.tags)):
                results.append(capability)
        
        return results
    
    def get_categories(self) -> List[str]:
        """Get all available categories"""
        return sorted(list(self.categories))
    
    def validate_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> tuple[bool, List[str]]:
        """Validate a tool call"""
        capability = self.get_capability(tool_name)
        
        if not capability:
            return False, [f"Tool '{tool_name}' not found"]
        
        if capability.deprecated:
            return False, [f"Tool '{tool_name}' is deprecated"]
        
        return capability.validate_arguments(arguments)
    
    def get_registry_stats(self) -> Dict[str, Any]:
        """Get registry statistics"""
        capabilities = list(self.capabilities.values())
        
        risk_level_counts = {}
        for risk_level in RiskLevel:
            risk_level_counts[risk_level.value] = len([
                cap for cap in capabilities if cap.risk_level == risk_level
            ])
        
        category_counts = {}
        for category in self.categories:
            category_counts[category] = len([
                cap for cap in capabilities if cap.category == category
            ])
        
        return {
            'total_tools': len(capabilities),
            'total_categories': len(self.categories),
            'risk_level_breakdown': risk_level_counts,
            'category_breakdown': category_counts,
            'deprecated_tools': len([cap for cap in capabilities if cap.deprecated]),
            'auth_required_tools': len([cap for cap in capabilities if cap.requires_auth])
        }
    
    def export_registry(self) -> Dict[str, Any]:
        """Export registry to dictionary"""
        return {
            'capabilities': {
                name: capability.to_dict() 
                for name, capability in self.capabilities.items()
            },
            'categories': list(self.categories),
            'stats': self.get_registry_stats()
        }
    
    def import_registry(self, registry_data: Dict[str, Any]):
        """Import registry from dictionary"""
        capabilities_data = registry_data.get('capabilities', {})
        
        for name, cap_data in capabilities_data.items():
            try:
                # Reconstruct parameters
                parameters = []
                for param_data in cap_data.get('parameters', []):
                    param = ToolParameter(
                        name=param_data['name'],
                        type=param_data['type'],
                        description=param_data['description'],
                        required=param_data.get('required', False),
                        default_value=param_data.get('default_value'),
                        enum_values=param_data.get('enum_values', []),
                        min_value=param_data.get('min_value'),
                        max_value=param_data.get('max_value'),
                        pattern=param_data.get('pattern')
                    )
                    parameters.append(param)
                
                # Reconstruct capability
                capability = ToolCapability(
                    name=cap_data['name'],
                    description=cap_data['description'],
                    parameters=parameters,
                    category=cap_data['category'],
                    requires_auth=cap_data.get('requires_auth', False),
                    risk_level=RiskLevel(cap_data.get('risk_level', 'low')),
                    tags=cap_data.get('tags', []),
                    version=cap_data.get('version', '1.0.0'),
                    deprecated=cap_data.get('deprecated', False),
                    rate_limit=cap_data.get('rate_limit'),
                    timeout=cap_data.get('timeout')
                )
                
                self.register_tool(capability)
                
            except Exception as e:
                self.logger.error(f"Failed to import capability '{name}': {str(e)}")
    
    def save_to_file(self, file_path: str):
        """Save registry to JSON file"""
        try:
            with open(file_path, 'w') as f:
                json.dump(self.export_registry(), f, indent=2)
            self.logger.info(f"Registry saved to {file_path}")
        except Exception as e:
            self.logger.error(f"Failed to save registry: {str(e)}")
    
    def load_from_file(self, file_path: str):
        """Load registry from JSON file"""
        try:
            with open(file_path, 'r') as f:
                registry_data = json.load(f)
            self.import_registry(registry_data)
            self.logger.info(f"Registry loaded from {file_path}")
        except Exception as e:
            self.logger.error(f"Failed to load registry: {str(e)}")


# Example usage and testing
def create_example_registry() -> ToolRegistry:
    """Create example registry with sample tools"""
    registry = ToolRegistry()
    
    # Example: Network scan tool
    network_scan = ToolCapability(
        name="network_scan",
        description="Perform network discovery scan",
        parameters=[
            ToolParameter("target", "string", "Target network or host", required=True),
            ToolParameter("ports", "string", "Port range to scan", default_value="1-1000"),
            ToolParameter("timeout", "integer", "Scan timeout in seconds", default_value=300, min_value=1, max_value=3600),
            ToolParameter("scan_type", "string", "Type of scan", enum_values=["tcp", "udp", "syn"], default_value="tcp")
        ],
        category="network_discovery",
        requires_auth=False,
        risk_level=RiskLevel.MEDIUM,
        tags=["network", "discovery", "nmap"],
        rate_limit=10,  # 10 scans per minute
        timeout=600
    )
    
    # Example: Vulnerability lookup tool
    vuln_lookup = ToolCapability(
        name="vulnerability_lookup",
        description="Look up vulnerability information",
        parameters=[
            ToolParameter("cve_id", "string", "CVE identifier", required=True, pattern=r"CVE-\d{4}-\d{4,7}"),
            ToolParameter("include_details", "boolean", "Include detailed information", default_value=True)
        ],
        category="vulnerability_research",
        requires_auth=False,
        risk_level=RiskLevel.LOW,
        tags=["vulnerability", "cve", "research"]
    )
    
    # Example: System configuration check
    config_check = ToolCapability(
        name="system_config_check",
        description="Check system configuration for compliance",
        parameters=[
            ToolParameter("framework", "string", "Compliance framework", required=True, 
                         enum_values=["soc2", "iso27001", "nist", "pci"]),
            ToolParameter("severity_filter", "string", "Minimum severity level", 
                         enum_values=["low", "medium", "high", "critical"], default_value="medium"),
            ToolParameter("categories", "array", "Categories to check", default_value=[])
        ],
        category="compliance_assessment",
        requires_auth=True,
        risk_level=RiskLevel.LOW,
        tags=["compliance", "configuration", "assessment"]
    )
    
    # Register tools
    registry.register_tool(network_scan)
    registry.register_tool(vuln_lookup)
    registry.register_tool(config_check)
    
    return registry


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    # Create example registry
    registry = create_example_registry()
    
    # Print statistics
    stats = registry.get_registry_stats()
    print("Registry Statistics:")
    print(json.dumps(stats, indent=2))
    
    # Test tool validation
    print("\nTesting tool validation:")
    
    # Valid call
    is_valid, errors = registry.validate_tool_call("network_scan", {
        "target": "192.168.1.0/24",
        "ports": "80,443,22",
        "timeout": 300
    })
    print(f"Valid call: {is_valid}, Errors: {errors}")
    
    # Invalid call (missing required parameter)
    is_valid, errors = registry.validate_tool_call("network_scan", {
        "ports": "80,443,22"
    })
    print(f"Invalid call: {is_valid}, Errors: {errors}")
    
    # Search capabilities
    print("\nSearching for 'network' tools:")
    results = registry.search_capabilities("network")
    for result in results:
        print(f"- {result.name}: {result.description}")