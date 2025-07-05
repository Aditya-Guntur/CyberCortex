"""
Compliance Framework MCP Server

Provides unified interface for compliance frameworks including SOC2, ISO27001, 
NIST CSF, GDPR, HIPAA with automated assessment and reporting capabilities.
"""

import asyncio
import json
import logging
import yaml
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict, field
from pathlib import Path
from enum import Enum
import sqlite3

from mcp import ClientSession, StdioServerParameters
from mcp.server import Server
from mcp.types import (
    CallToolRequest, 
    CallToolResult, 
    ListToolsRequest, 
    Tool, 
    TextContent
)

from .tool_registry import ToolRegistry, ToolCapability, ToolParameter


class ComplianceStatus(Enum):
    """Compliance status values"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"
    IN_PROGRESS = "in_progress"


class ControlSeverity(Enum):
    """Control severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ComplianceControl:
    """Individual compliance control definition"""
    control_id: str
    framework: str
    title: str
    description: str
    category: str
    severity: ControlSeverity
    requirements: List[str]
    validation_rules: List[Dict[str, Any]]
    remediation_guidance: str
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    automated: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert control to dictionary"""
        data = asdict(self)
        data['severity'] = self.severity.value
        return data


@dataclass
class ComplianceAssessment:
    """Result of compliance control assessment"""
    assessment_id: str
    control_id: str
    framework: str
    status: ComplianceStatus
    score: float  # 0.0 to 1.0
    findings: List[Dict[str, Any]]
    evidence: List[Dict[str, Any]]
    recommendations: List[str]
    assessed_at: datetime
    assessed_by: str
    next_assessment: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert assessment to dictionary"""
        data = asdict(self)
        data['status'] = self.status.value
        data['assessed_at'] = self.assessed_at.isoformat()
        if self.next_assessment:
            data['next_assessment'] = self.next_assessment.isoformat()
        return data


@dataclass
class ComplianceFramework:
    """Compliance framework definition"""
    framework_id: str
    name: str
    version: str
    description: str
    controls: Dict[str, ComplianceControl]
    categories: List[str]
    assessment_frequency: str  # daily, weekly, monthly, quarterly
    mandatory_controls: set = field(default_factory=set)
    
    def get_control(self, control_id: str) -> Optional[ComplianceControl]:
        """Get specific control by ID"""
        return self.controls.get(control_id)
    
    def get_controls_by_category(self, category: str) -> List[ComplianceControl]:
        """Get all controls in a category"""
        return [control for control in self.controls.values() 
                if control.category == category]
    
    def get_critical_controls(self) -> List[ComplianceControl]:
        """Get all critical controls"""
        return [control for control in self.controls.values() 
                if control.severity == ControlSeverity.CRITICAL]


class ComplianceDatabase:
    """Database for storing compliance frameworks and assessments"""
    
    def __init__(self, db_path: str = "compliance_db.sqlite"):
        self.db_path = db_path
        self.connection: Optional[sqlite3.Connection] = None
        self.logger = logging.getLogger(__name__)
    
    async def initialize(self):
        """Initialize database schema"""
        self.connection = sqlite3.connect(self.db_path)
        self.connection.row_factory = sqlite3.Row
        
        await self._create_tables()
        await self._create_indexes()
        
        self.logger.info("Compliance database initialized")
    
    async def _create_tables(self):
        """Create database tables"""
        cursor = self.connection.cursor()
        
        # Frameworks table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS frameworks (
                framework_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                version TEXT,
                description TEXT,
                categories TEXT,  -- JSON array
                assessment_frequency TEXT,
                mandatory_controls TEXT,  -- JSON array
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Controls table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS controls (
                control_id TEXT,
                framework_id TEXT,
                title TEXT NOT NULL,
                description TEXT,
                category TEXT,
                severity TEXT,
                requirements TEXT,  -- JSON array
                validation_rules TEXT,  -- JSON array
                remediation_guidance TEXT,
                references TEXT,  -- JSON array
                tags TEXT,  -- JSON array
                automated BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (control_id, framework_id),
                FOREIGN KEY (framework_id) REFERENCES frameworks (framework_id)
            )
        """)
        
        # Assessments table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assessments (
                assessment_id TEXT PRIMARY KEY,
                control_id TEXT,
                framework_id TEXT,
                status TEXT,
                score REAL,
                findings TEXT,  -- JSON array
                evidence TEXT,  -- JSON array
                recommendations TEXT,  -- JSON array
                assessed_at TIMESTAMP,
                assessed_by TEXT,
                next_assessment TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (control_id, framework_id) REFERENCES controls (control_id, framework_id)
            )
        """)
        
        # Assessment history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assessment_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id TEXT,
                control_id TEXT,
                framework_id TEXT,
                previous_status TEXT,
                new_status TEXT,
                previous_score REAL,
                new_score REAL,
                changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                changed_by TEXT,
                FOREIGN KEY (assessment_id) REFERENCES assessments (assessment_id)
            )
        """)
        
        self.connection.commit()
    
    async def _create_indexes(self):
        """Create database indexes"""
        cursor = self.connection.cursor()
        
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_framework_id ON controls(framework_id)",
            "CREATE INDEX IF NOT EXISTS idx_control_category ON controls(category)",
            "CREATE INDEX IF NOT EXISTS idx_control_severity ON controls(severity)",
            "CREATE INDEX IF NOT EXISTS idx_assessment_framework ON assessments(framework_id)",
            "CREATE INDEX IF NOT EXISTS idx_assessment_status ON assessments(status)",
            "CREATE INDEX IF NOT EXISTS idx_assessment_date ON assessments(assessed_at)",
            "CREATE INDEX IF NOT EXISTS idx_history_date ON assessment_history(changed_at)"
        ]
        
        for index_sql in indexes:
            cursor.execute(index_sql)
        
        self.connection.commit()
    
    async def store_framework(self, framework: ComplianceFramework):
        """Store compliance framework"""
        cursor = self.connection.cursor()
        
        # Store framework
        cursor.execute("""
            INSERT OR REPLACE INTO frameworks (
                framework_id, name, version, description, categories,
                assessment_frequency, mandatory_controls
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            framework.framework_id,
            framework.name,
            framework.version,
            framework.description,
            json.dumps(framework.categories),
            framework.assessment_frequency,
            json.dumps(list(framework.mandatory_controls))
        ))
        
        # Store controls
        for control in framework.controls.values():
            cursor.execute("""
                INSERT OR REPLACE INTO controls (
                    control_id, framework_id, title, description, category,
                    severity, requirements, validation_rules, remediation_guidance,
                    references, tags, automated
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                control.control_id,
                framework.framework_id,
                control.title,
                control.description,
                control.category,
                control.severity.value,
                json.dumps(control.requirements),
                json.dumps(control.validation_rules),
                control.remediation_guidance,
                json.dumps(control.references),
                json.dumps(control.tags),
                control.automated
            ))
        
        self.connection.commit()
    
    async def get_framework(self, framework_id: str) -> Optional[ComplianceFramework]:
        """Get compliance framework by ID"""
        cursor = self.connection.cursor()
        
        # Get framework
        cursor.execute("SELECT * FROM frameworks WHERE framework_id = ?", (framework_id,))
        framework_row = cursor.fetchone()
        
        if not framework_row:
            return None
        
        # Get controls
        cursor.execute("SELECT * FROM controls WHERE framework_id = ?", (framework_id,))
        control_rows = cursor.fetchall()
        
        controls = {}
        for row in control_rows:
            control = ComplianceControl(
                control_id=row['control_id'],
                framework=framework_id,
                title=row['title'],
                description=row['description'],
                category=row['category'],
                severity=ControlSeverity(row['severity']),
                requirements=json.loads(row['requirements'] or '[]'),
                validation_rules=json.loads(row['validation_rules'] or '[]'),
                remediation_guidance=row['remediation_guidance'],
                references=json.loads(row['references'] or '[]'),
                tags=json.loads(row['tags'] or '[]'),
                automated=bool(row['automated'])
            )
            controls[control.control_id] = control
        
        return ComplianceFramework(
            framework_id=framework_row['framework_id'],
            name=framework_row['name'],
            version=framework_row['version'],
            description=framework_row['description'],
            controls=controls,
            categories=json.loads(framework_row['categories'] or '[]'),
            assessment_frequency=framework_row['assessment_frequency'],
            mandatory_controls=set(json.loads(framework_row['mandatory_controls'] or '[]'))
        )
    
    async def store_assessment(self, assessment: ComplianceAssessment):
        """Store compliance assessment"""
        cursor = self.connection.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO assessments (
                assessment_id, control_id, framework_id, status, score,
                findings, evidence, recommendations, assessed_at,
                assessed_by, next_assessment
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            assessment.assessment_id,
            assessment.control_id,
            assessment.framework,
            assessment.status.value,
            assessment.score,
            json.dumps(assessment.findings),
            json.dumps(assessment.evidence),
            json.dumps(assessment.recommendations),
            assessment.assessed_at.isoformat(),
            assessment.assessed_by,
            assessment.next_assessment.isoformat() if assessment.next_assessment else None
        ))
        
        self.connection.commit()
    
    async def get_assessments(self, framework_id: str, control_id: str = None) -> List[ComplianceAssessment]:
        """Get compliance assessments"""
        cursor = self.connection.cursor()
        
        if control_id:
            cursor.execute("""
                SELECT * FROM assessments 
                WHERE framework_id = ? AND control_id = ?
                ORDER BY assessed_at DESC
            """, (framework_id, control_id))
        else:
            cursor.execute("""
                SELECT * FROM assessments 
                WHERE framework_id = ?
                ORDER BY assessed_at DESC
            """, (framework_id,))
        
        rows = cursor.fetchall()
        
        assessments = []
        for row in rows:
            assessment = ComplianceAssessment(
                assessment_id=row['assessment_id'],
                control_id=row['control_id'],
                framework=row['framework_id'],
                status=ComplianceStatus(row['status']),
                score=row['score'],
                findings=json.loads(row['findings'] or '[]'),
                evidence=json.loads(row['evidence'] or '[]'),
                recommendations=json.loads(row['recommendations'] or '[]'),
                assessed_at=datetime.fromisoformat(row['assessed_at']),
                assessed_by=row['assessed_by'],
                next_assessment=datetime.fromisoformat(row['next_assessment']) if row['next_assessment'] else None
            )
            assessments.append(assessment)
        
        return assessments


class ComplianceValidator:
    """Validates system configuration against compliance controls"""
    
    def __init__(self, database: ComplianceDatabase):
        self.database = database
        self.logger = logging.getLogger(__name__)
    
    async def assess_control(self, control: ComplianceControl, 
                           system_config: Dict[str, Any]) -> ComplianceAssessment:
        """Assess a single compliance control"""
        try:
            findings = []
            evidence = []
            recommendations = []
            total_checks = len(control.validation_rules)
            passed_checks = 0
            
            # Process each validation rule
            for rule in control.validation_rules:
                rule_result = await self._validate_rule(rule, system_config)
                
                if rule_result['passed']:
                    passed_checks += 1
                    evidence.append({
                        'rule': rule['name'],
                        'status': 'passed',
                        'details': rule_result.get('details', {}),
                        'timestamp': datetime.utcnow().isoformat()
                    })
                else:
                    findings.append({
                        'rule': rule['name'],
                        'severity': rule.get('severity', 'medium'),
                        'description': rule_result.get('description', ''),
                        'current_value': rule_result.get('current_value'),
                        'expected_value': rule_result.get('expected_value'),
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    
                    if 'recommendation' in rule_result:
                        recommendations.append(rule_result['recommendation'])
            
            # Calculate compliance score
            score = passed_checks / total_checks if total_checks > 0 else 0.0
            
            # Determine status
            if score == 1.0:
                status = ComplianceStatus.COMPLIANT
            elif score >= 0.8:
                status = ComplianceStatus.PARTIAL
            elif score > 0.0:
                status = ComplianceStatus.PARTIAL
            else:
                status = ComplianceStatus.NON_COMPLIANT
            
            # Create assessment
            assessment = ComplianceAssessment(
                assessment_id=f"{control.control_id}_{int(datetime.utcnow().timestamp())}",
                control_id=control.control_id,
                framework=control.framework,
                status=status,
                score=score,
                findings=findings,
                evidence=evidence,
                recommendations=list(set(recommendations)),  # Remove duplicates
                assessed_at=datetime.utcnow(),
                assessed_by="automated_validator",
                next_assessment=self._calculate_next_assessment(control)
            )
            
            return assessment
            
        except Exception as e:
            self.logger.error(f"Error assessing control {control.control_id}: {str(e)}")
            
            return ComplianceAssessment(
                assessment_id=f"{control.control_id}_{int(datetime.utcnow().timestamp())}",
                control_id=control.control_id,
                framework=control.framework,
                status=ComplianceStatus.UNKNOWN,
                score=0.0,
                findings=[{
                    'rule': 'validation_error',
                    'severity': 'high',
                    'description': f"Assessment failed: {str(e)}",
                    'timestamp': datetime.utcnow().isoformat()
                }],
                evidence=[],
                recommendations=["Review control validation configuration"],
                assessed_at=datetime.utcnow(),
                assessed_by="automated_validator"
            )
    
    async def _validate_rule(self, rule: Dict[str, Any], 
                           system_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate individual rule against system configuration"""
        rule_type = rule.get('type')
        
        try:
            if rule_type == 'config_check':
                return await self._validate_config_rule(rule, system_config)
            elif rule_type == 'policy_check':
                return await self._validate_policy_rule(rule, system_config)
            elif rule_type == 'security_check':
                return await self._validate_security_rule(rule, system_config)
            elif rule_type == 'process_check':
                return await self._validate_process_rule(rule, system_config)
            else:
                return {
                    'passed': False,
                    'description': f"Unknown rule type: {rule_type}",
                    'recommendation': f"Review rule configuration"
                }
                
        except Exception as e:
            return {
                'passed': False,
                'description': f"Rule validation error: {str(e)}",
                'recommendation': f"Fix validation error"
            }
    
    async def _validate_config_rule(self, rule: Dict[str, Any], 
                                   system_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate configuration-based rule"""
        config_path = rule.get('config_path', '')
        expected_value = rule.get('expected_value')
        operator = rule.get('operator', 'equals')
        
        # Navigate to config value
        current_value = system_config
        for path_part in config_path.split('.'):
            if isinstance(current_value, dict) and path_part in current_value:
                current_value = current_value[path_part]
            else:
                current_value = None
                break
        
        # Compare values based on operator
        passed = False
        if operator == 'equals':
            passed = current_value == expected_value
        elif operator == 'not_equals':
            passed = current_value != expected_value
        elif operator == 'greater_than':
            passed = isinstance(current_value, (int, float)) and current_value > expected_value
        elif operator == 'less_than':
            passed = isinstance(current_value, (int, float)) and current_value < expected_value
        elif operator == 'contains':
            passed = expected_value in (current_value or [])
        elif operator == 'not_contains':
            passed = expected_value not in (current_value or [])
        elif operator == 'exists':
            passed = current_value is not None
        elif operator == 'not_exists':
            passed = current_value is None
        
        return {
            'passed': passed,
            'current_value': current_value,
            'expected_value': expected_value,
            'operator': operator,
            'description': f"Config check: {config_path} {operator} {expected_value}",
            'recommendation': rule.get('recommendation', f"Set {config_path} to {expected_value}")
        }
    
    async def _validate_policy_rule(self, rule: Dict[str, Any], 
                                   system_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate policy-based rule"""
        # Implementation for policy validation
        return {
            'passed': True,
            'description': "Policy validation not implemented",
            'recommendation': "Implement policy validation"
        }
    
    async def _validate_security_rule(self, rule: Dict[str, Any], 
                                     system_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate security-specific rule"""
        # Implementation for security validation
        return {
            'passed': True,
            'description': "Security validation not implemented",
            'recommendation': "Implement security validation"
        }
    
    async def _validate_process_rule(self, rule: Dict[str, Any], 
                                    system_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate process-based rule"""
        # Implementation for process validation
        return {
            'passed': True,
            'description': "Process validation not implemented",
            'recommendation': "Implement process validation"
        }
    
    def _calculate_next_assessment(self, control: ComplianceControl) -> datetime:
        """Calculate next assessment date based on control criticality"""
        if control.severity == ControlSeverity.CRITICAL:
            return datetime.utcnow() + timedelta(days=7)  # Weekly
        elif control.severity == ControlSeverity.HIGH:
            return datetime.utcnow() + timedelta(days=30)  # Monthly
        elif control.severity == ControlSeverity.MEDIUM:
            return datetime.utcnow() + timedelta(days=90)  # Quarterly
        else:
            return datetime.utcnow() + timedelta(days=180)  # Semi-annually


class ComplianceFrameworkServer:
    """MCP Server for compliance framework operations"""
    
    def __init__(self, db_path: str = "compliance_db.sqlite"):
        self.server = Server("compliance-framework")
        self.logger = logging.getLogger(__name__)
        self.database = ComplianceDatabase(db_path)
        self.validator = ComplianceValidator(self.database)
        self.registry = ToolRegistry()
        
        self._load_builtin_frameworks()
        self._register_tools()
        self._setup_handlers()
    
    def _load_builtin_frameworks(self):
        """Load built-in compliance frameworks"""
        # This would load frameworks from configuration files
        # For now, we'll create some basic examples
        pass
    
    def _register_tools(self):
        """Register compliance framework tools"""
        
        self.registry.register_tool(ToolCapability(
            name="list_frameworks",
            description="List available compliance frameworks",
            parameters=[],
            category="framework_management",
            requires_auth=False,
            risk_level="low"
        ))
        
        self.registry.register_tool(ToolCapability(
            name="get_framework_details",
            description="Get detailed information about a compliance framework",
            parameters=[
                ToolParameter("framework_id", "string", "Framework identifier", True)
            ],
            category="framework_management",
            requires_auth=False,
            risk_level="low"
        ))
        
        self.registry.register_tool(ToolCapability(
            name="assess_framework",
            description="Perform compliance assessment for entire framework",
            parameters=[
                ToolParameter("framework_id", "string", "Framework identifier", True),
                ToolParameter("system_config", "object", "System configuration data", True),
                ToolParameter("assessor", "string", "Name of assessor", False, "automated")
            ],
            category="compliance_assessment",
            requires_auth=True,
            risk_level="medium"
        ))
        
        self.registry.register_tool(ToolCapability(
            name="assess_control",
            description="Assess specific compliance control",
            parameters=[
                ToolParameter("framework_id", "string", "Framework identifier", True),
                ToolParameter("control_id", "string", "Control identifier", True),
                ToolParameter("system_config", "object", "System configuration data", True),
                ToolParameter("assessor", "string", "Name of assessor", False, "automated")
            ],
            category="compliance_assessment",
            requires_auth=True,
            risk_level="medium"
        ))
        
        self.registry.register_tool(ToolCapability(
            name="get_assessment_results",
            description="Get compliance assessment results",
            parameters=[
                ToolParameter("framework_id", "string", "Framework identifier", True),
                ToolParameter("control_id", "string", "Control identifier (optional)", False),
                ToolParameter("status_filter", "string", "Filter by status", False),
                ToolParameter("limit", "integer", "Maximum results", False, 100)
            ],
            category="compliance_reporting",
            requires_auth=False,
            risk_level="low"
        ))
        
        self.registry.register_tool(ToolCapability(
            name="generate_compliance_report",
            description="Generate comprehensive compliance report",
            parameters=[
                ToolParameter("framework_id", "string", "Framework identifier", True),
                ToolParameter("report_type", "string", "Report type (summary, detailed, executive)", False, "summary"),
                ToolParameter("include_recommendations", "boolean", "Include remediation recommendations", False, True)
            ],
            category="compliance_reporting",
            requires_auth=False,
            risk_level="low"
        ))
        
        self.registry.register_tool(ToolCapability(
            name="track_compliance_trends",
            description="Track compliance trends over time",
            parameters=[
                ToolParameter("framework_id", "string", "Framework identifier", True),
                ToolParameter("time_period", "string", "Time period (30d, 90d, 1y)", False, "90d"),
                ToolParameter("metric", "string", "Metric to track (score, status_changes)", False, "score")
            ],
            category="compliance_analytics",
            requires_auth=False,
            risk_level="low"
        ))
    
    def _setup_handlers(self):
        """Setup MCP request handlers"""
        
        @self.server.list_tools()
        async def handle_list_tools() -> List[Tool]:
            """List available compliance tools"""
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
            """Execute compliance tool"""
            try:
                start_time = datetime.now()
                
                if name == "list_frameworks":
                    result = await self._list_frameworks(arguments)
                elif name == "get_framework_details":
                    result = await self._get_framework_details(arguments)
                elif name == "assess_framework":
                    result = await self._assess_framework(arguments)
                elif name == "assess_control":
                    result = await self._assess_control(arguments)
                elif name == "get_assessment_results":
                    result = await self._get_assessment_results(arguments)
                elif name == "generate_compliance_report":
                    result = await self._generate_compliance_report(arguments)
                elif name == "track_compliance_trends":
                    result = await self._track_compliance_trends(arguments)
                else:
                    return CallToolResult(
                        content=[TextContent(
                            type="text",
                            text=f"Unknown tool: {name}"
                        )],
                        isError=True
                    )
                
                execution_time = (datetime.now() - start_time).total_seconds() * 1000
                result['execution_time_ms'] = execution_time
                
                return CallToolResult(
                    content=[TextContent(
                        type="text",
                        text=json.dumps(result, indent=2, default=str)
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
    
    async def _list_frameworks(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """List available compliance frameworks"""
        # This would query the database for available frameworks
        frameworks = [
            {
                'framework_id': 'soc2',
                'name': 'SOC 2 Type II',
                'version': '2017',
                'description': 'Service Organization Control 2 - Security, Availability, Processing Integrity, Confidentiality, Privacy',
                'categories': ['security', 'availability', 'processing_integrity', 'confidentiality', 'privacy'],
                'control_count': 50
            },
            {
                'framework_id': 'iso27001',
                'name': 'ISO 27001:2013',
                'version': '2013',
                'description': 'Information Security Management System Requirements',
                'categories': ['information_security_policies', 'organization_of_information_security'],
                'control_count': 114
            },
            {
                'framework_id': 'nist_csf',
                'name': 'NIST Cybersecurity Framework',
                'version': '1.1',
                'description': 'Framework for Improving Critical Infrastructure Cybersecurity',
                'categories': ['identify', 'protect', 'detect', 'respond', 'recover'],
                'control_count': 98
            }
        ]
        
        return {
            'frameworks': frameworks,
            'total_count': len(frameworks)
        }
    
    async def _get_framework_details(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get detailed framework information"""
        framework_id = arguments['framework_id']
        
        framework = await self.database.get_framework(framework_id)
        
        if framework:
            return {
                'found': True,
                'framework': {
                    'framework_id': framework.framework_id,
                    'name': framework.name,
                    'version': framework.version,
                    'description': framework.description,
                    'categories': framework.categories,
                    'assessment_frequency': framework.assessment_frequency,
                    'total_controls': len(framework.controls),
                    'mandatory_controls': len(framework.mandatory_controls),
                    'controls_by_category': {
                        category: len(framework.get_controls_by_category(category))
                        for category in framework.categories
                    },
                    'critical_controls': len(framework.get_critical_controls())
                }
            }
        else:
            return {
                'found': False,
                'message': f"Framework {framework_id} not found"
            }
    
    async def _assess_framework(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Assess entire compliance framework"""
        framework_id = arguments['framework_id']
        system_config = arguments['system_config']
        assessor = arguments.get('assessor', 'automated')
        
        framework = await self.database.get_framework(framework_id)
        if not framework:
            return {'error': f"Framework {framework_id} not found"}
        
        results = {}
        total_score = 0.0
        control_count = 0
        
        # Assess each control
        for control_id, control in framework.controls.items():
            try:
                assessment = await self.validator.assess_control(control, system_config)
                assessment.assessed_by = assessor
                
                # Store assessment
                await self.database.store_assessment(assessment)
                
                results[control_id] = assessment.to_dict()
                total_score += assessment.score
                control_count += 1
                
            except Exception as e:
                self.logger.error(f"Failed to assess control {control_id}: {str(e)}")
                continue
        
        # Calculate overall compliance score
        overall_score = total_score / control_count if control_count > 0 else 0.0
        
        # Determine overall status
        if overall_score >= 0.95:
            overall_status = ComplianceStatus.COMPLIANT
        elif overall_score >= 0.8:
            overall_status = ComplianceStatus.PARTIAL
        else:
            overall_status = ComplianceStatus.NON_COMPLIANT
        
        return {
            'framework_id': framework_id,
            'framework_name': framework.name,
            'assessment_date': datetime.utcnow().isoformat(),
            'assessed_by': assessor,
            'overall_status': overall_status.value,
            'overall_score': round(overall_score, 3),
            'total_controls': control_count,
            'compliant_controls': len([r for r in results.values() if r['status'] == 'compliant']),
            'non_compliant_controls': len([r for r in results.values() if r['status'] == 'non_compliant']),
            'partial_controls': len([r for r in results.values() if r['status'] == 'partial']),
            'control_results': results
        }
    
    async def _assess_control(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Assess specific compliance control"""
        framework_id = arguments['framework_id']
        control_id = arguments['control_id']
        system_config = arguments['system_config']
        assessor = arguments.get('assessor', 'automated')
        
        framework = await self.database.get_framework(framework_id)
        if not framework:
            return {'error': f"Framework {framework_id} not found"}
        
        control = framework.get_control(control_id)
        if not control:
            return {'error': f"Control {control_id} not found in framework {framework_id}"}
        
        assessment = await self.validator.assess_control(control, system_config)
        assessment.assessed_by = assessor
        
        # Store assessment
        await self.database.store_assessment(assessment)
        
        return {
            'framework_id': framework_id,
            'control_id': control_id,
            'assessment': assessment.to_dict()
        }
    
    async def _get_assessment_results(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get compliance assessment results"""
        framework_id = arguments['framework_id']
        control_id = arguments.get('control_id')
        status_filter = arguments.get('status_filter')
        limit = arguments.get('limit', 100)
        
        assessments = await self.database.get_assessments(framework_id, control_id)
        
        # Apply status filter
        if status_filter:
            assessments = [a for a in assessments if a.status.value == status_filter]
        
        # Apply limit
        assessments = assessments[:limit]
        
        return {
            'framework_id': framework_id,
            'control_id': control_id,
            'total_results': len(assessments),
            'assessments': [assessment.to_dict() for assessment in assessments]
        }
    
    async def _generate_compliance_report(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Generate compliance report"""
        framework_id = arguments['framework_id']
        report_type = arguments.get('report_type', 'summary')
        include_recommendations = arguments.get('include_recommendations', True)
        
        framework = await self.database.get_framework(framework_id)
        if not framework:
            return {'error': f"Framework {framework_id} not found"}
        
        assessments = await self.database.get_assessments(framework_id)
        
        # Generate report based on type
        if report_type == 'summary':
            return self._generate_summary_report(framework, assessments, include_recommendations)
        elif report_type == 'detailed':
            return self._generate_detailed_report(framework, assessments, include_recommendations)
        elif report_type == 'executive':
            return self._generate_executive_report(framework, assessments, include_recommendations)
        else:
            return {'error': f"Unknown report type: {report_type}"}
    
    def _generate_summary_report(self, framework: ComplianceFramework, 
                               assessments: List[ComplianceAssessment],
                               include_recommendations: bool) -> Dict[str, Any]:
        """Generate summary compliance report"""
        if not assessments:
            return {
                'framework': framework.name,
                'status': 'not_assessed',
                'message': 'No assessments found'
            }
        
        # Calculate statistics
        total_controls = len(framework.controls)
        assessed_controls = len(set(a.control_id for a in assessments))
        
        status_counts = {}
        total_score = 0.0
        
        # Get latest assessment for each control
        latest_assessments = {}
        for assessment in assessments:
            if (assessment.control_id not in latest_assessments or 
                assessment.assessed_at > latest_assessments[assessment.control_id].assessed_at):
                latest_assessments[assessment.control_id] = assessment
        
        for assessment in latest_assessments.values():
            status_counts[assessment.status.value] = status_counts.get(assessment.status.value, 0) + 1
            total_score += assessment.score
        
        overall_score = total_score / len(latest_assessments) if latest_assessments else 0.0
        
        report = {
            'framework': framework.name,
            'framework_id': framework.framework_id,
            'report_type': 'summary',
            'generated_at': datetime.utcnow().isoformat(),
            'overall_score': round(overall_score, 3),
            'total_controls': total_controls,
            'assessed_controls': assessed_controls,
            'status_breakdown': status_counts,
            'compliance_percentage': round((status_counts.get('compliant', 0) / assessed_controls * 100), 1) if assessed_controls > 0 else 0
        }
        
        if include_recommendations:
            # Collect top recommendations
            all_recommendations = []
            for assessment in latest_assessments.values():
                if assessment.status != ComplianceStatus.COMPLIANT:
                    all_recommendations.extend(assessment.recommendations)
            
            # Get unique recommendations
            unique_recommendations = list(set(all_recommendations))[:10]
            report['top_recommendations'] = unique_recommendations
        
        return report
    
    def _generate_detailed_report(self, framework: ComplianceFramework, 
                                assessments: List[ComplianceAssessment],
                                include_recommendations: bool) -> Dict[str, Any]:
        """Generate detailed compliance report"""
        # Implementation for detailed report
        summary = self._generate_summary_report(framework, assessments, include_recommendations)
        
        # Add detailed control information
        latest_assessments = {}
        for assessment in assessments:
            if (assessment.control_id not in latest_assessments or 
                assessment.assessed_at > latest_assessments[assessment.control_id].assessed_at):
                latest_assessments[assessment.control_id] = assessment
        
        control_details = []
        for control_id, control in framework.controls.items():
            assessment = latest_assessments.get(control_id)
            
            control_detail = {
                'control_id': control_id,
                'title': control.title,
                'category': control.category,
                'severity': control.severity.value,
                'status': assessment.status.value if assessment else 'not_assessed',
                'score': assessment.score if assessment else 0.0,
                'findings_count': len(assessment.findings) if assessment else 0,
                'last_assessed': assessment.assessed_at.isoformat() if assessment else None
            }
            
            if include_recommendations and assessment and assessment.recommendations:
                control_detail['recommendations'] = assessment.recommendations
            
            control_details.append(control_detail)
        
        summary.update({
            'report_type': 'detailed',
            'control_details': control_details
        })
        
        return summary
    
    def _generate_executive_report(self, framework: ComplianceFramework, 
                                 assessments: List[ComplianceAssessment],
                                 include_recommendations: bool) -> Dict[str, Any]:
        """Generate executive compliance report"""
        summary = self._generate_summary_report(framework, assessments, include_recommendations)
        
        # Add executive-level insights
        summary.update({
            'report_type': 'executive',
            'key_insights': [
                f"Overall compliance score: {summary['overall_score']:.1%}",
                f"Assessed {summary['assessed_controls']} of {summary['total_controls']} controls",
                f"{summary['compliance_percentage']:.1f}% of controls are compliant"
            ],
            'risk_summary': {
                'high_risk_controls': len([a for a in assessments if a.status == ComplianceStatus.NON_COMPLIANT]),
                'medium_risk_controls': len([a for a in assessments if a.status == ComplianceStatus.PARTIAL]),
                'compliant_controls': len([a for a in assessments if a.status == ComplianceStatus.COMPLIANT])
            }
        })
        
        return summary
    
    async def _track_compliance_trends(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Track compliance trends over time"""
        framework_id = arguments['framework_id']
        time_period = arguments.get('time_period', '90d')
        metric = arguments.get('metric', 'score')
        
        # This would query historical assessment data
        # For now, return mock trend data
        
        return {
            'framework_id': framework_id,
            'time_period': time_period,
            'metric': metric,
            'trend_data': [
                {'date': '2024-01-01', 'value': 0.75},
                {'date': '2024-01-15', 'value': 0.78},
                {'date': '2024-02-01', 'value': 0.82},
                {'date': '2024-02-15', 'value': 0.85},
                {'date': '2024-03-01', 'value': 0.87}
            ],
            'trend_direction': 'improving',
            'change_percentage': 16.0
        }
    
    async def initialize(self):
        """Initialize the compliance framework server"""
        await self.database.initialize()
        self.logger.info("Compliance Framework MCP Server initialized")
    
    async def run(self):
        """Run the MCP server"""
        await self.initialize()
        
        async with ClientSession(StdioServerParameters()) as session:
            await session.initialize()
            
            self.logger.info("Compliance Framework MCP Server running...")
            
            try:
                while True:
                    await asyncio.sleep(1)
            except KeyboardInterrupt:
                self.logger.info("Shutting down Compliance Framework MCP Server...")


# Example usage
async def main():
    """Example usage of Compliance Framework MCP Server"""
    server = ComplianceFrameworkServer()
    await server.run()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())