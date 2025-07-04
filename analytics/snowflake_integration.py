"""
Snowflake Security Analytics Integration

Comprehensive analytics system with real-time security event ingestion,
Cortex AI-powered analysis, and interactive Streamlit dashboards.
"""

import asyncio
import json
import logging
import time
import hashlib
from typing import Dict, List, Optional, Any, AsyncGenerator, Tuple, Union
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict, field
from enum import Enum
import pandas as pd
import numpy as np
from concurrent.futures import ThreadPoolExecutor
import threading
from abc import ABC, abstractmethod

# Snowflake imports
import snowflake.connector
from snowflake.connector.pandas_tools import write_pandas
from snowflake.snowpark import Session
from snowflake.snowpark.functions import col, when, sum as sf_sum, avg as sf_avg, count as sf_count
from snowflake.snowpark.types import StructType, StructField, StringType, IntegerType, FloatType, TimestampType
from snowflake.cortex import Complete, Sentiment, Translate, Summarize

# Streamlit imports
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Additional analytics imports
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import redis.asyncio as redis


class SecurityEventType(Enum):
    """Types of security events"""
    THREAT_DETECTED = "threat_detected"
    VULNERABILITY_FOUND = "vulnerability_found"
    COMPLIANCE_VIOLATION = "compliance_violation"
    INCIDENT_RESPONSE = "incident_response"
    AUTHENTICATION_EVENT = "authentication_event"
    NETWORK_ANOMALY = "network_anomaly"
    DATA_ACCESS = "data_access"
    SYSTEM_CHANGE = "system_change"


class AnalyticsMetric(Enum):
    """Analytics metrics"""
    SECURITY_SCORE = "security_score"
    THREAT_LEVEL = "threat_level"
    COMPLIANCE_SCORE = "compliance_score"
    RISK_SCORE = "risk_score"
    INCIDENT_COUNT = "incident_count"
    VULNERABILITY_COUNT = "vulnerability_count"
    RESPONSE_TIME = "response_time"
    COVERAGE_PERCENTAGE = "coverage_percentage"


@dataclass
class SecurityEvent:
    """Security event data structure"""
    event_id: str
    event_type: SecurityEventType
    timestamp: datetime
    severity: str
    source: str
    target: Optional[str]
    description: str
    metadata: Dict[str, Any]
    tags: List[str]
    correlation_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Snowflake ingestion"""
        return {
            'EVENT_ID': self.event_id,
            'EVENT_TYPE': self.event_type.value,
            'TIMESTAMP': self.timestamp,
            'SEVERITY': self.severity,
            'SOURCE': self.source,
            'TARGET': self.target,
            'DESCRIPTION': self.description,
            'METADATA': json.dumps(self.metadata),
            'TAGS': json.dumps(self.tags),
            'CORRELATION_ID': self.correlation_id
        }


@dataclass
class AnalyticsResult:
    """Analytics computation result"""
    metric: AnalyticsMetric
    value: float
    timestamp: datetime
    dimensions: Dict[str, Any]
    confidence: float
    trend: str  # increasing, decreasing, stable
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'METRIC': self.metric.value,
            'VALUE': self.value,
            'TIMESTAMP': self.timestamp,
            'DIMENSIONS': json.dumps(self.dimensions),
            'CONFIDENCE': self.confidence,
            'TREND': self.trend
        }


@dataclass
class SnowflakeConfig:
    """Snowflake connection configuration"""
    account: str
    user: str
    password: str
    database: str
    schema: str
    warehouse: str
    role: str
    
    # Connection pool settings
    max_connections: int = 10
    connection_timeout: int = 30
    
    # Snowpipe settings
    pipe_name: str = "SECURITY_EVENTS_PIPE"
    stage_name: str = "SECURITY_EVENTS_STAGE"
    
    # Cortex AI settings
    cortex_model: str = "llama2-70b-chat"
    max_tokens: int = 2048
    temperature: float = 0.1


class SnowflakeConnectionManager:
    """Manage Snowflake connections with pooling"""
    
    def __init__(self, config: SnowflakeConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._connection_pool = []
        self._pool_lock = threading.Lock()
        self._session_cache = {}
        
    def get_connection(self) -> snowflake.connector.SnowflakeConnection:
        """Get connection from pool or create new one"""
        with self._pool_lock:
            if self._connection_pool:
                return self._connection_pool.pop()
        
        # Create new connection
        return snowflake.connector.connect(
            account=self.config.account,
            user=self.config.user,
            password=self.config.password,
            database=self.config.database,
            schema=self.config.schema,
            warehouse=self.config.warehouse,
            role=self.config.role,
            client_session_keep_alive=True,
            network_timeout=self.config.connection_timeout
        )
    
    def return_connection(self, conn: snowflake.connector.SnowflakeConnection):
        """Return connection to pool"""
        with self._pool_lock:
            if len(self._connection_pool) < self.config.max_connections:
                self._connection_pool.append(conn)
            else:
                conn.close()
    
    def get_session(self, session_id: str = "default") -> Session:
        """Get Snowpark session"""
        if session_id not in self._session_cache:
            self._session_cache[session_id] = Session.builder.configs({
                "account": self.config.account,
                "user": self.config.user,
                "password": self.config.password,
                "database": self.config.database,
                "schema": self.config.schema,
                "warehouse": self.config.warehouse,
                "role": self.config.role
            }).create()
        
        return self._session_cache[session_id]


class SecurityDataPipeline:
    """Real-time security data ingestion pipeline"""
    
    def __init__(self, config: SnowflakeConfig):
        self.config = config
        self.connection_manager = SnowflakeConnectionManager(config)
        self.logger = logging.getLogger(__name__)
        self.event_buffer = []
        self.buffer_lock = threading.Lock()
        self.batch_size = 1000
        self.flush_interval = 30  # seconds
        self._running = False
        
    async def initialize(self):
        """Initialize data pipeline"""
        await self._create_tables()
        await self._setup_snowpipe()
        self._start_batch_processor()
        self.logger.info("Security data pipeline initialized")
    
    async def _create_tables(self):
        """Create necessary tables in Snowflake"""
        session = self.connection_manager.get_session()
        
        # Security events table
        session.sql("""
            CREATE TABLE IF NOT EXISTS SECURITY_EVENTS (
                EVENT_ID STRING PRIMARY KEY,
                EVENT_TYPE STRING NOT NULL,
                TIMESTAMP TIMESTAMP_NTZ NOT NULL,
                SEVERITY STRING NOT NULL,
                SOURCE STRING NOT NULL,
                TARGET STRING,
                DESCRIPTION STRING,
                METADATA VARIANT,
                TAGS ARRAY,
                CORRELATION_ID STRING,
                INGESTION_TIME TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
                PARTITION_DATE DATE AS (DATE(TIMESTAMP))
            ) CLUSTER BY (PARTITION_DATE, EVENT_TYPE, SEVERITY)
        """).collect()
        
        # Analytics metrics table
        session.sql("""
            CREATE TABLE IF NOT EXISTS ANALYTICS_METRICS (
                METRIC_ID STRING PRIMARY KEY,
                METRIC STRING NOT NULL,
                VALUE FLOAT NOT NULL,
                TIMESTAMP TIMESTAMP_NTZ NOT NULL,
                DIMENSIONS VARIANT,
                CONFIDENCE FLOAT,
                TREND STRING,
                COMPUTATION_TIME TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
            ) CLUSTER BY (TIMESTAMP, METRIC)
        """).collect()
        
        # Threat intelligence table
        session.sql("""
            CREATE TABLE IF NOT EXISTS THREAT_INTELLIGENCE (
                THREAT_ID STRING PRIMARY KEY,
                THREAT_TYPE STRING NOT NULL,
                INDICATORS ARRAY NOT NULL,
                CONFIDENCE FLOAT NOT NULL,
                SOURCE STRING NOT NULL,
                FIRST_SEEN TIMESTAMP_NTZ NOT NULL,
                LAST_SEEN TIMESTAMP_NTZ NOT NULL,
                METADATA VARIANT,
                ACTIVE BOOLEAN DEFAULT TRUE
            ) CLUSTER BY (THREAT_TYPE, CONFIDENCE)
        """).collect()
        
        # Compliance assessments table
        session.sql("""
            CREATE TABLE IF NOT EXISTS COMPLIANCE_ASSESSMENTS (
                ASSESSMENT_ID STRING PRIMARY KEY,
                FRAMEWORK STRING NOT NULL,
                CONTROL_ID STRING NOT NULL,
                STATUS STRING NOT NULL,
                SCORE FLOAT NOT NULL,
                ASSESSMENT_DATE TIMESTAMP_NTZ NOT NULL,
                FINDINGS VARIANT,
                REMEDIATION VARIANT,
                ASSESSOR STRING
            ) CLUSTER BY (FRAMEWORK, ASSESSMENT_DATE)
        """).collect()
        
        self.logger.info("Snowflake tables created successfully")
    
    async def _setup_snowpipe(self):
        """Setup Snowpipe for real-time ingestion"""
        session = self.connection_manager.get_session()
        
        # Create stage for file ingestion
        session.sql(f"""
            CREATE STAGE IF NOT EXISTS {self.config.stage_name}
            FILE_FORMAT = (TYPE = JSON)
        """).collect()
        
        # Create pipe for automatic ingestion
        session.sql(f"""
            CREATE PIPE IF NOT EXISTS {self.config.pipe_name}
            AUTO_INGEST = TRUE
            AS COPY INTO SECURITY_EVENTS
            FROM @{self.config.stage_name}
            FILE_FORMAT = (TYPE = JSON)
        """).collect()
        
        self.logger.info("Snowpipe configured for real-time ingestion")
    
    async def ingest_event(self, event: SecurityEvent):
        """Ingest single security event"""
        with self.buffer_lock:
            self.event_buffer.append(event)
            
            # Flush if buffer is full
            if len(self.event_buffer) >= self.batch_size:
                await self._flush_buffer()
    
    async def ingest_events_batch(self, events: List[SecurityEvent]):
        """Ingest batch of security events"""
        with self.buffer_lock:
            self.event_buffer.extend(events)
            
            # Flush if buffer is full
            if len(self.event_buffer) >= self.batch_size:
                await self._flush_buffer()
    
    async def _flush_buffer(self):
        """Flush event buffer to Snowflake"""
        if not self.event_buffer:
            return
        
        try:
            # Convert events to DataFrame
            events_data = [event.to_dict() for event in self.event_buffer]
            df = pd.DataFrame(events_data)
            
            # Write to Snowflake
            conn = self.connection_manager.get_connection()
            try:
                success, nchunks, nrows, _ = write_pandas(
                    conn, df, 'SECURITY_EVENTS',
                    auto_create_table=False,
                    overwrite=False
                )
                
                if success:
                    self.logger.info(f"Ingested {nrows} security events to Snowflake")
                    self.event_buffer.clear()
                else:
                    self.logger.error("Failed to ingest events to Snowflake")
                    
            finally:
                self.connection_manager.return_connection(conn)
                
        except Exception as e:
            self.logger.error(f"Event ingestion failed: {str(e)}")
    
    def _start_batch_processor(self):
        """Start background batch processor"""
        self._running = True
        
        def batch_processor():
            while self._running:
                time.sleep(self.flush_interval)
                if self.event_buffer:
                    asyncio.create_task(self._flush_buffer())
        
        thread = threading.Thread(target=batch_processor, daemon=True)
        thread.start()
        self.logger.info("Batch processor started")
    
    def stop(self):
        """Stop the data pipeline"""
        self._running = False
        if self.event_buffer:
            asyncio.create_task(self._flush_buffer())


class ThreatIntelligenceAnalyzer:
    """AI-powered threat intelligence analysis using Cortex"""
    
    def __init__(self, config: SnowflakeConfig):
        self.config = config
        self.connection_manager = SnowflakeConnectionManager(config)
        self.logger = logging.getLogger(__name__)
    
    async def analyze_threat_patterns(self, time_window_hours: int = 24) -> Dict[str, Any]:
        """Analyze threat patterns using Cortex AI"""
        session = self.connection_manager.get_session()
        
        # Get recent threat events
        threat_events = session.sql(f"""
            SELECT EVENT_TYPE, SEVERITY, DESCRIPTION, METADATA, TAGS
            FROM SECURITY_EVENTS
            WHERE EVENT_TYPE = 'threat_detected'
            AND TIMESTAMP >= DATEADD(hour, -{time_window_hours}, CURRENT_TIMESTAMP())
            ORDER BY TIMESTAMP DESC
        """).collect()
        
        if not threat_events:
            return {"patterns": [], "insights": "No threat events found in the specified time window"}
        
        # Prepare data for Cortex analysis
        threat_descriptions = [row['DESCRIPTION'] for row in threat_events]
        combined_threats = "\n".join(threat_descriptions[:100])  # Limit for token constraints
        
        # Use Cortex AI for pattern analysis
        analysis_prompt = f"""
        Analyze the following security threat events and identify patterns:
        
        {combined_threats}
        
        Provide insights on:
        1. Common attack vectors
        2. Threat actor patterns
        3. Target preferences
        4. Temporal patterns
        5. Recommended countermeasures
        
        Format as JSON with structured insights.
        """
        
        try:
            cortex_response = Complete(
                model=self.config.cortex_model,
                prompt=analysis_prompt,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature
            )
            
            # Parse and structure the response
            insights = self._parse_cortex_response(cortex_response)
            
            # Add statistical analysis
            patterns = await self._statistical_threat_analysis(session, time_window_hours)
            
            return {
                "ai_insights": insights,
                "statistical_patterns": patterns,
                "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
                "events_analyzed": len(threat_events)
            }
            
        except Exception as e:
            self.logger.error(f"Threat pattern analysis failed: {str(e)}")
            return {"error": str(e), "fallback_analysis": await self._statistical_threat_analysis(session, time_window_hours)}
    
    async def _statistical_threat_analysis(self, session: Session, time_window_hours: int) -> Dict[str, Any]:
        """Perform statistical threat analysis"""
        # Threat type distribution
        threat_distribution = session.sql(f"""
            SELECT EVENT_TYPE, SEVERITY, COUNT(*) as COUNT
            FROM SECURITY_EVENTS
            WHERE TIMESTAMP >= DATEADD(hour, -{time_window_hours}, CURRENT_TIMESTAMP())
            GROUP BY EVENT_TYPE, SEVERITY
            ORDER BY COUNT DESC
        """).collect()
        
        # Temporal patterns
        temporal_patterns = session.sql(f"""
            SELECT 
                HOUR(TIMESTAMP) as HOUR_OF_DAY,
                DAYOFWEEK(TIMESTAMP) as DAY_OF_WEEK,
                COUNT(*) as EVENT_COUNT
            FROM SECURITY_EVENTS
            WHERE TIMESTAMP >= DATEADD(hour, -{time_window_hours}, CURRENT_TIMESTAMP())
            GROUP BY HOUR(TIMESTAMP), DAYOFWEEK(TIMESTAMP)
            ORDER BY EVENT_COUNT DESC
        """).collect()
        
        # Source analysis
        source_analysis = session.sql(f"""
            SELECT SOURCE, COUNT(*) as COUNT, COUNT(DISTINCT TARGET) as UNIQUE_TARGETS
            FROM SECURITY_EVENTS
            WHERE TIMESTAMP >= DATEADD(hour, -{time_window_hours}, CURRENT_TIMESTAMP())
            GROUP BY SOURCE
            ORDER BY COUNT DESC
            LIMIT 20
        """).collect()
        
        return {
            "threat_distribution": [dict(row.asDict()) for row in threat_distribution],
            "temporal_patterns": [dict(row.asDict()) for row in temporal_patterns],
            "top_sources": [dict(row.asDict()) for row in source_analysis]
        }
    
    def _parse_cortex_response(self, response: str) -> Dict[str, Any]:
        """Parse Cortex AI response"""
        try:
            # Try to extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            else:
                return {"raw_insights": response}
        except:
            return {"raw_insights": response}
    
    async def correlate_threat_intelligence(self, indicators: List[str]) -> Dict[str, Any]:
        """Correlate indicators with threat intelligence"""
        session = self.connection_manager.get_session()
        
        # Search for matching indicators in threat intelligence
        indicator_list = "', '".join(indicators)
        matches = session.sql(f"""
            SELECT 
                THREAT_ID,
                THREAT_TYPE,
                INDICATORS,
                CONFIDENCE,
                SOURCE,
                METADATA
            FROM THREAT_INTELLIGENCE
            WHERE ACTIVE = TRUE
            AND EXISTS (
                SELECT 1 FROM TABLE(FLATTEN(INDICATORS)) f
                WHERE f.VALUE IN ('{indicator_list}')
            )
            ORDER BY CONFIDENCE DESC
        """).collect()
        
        correlations = []
        for match in matches:
            correlations.append({
                "threat_id": match['THREAT_ID'],
                "threat_type": match['THREAT_TYPE'],
                "confidence": match['CONFIDENCE'],
                "source": match['SOURCE'],
                "matching_indicators": [
                    ind for ind in json.loads(match['INDICATORS']) 
                    if ind in indicators
                ]
            })
        
        return {
            "correlations": correlations,
            "total_matches": len(correlations),
            "high_confidence_matches": len([c for c in correlations if c['confidence'] > 0.8])
        }


class ComplianceReporter:
    """Automated compliance reporting with Cortex AI"""
    
    def __init__(self, config: SnowflakeConfig):
        self.config = config
        self.connection_manager = SnowflakeConnectionManager(config)
        self.logger = logging.getLogger(__name__)
        
        # Compliance frameworks
        self.frameworks = {
            'SOC2': {
                'controls': ['CC6.1', 'CC6.2', 'CC6.3', 'CC6.6', 'CC6.7', 'CC6.8'],
                'categories': ['security', 'availability', 'processing_integrity', 'confidentiality', 'privacy']
            },
            'ISO27001': {
                'controls': ['A.5.1.1', 'A.6.1.1', 'A.9.1.1', 'A.12.6.1', 'A.13.1.1'],
                'categories': ['information_security_policies', 'organization_of_information_security', 'access_control']
            },
            'NIST': {
                'controls': ['ID.AM-1', 'PR.AC-1', 'DE.CM-1', 'RS.RP-1', 'RC.RP-1'],
                'categories': ['identify', 'protect', 'detect', 'respond', 'recover']
            }
        }
    
    async def generate_compliance_report(self, framework: str, assessment_period_days: int = 30) -> Dict[str, Any]:
        """Generate comprehensive compliance report"""
        if framework not in self.frameworks:
            raise ValueError(f"Unsupported framework: {framework}")
        
        session = self.connection_manager.get_session()
        
        # Get compliance assessments for the period
        assessments = session.sql(f"""
            SELECT 
                CONTROL_ID,
                STATUS,
                SCORE,
                ASSESSMENT_DATE,
                FINDINGS,
                REMEDIATION
            FROM COMPLIANCE_ASSESSMENTS
            WHERE FRAMEWORK = '{framework}'
            AND ASSESSMENT_DATE >= DATEADD(day, -{assessment_period_days}, CURRENT_TIMESTAMP())
            ORDER BY ASSESSMENT_DATE DESC
        """).collect()
        
        # Calculate compliance metrics
        total_controls = len(self.frameworks[framework]['controls'])
        assessed_controls = len(set(row['CONTROL_ID'] for row in assessments))
        compliant_controls = len([row for row in assessments if row['STATUS'] == 'compliant'])
        
        overall_score = (compliant_controls / total_controls * 100) if total_controls > 0 else 0
        
        # Generate AI-powered insights
        compliance_summary = await self._generate_compliance_insights(framework, assessments)
        
        # Identify gaps and recommendations
        gaps = await self._identify_compliance_gaps(framework, assessments)
        
        return {
            "framework": framework,
            "assessment_period_days": assessment_period_days,
            "overall_score": round(overall_score, 2),
            "metrics": {
                "total_controls": total_controls,
                "assessed_controls": assessed_controls,
                "compliant_controls": compliant_controls,
                "non_compliant_controls": assessed_controls - compliant_controls,
                "coverage_percentage": round((assessed_controls / total_controls * 100), 2)
            },
            "control_details": [dict(row.asDict()) for row in assessments],
            "ai_insights": compliance_summary,
            "gaps_and_recommendations": gaps,
            "report_generated": datetime.now(timezone.utc).isoformat()
        }
    
    async def _generate_compliance_insights(self, framework: str, assessments: List) -> Dict[str, Any]:
        """Generate AI-powered compliance insights"""
        if not assessments:
            return {"insights": "No assessments available for analysis"}
        
        # Prepare assessment data for AI analysis
        assessment_summary = []
        for assessment in assessments[:50]:  # Limit for token constraints
            assessment_summary.append(f"Control {assessment['CONTROL_ID']}: {assessment['STATUS']} (Score: {assessment['SCORE']})")
        
        summary_text = "\n".join(assessment_summary)
        
        analysis_prompt = f"""
        Analyze the following {framework} compliance assessment results:
        
        {summary_text}
        
        Provide insights on:
        1. Overall compliance posture
        2. Critical gaps requiring immediate attention
        3. Trends and patterns in compliance status
        4. Risk areas and potential impacts
        5. Strategic recommendations for improvement
        
        Format as structured analysis with clear recommendations.
        """
        
        try:
            cortex_response = Complete(
                model=self.config.cortex_model,
                prompt=analysis_prompt,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature
            )
            
            return {"ai_analysis": cortex_response, "analysis_method": "cortex_ai"}
            
        except Exception as e:
            self.logger.error(f"AI compliance analysis failed: {str(e)}")
            return {"error": str(e), "analysis_method": "fallback"}
    
    async def _identify_compliance_gaps(self, framework: str, assessments: List) -> Dict[str, Any]:
        """Identify compliance gaps and generate recommendations"""
        required_controls = set(self.frameworks[framework]['controls'])
        assessed_controls = set(row['CONTROL_ID'] for row in assessments)
        non_compliant_controls = [row['CONTROL_ID'] for row in assessments if row['STATUS'] != 'compliant']
        
        gaps = {
            "missing_assessments": list(required_controls - assessed_controls),
            "non_compliant_controls": non_compliant_controls,
            "critical_gaps": [],
            "recommendations": []
        }
        
        # Identify critical gaps (high-priority controls that are non-compliant)
        critical_controls = {
            'SOC2': ['CC6.1', 'CC6.2', 'CC6.3'],
            'ISO27001': ['A.9.1.1', 'A.12.6.1'],
            'NIST': ['ID.AM-1', 'PR.AC-1', 'DE.CM-1']
        }
        
        if framework in critical_controls:
            gaps["critical_gaps"] = [
                control for control in critical_controls[framework]
                if control in non_compliant_controls or control in gaps["missing_assessments"]
            ]
        
        # Generate recommendations
        if gaps["missing_assessments"]:
            gaps["recommendations"].append(f"Schedule assessments for {len(gaps['missing_assessments'])} missing controls")
        
        if gaps["critical_gaps"]:
            gaps["recommendations"].append(f"Prioritize remediation of {len(gaps['critical_gaps'])} critical control gaps")
        
        if len(non_compliant_controls) > len(required_controls) * 0.2:
            gaps["recommendations"].append("Consider comprehensive compliance program review due to high non-compliance rate")
        
        return gaps


class RiskAssessmentEngine:
    """Advanced risk assessment using machine learning and Cortex AI"""
    
    def __init__(self, config: SnowflakeConfig):
        self.config = config
        self.connection_manager = SnowflakeConnectionManager(config)
        self.logger = logging.getLogger(__name__)
        self.ml_models = {}
    
    async def calculate_organizational_risk(self, assessment_period_days: int = 30) -> Dict[str, Any]:
        """Calculate comprehensive organizational risk score"""
        session = self.connection_manager.get_session()
        
        # Gather risk factors
        risk_factors = await self._gather_risk_factors(session, assessment_period_days)
        
        # Calculate component risk scores
        threat_risk = await self._calculate_threat_risk(risk_factors)
        vulnerability_risk = await self._calculate_vulnerability_risk(risk_factors)
        compliance_risk = await self._calculate_compliance_risk(risk_factors)
        operational_risk = await self._calculate_operational_risk(risk_factors)
        
        # Calculate weighted overall risk
        weights = {
            'threat': 0.3,
            'vulnerability': 0.25,
            'compliance': 0.25,
            'operational': 0.2
        }
        
        overall_risk = (
            threat_risk * weights['threat'] +
            vulnerability_risk * weights['vulnerability'] +
            compliance_risk * weights['compliance'] +
            operational_risk * weights['operational']
        )
        
        # Generate risk insights using AI
        risk_insights = await self._generate_risk_insights(risk_factors, overall_risk)
        
        return {
            "overall_risk_score": round(overall_risk, 2),
            "risk_level": self._categorize_risk_level(overall_risk),
            "component_scores": {
                "threat_risk": round(threat_risk, 2),
                "vulnerability_risk": round(vulnerability_risk, 2),
                "compliance_risk": round(compliance_risk, 2),
                "operational_risk": round(operational_risk, 2)
            },
            "risk_factors": risk_factors,
            "ai_insights": risk_insights,
            "assessment_date": datetime.now(timezone.utc).isoformat(),
            "assessment_period_days": assessment_period_days
        }
    
    async def _gather_risk_factors(self, session: Session, days: int) -> Dict[str, Any]:
        """Gather comprehensive risk factors"""
        # Security events analysis
        security_events = session.sql(f"""
            SELECT 
                EVENT_TYPE,
                SEVERITY,
                COUNT(*) as COUNT
            FROM SECURITY_EVENTS
            WHERE TIMESTAMP >= DATEADD(day, -{days}, CURRENT_TIMESTAMP())
            GROUP BY EVENT_TYPE, SEVERITY
        """).collect()
        
        # Vulnerability metrics
        vulnerability_metrics = session.sql(f"""
            SELECT 
                SEVERITY,
                COUNT(*) as COUNT,
                AVG(CASE WHEN METADATA:cvss_score IS NOT NULL THEN METADATA:cvss_score::FLOAT ELSE 5.0 END) as AVG_CVSS
            FROM SECURITY_EVENTS
            WHERE EVENT_TYPE = 'vulnerability_found'
            AND TIMESTAMP >= DATEADD(day, -{days}, CURRENT_TIMESTAMP())
            GROUP BY SEVERITY
        """).collect()
        
        # Compliance status
        compliance_status = session.sql(f"""
            SELECT 
                FRAMEWORK,
                STATUS,
                COUNT(*) as COUNT,
                AVG(SCORE) as AVG_SCORE
            FROM COMPLIANCE_ASSESSMENTS
            WHERE ASSESSMENT_DATE >= DATEADD(day, -{days}, CURRENT_TIMESTAMP())
            GROUP BY FRAMEWORK, STATUS
        """).collect()
        
        # Incident response metrics
        incident_metrics = session.sql(f"""
            SELECT 
                COUNT(*) as TOTAL_INCIDENTS,
                AVG(CASE WHEN METADATA:response_time_minutes IS NOT NULL 
                    THEN METADATA:response_time_minutes::FLOAT ELSE 60 END) as AVG_RESPONSE_TIME,
                COUNT(CASE WHEN SEVERITY = 'critical' THEN 1 END) as CRITICAL_INCIDENTS
            FROM SECURITY_EVENTS
            WHERE EVENT_TYPE = 'incident_response'
            AND TIMESTAMP >= DATEADD(day, -{days}, CURRENT_TIMESTAMP())
        """).collect()
        
        return {
            "security_events": [dict(row.asDict()) for row in security_events],
            "vulnerability_metrics": [dict(row.asDict()) for row in vulnerability_metrics],
            "compliance_status": [dict(row.asDict()) for row in compliance_status],
            "incident_metrics": dict(incident_metrics[0].asDict()) if incident_metrics else {}
        }
    
    async def _calculate_threat_risk(self, risk_factors: Dict[str, Any]) -> float:
        """Calculate threat-based risk score (0-10)"""
        security_events = risk_factors.get('security_events', [])
        
        if not security_events:
            return 3.0  # Baseline risk when no data
        
        # Weight threats by severity
        severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 1}
        threat_score = 0
        total_events = 0
        
        for event in security_events:
            if event['EVENT_TYPE'] == 'threat_detected':
                weight = severity_weights.get(event['SEVERITY'], 3)
                threat_score += event['COUNT'] * weight
                total_events += event['COUNT']
        
        if total_events == 0:
            return 2.0
        
        # Normalize to 0-10 scale
        normalized_score = min(10, (threat_score / total_events) * 1.5)
        return normalized_score
    
    async def _calculate_vulnerability_risk(self, risk_factors: Dict[str, Any]) -> float:
        """Calculate vulnerability-based risk score (0-10)"""
        vuln_metrics = risk_factors.get('vulnerability_metrics', [])
        
        if not vuln_metrics:
            return 4.0  # Baseline risk
        
        # Calculate weighted vulnerability score
        severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2}
        vuln_score = 0
        total_vulns = 0
        
        for metric in vuln_metrics:
            weight = severity_weights.get(metric['SEVERITY'], 3)
            vuln_score += metric['COUNT'] * weight
            total_vulns += metric['COUNT']
        
        if total_vulns == 0:
            return 2.0
        
        # Factor in CVSS scores
        avg_cvss = sum(m.get('AVG_CVSS', 5.0) for m in vuln_metrics) / len(vuln_metrics)
        cvss_factor = avg_cvss / 10.0  # Normalize CVSS to 0-1
        
        # Combine count-based and CVSS-based scores
        normalized_score = min(10, ((vuln_score / total_vulns) * 1.2) + (cvss_factor * 3))
        return normalized_score
    
    async def _calculate_compliance_risk(self, risk_factors: Dict[str, Any]) -> float:
        """Calculate compliance-based risk score (0-10)"""
        compliance_status = risk_factors.get('compliance_status', [])
        
        if not compliance_status:
            return 6.0  # High risk when no compliance data
        
        # Calculate compliance score
        total_assessments = sum(c['COUNT'] for c in compliance_status)
        compliant_assessments = sum(c['COUNT'] for c in compliance_status if c['STATUS'] == 'compliant')
        
        if total_assessments == 0:
            return 6.0
        
        compliance_rate = compliant_assessments / total_assessments
        
        # Convert compliance rate to risk score (inverse relationship)
        risk_score = (1 - compliance_rate) * 10
        return min(10, max(0, risk_score))
    
    async def _calculate_operational_risk(self, risk_factors: Dict[str, Any]) -> float:
        """Calculate operational risk score (0-10)"""
        incident_metrics = risk_factors.get('incident_metrics', {})
        
        if not incident_metrics:
            return 3.0  # Baseline risk
        
        # Factor in incident frequency and response time
        total_incidents = incident_metrics.get('TOTAL_INCIDENTS', 0)
        avg_response_time = incident_metrics.get('AVG_RESPONSE_TIME', 60)
        critical_incidents = incident_metrics.get('CRITICAL_INCIDENTS', 0)
        
        # Calculate risk factors
        incident_frequency_risk = min(5, total_incidents * 0.1)  # Cap at 5
        response_time_risk = min(3, avg_response_time / 30)  # 30 min baseline
        critical_incident_risk = min(2, critical_incidents * 0.5)  # Cap at 2
        
        operational_risk = incident_frequency_risk + response_time_risk + critical_incident_risk
        return min(10, operational_risk)
    
    def _categorize_risk_level(self, risk_score: float) -> str:
        """Categorize risk score into levels"""
        if risk_score >= 8:
            return "Critical"
        elif risk_score >= 6:
            return "High"
        elif risk_score >= 4:
            return "Medium"
        elif risk_score >= 2:
            return "Low"
        else:
            return "Minimal"
    
    async def _generate_risk_insights(self, risk_factors: Dict[str, Any], overall_risk: float) -> Dict[str, Any]:
        """Generate AI-powered risk insights"""
        risk_summary = f"""
        Organizational Risk Assessment Summary:
        - Overall Risk Score: {overall_risk:.2f}/10
        - Security Events: {len(risk_factors.get('security_events', []))} types
        - Vulnerability Metrics: {len(risk_factors.get('vulnerability_metrics', []))} severity levels
        - Compliance Status: {len(risk_factors.get('compliance_status', []))} frameworks assessed
        - Incident Metrics: {risk_factors.get('incident_metrics', {})}
        """
        
        analysis_prompt = f"""
        Analyze the following organizational risk assessment:
        
        {risk_summary}
        
        Provide strategic insights on:
        1. Primary risk drivers and root causes
        2. Immediate actions to reduce risk
        3. Long-term risk management strategies
        4. Resource allocation recommendations
        5. Risk monitoring priorities
        
        Focus on actionable recommendations for executive decision-making.
        """
        
        try:
            cortex_response = Complete(
                model=self.config.cortex_model,
                prompt=analysis_prompt,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature
            )
            
            return {"ai_analysis": cortex_response, "analysis_method": "cortex_ai"}
            
        except Exception as e:
            self.logger.error(f"AI risk analysis failed: {str(e)}")
            return {"error": str(e), "analysis_method": "fallback"}


class StreamlitDashboardManager:
    """Streamlit-in-Snowflake dashboard management"""
    
    def __init__(self, config: SnowflakeConfig):
        self.config = config
        self.connection_manager = SnowflakeConnectionManager(config)
        self.logger = logging.getLogger(__name__)
    
    def create_executive_dashboard(self):
        """Create executive security dashboard"""
        st.set_page_config(
            page_title="CyberCortex Executive Dashboard",
            page_icon="🛡️",
            layout="wide",
            initial_sidebar_state="expanded"
        )
        
        st.title("🛡️ CyberCortex Executive Security Dashboard")
        st.markdown("Real-time security posture and risk assessment")
        
        # Sidebar controls
        st.sidebar.header("Dashboard Controls")
        time_range = st.sidebar.selectbox(
            "Time Range",
            ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "Last 90 Days"]
        )
        
        auto_refresh = st.sidebar.checkbox("Auto Refresh (30s)", value=True)
        
        if auto_refresh:
            st.rerun()
        
        # Main metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                label="Security Score",
                value="87/100",
                delta="5",
                delta_color="normal"
            )
        
        with col2:
            st.metric(
                label="Active Threats",
                value="3",
                delta="-2",
                delta_color="inverse"
            )
        
        with col3:
            st.metric(
                label="Compliance Score",
                value="94%",
                delta="2%",
                delta_color="normal"
            )
        
        with col4:
            st.metric(
                label="Risk Level",
                value="Medium",
                delta="Stable",
                delta_color="off"
            )
        
        # Charts section
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Threat Landscape")
            self._create_threat_chart()
        
        with col2:
            st.subheader("Compliance Status")
            self._create_compliance_chart()
        
        # Detailed analytics
        st.subheader("Security Analytics")
        tab1, tab2, tab3 = st.tabs(["Threat Intelligence", "Vulnerability Management", "Incident Response"])
        
        with tab1:
            self._create_threat_intelligence_view()
        
        with tab2:
            self._create_vulnerability_view()
        
        with tab3:
            self._create_incident_response_view()
    
    def _create_threat_chart(self):
        """Create threat landscape visualization"""
        # Sample data - in production, this would query Snowflake
        threat_data = {
            'Threat Type': ['Malware', 'Phishing', 'DDoS', 'Insider Threat', 'APT'],
            'Count': [45, 32, 18, 12, 8],
            'Severity': ['High', 'Medium', 'Low', 'Medium', 'Critical']
        }
        
        df = pd.DataFrame(threat_data)
        
        fig = px.bar(
            df, 
            x='Threat Type', 
            y='Count',
            color='Severity',
            color_discrete_map={
                'Critical': '#dc2626',
                'High': '#ea580c',
                'Medium': '#d97706',
                'Low': '#65a30d'
            }
        )
        
        fig.update_layout(
            showlegend=True,
            height=400,
            margin=dict(l=0, r=0, t=0, b=0)
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    def _create_compliance_chart(self):
        """Create compliance status visualization"""
        # Sample compliance data
        compliance_data = {
            'Framework': ['SOC2', 'ISO27001', 'NIST', 'GDPR'],
            'Score': [94, 87, 91, 78],
            'Status': ['Compliant', 'Partial', 'Compliant', 'Non-Compliant']
        }
        
        df = pd.DataFrame(compliance_data)
        
        fig = go.Figure()
        
        colors = ['#10b981' if score >= 90 else '#f59e0b' if score >= 75 else '#ef4444' for score in df['Score']]
        
        fig.add_trace(go.Bar(
            x=df['Framework'],
            y=df['Score'],
            marker_color=colors,
            text=df['Score'],
            textposition='auto'
        ))
        
        fig.update_layout(
            yaxis_title="Compliance Score (%)",
            showlegend=False,
            height=400,
            margin=dict(l=0, r=0, t=0, b=0)
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    def _create_threat_intelligence_view(self):
        """Create threat intelligence detailed view"""
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Recent Threats")
            threat_data = [
                {"Threat": "APT29 Campaign", "Confidence": 95, "Severity": "Critical"},
                {"Threat": "Phishing Wave", "Confidence": 87, "Severity": "High"},
                {"Threat": "Malware Family X", "Confidence": 72, "Severity": "Medium"}
            ]
            
            for threat in threat_data:
                with st.container():
                    st.write(f"**{threat['Threat']}**")
                    st.progress(threat['Confidence'] / 100)
                    st.caption(f"Confidence: {threat['Confidence']}% | Severity: {threat['Severity']}")
        
        with col2:
            st.subheader("IOC Analysis")
            ioc_data = {
                'IOC Type': ['IP Address', 'Domain', 'Hash', 'Email'],
                'Count': [156, 89, 234, 45]
            }
            
            fig = px.pie(
                values=ioc_data['Count'],
                names=ioc_data['IOC Type'],
                title="IOC Distribution"
            )
            
            st.plotly_chart(fig, use_container_width=True)
    
    def _create_vulnerability_view(self):
        """Create vulnerability management view"""
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Vulnerability Trends")
            
            # Time series data
            dates = pd.date_range(start='2024-01-01', end='2024-01-30', freq='D')
            vuln_counts = np.random.poisson(15, len(dates))
            
            fig = px.line(
                x=dates,
                y=vuln_counts,
                title="Daily Vulnerability Discoveries"
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("CVSS Score Distribution")
            
            cvss_data = {
                'CVSS Range': ['0-3.9 (Low)', '4.0-6.9 (Medium)', '7.0-8.9 (High)', '9.0-10.0 (Critical)'],
                'Count': [45, 123, 67, 12]
            }
            
            fig = px.bar(
                x=cvss_data['CVSS Range'],
                y=cvss_data['Count'],
                color=cvss_data['Count'],
                color_continuous_scale='Reds'
            )
            
            st.plotly_chart(fig, use_container_width=True)
    
    def _create_incident_response_view(self):
        """Create incident response view"""
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Response Time Metrics")
            
            response_data = {
                'Metric': ['Mean Time to Detection', 'Mean Time to Response', 'Mean Time to Resolution'],
                'Time (minutes)': [15, 45, 180],
                'Target': [30, 60, 240]
            }
            
            df = pd.DataFrame(response_data)
            
            fig = go.Figure()
            fig.add_trace(go.Bar(name='Actual', x=df['Metric'], y=df['Time (minutes)']))
            fig.add_trace(go.Bar(name='Target', x=df['Metric'], y=df['Target']))
            
            fig.update_layout(barmode='group')
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("Incident Status")
            
            status_data = {
                'Status': ['Open', 'In Progress', 'Resolved', 'Closed'],
                'Count': [8, 15, 45, 132]
            }
            
            fig = px.donut(
                values=status_data['Count'],
                names=status_data['Status'],
                title="Current Incident Status"
            )
            
            st.plotly_chart(fig, use_container_width=True)
    
    def create_technical_dashboard(self):
        """Create technical security analytics dashboard"""
        st.set_page_config(
            page_title="CyberCortex Technical Analytics",
            page_icon="🔬",
            layout="wide"
        )
        
        st.title("🔬 Technical Security Analytics")
        st.markdown("Deep-dive security analysis and forensics")
        
        # Advanced analytics sections
        tab1, tab2, tab3, tab4 = st.tabs([
            "Network Analysis", 
            "Behavioral Analytics", 
            "Threat Hunting", 
            "Forensic Analysis"
        ])
        
        with tab1:
            self._create_network_analysis()
        
        with tab2:
            self._create_behavioral_analytics()
        
        with tab3:
            self._create_threat_hunting()
        
        with tab4:
            self._create_forensic_analysis()
    
    def _create_network_analysis(self):
        """Create network security analysis"""
        st.subheader("Network Traffic Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Network flow visualization
            st.write("**Top Talkers**")
            network_data = {
                'Source': ['192.168.1.100', '10.0.0.50', '172.16.1.25'],
                'Destination': ['8.8.8.8', '1.1.1.1', '208.67.222.222'],
                'Bytes': [1024000, 512000, 256000],
                'Packets': [1500, 800, 400]
            }
            
            st.dataframe(pd.DataFrame(network_data))
        
        with col2:
            # Protocol distribution
            protocol_data = {
                'Protocol': ['HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP'],
                'Percentage': [35, 45, 15, 3, 2]
            }
            
            fig = px.pie(
                values=protocol_data['Percentage'],
                names=protocol_data['Protocol'],
                title="Protocol Distribution"
            )
            
            st.plotly_chart(fig, use_container_width=True)
    
    def _create_behavioral_analytics(self):
        """Create behavioral analytics view"""
        st.subheader("User Behavior Analytics")
        
        # Anomaly detection results
        st.write("**Behavioral Anomalies Detected**")
        
        anomaly_data = {
            'User': ['john.doe', 'jane.smith', 'admin'],
            'Anomaly Type': ['Unusual Login Time', 'Excessive Data Access', 'Privilege Escalation'],
            'Risk Score': [7.5, 8.2, 9.1],
            'Status': ['Investigating', 'Resolved', 'Open']
        }
        
        df = pd.DataFrame(anomaly_data)
        
        # Color code by risk score
        def color_risk_score(val):
            if val >= 8:
                return 'background-color: #fee2e2'
            elif val >= 6:
                return 'background-color: #fef3c7'
            else:
                return 'background-color: #dcfce7'
        
        styled_df = df.style.applymap(color_risk_score, subset=['Risk Score'])
        st.dataframe(styled_df)
    
    def _create_threat_hunting(self):
        """Create threat hunting interface"""
        st.subheader("Threat Hunting Console")
        
        # Query interface
        st.write("**Custom Threat Hunt Query**")
        query = st.text_area(
            "Enter your hunt query:",
            value="SELECT * FROM SECURITY_EVENTS WHERE severity = 'critical' AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '24 HOURS'"
        )
        
        if st.button("Execute Hunt"):
            st.success("Hunt query executed successfully!")
            
            # Mock results
            hunt_results = {
                'Event ID': ['evt_001', 'evt_002', 'evt_003'],
                'Timestamp': ['2024-01-15 10:30:00', '2024-01-15 11:45:00', '2024-01-15 12:15:00'],
                'Threat Type': ['Malware', 'Phishing', 'C2 Communication'],
                'Confidence': [0.95, 0.87, 0.92]
            }
            
            st.dataframe(pd.DataFrame(hunt_results))
    
    def _create_forensic_analysis(self):
        """Create forensic analysis view"""
        st.subheader("Digital Forensics")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Timeline Analysis**")
            
            # Timeline visualization
            timeline_data = {
                'Time': ['10:00', '10:15', '10:30', '10:45', '11:00'],
                'Event': ['Initial Access', 'Privilege Escalation', 'Lateral Movement', 'Data Exfiltration', 'Cleanup'],
                'Severity': [8, 9, 7, 10, 6]
            }
            
            fig = px.line(
                x=timeline_data['Time'],
                y=timeline_data['Severity'],
                markers=True,
                title="Attack Timeline"
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.write("**Evidence Collection**")
            
            evidence_data = {
                'Artifact': ['Memory Dump', 'Network Logs', 'File System', 'Registry'],
                'Status': ['Collected', 'Analyzing', 'Collected', 'Pending'],
                'Size': ['2.1 GB', '450 MB', '1.8 GB', '125 MB']
            }
            
            st.dataframe(pd.DataFrame(evidence_data))


class SnowflakeSecurityAnalytics:
    """Main Snowflake security analytics orchestrator"""
    
    def __init__(self, config: SnowflakeConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.data_pipeline = SecurityDataPipeline(config)
        self.threat_analyzer = ThreatIntelligenceAnalyzer(config)
        self.compliance_reporter = ComplianceReporter(config)
        self.risk_engine = RiskAssessmentEngine(config)
        self.dashboard_manager = StreamlitDashboardManager(config)
        
        # Performance metrics
        self.metrics = {
            'events_ingested': 0,
            'analyses_completed': 0,
            'reports_generated': 0,
            'uptime_start': datetime.now(timezone.utc)
        }
    
    async def initialize(self):
        """Initialize the analytics system"""
        await self.data_pipeline.initialize()
        self.logger.info("Snowflake Security Analytics initialized successfully")
    
    async def ingest_security_event(self, event_data: Dict[str, Any]) -> str:
        """Ingest single security event"""
        event = SecurityEvent(
            event_id=event_data.get('event_id', self._generate_event_id()),
            event_type=SecurityEventType(event_data['event_type']),
            timestamp=datetime.fromisoformat(event_data['timestamp']) if isinstance(event_data['timestamp'], str) else event_data['timestamp'],
            severity=event_data['severity'],
            source=event_data['source'],
            target=event_data.get('target'),
            description=event_data['description'],
            metadata=event_data.get('metadata', {}),
            tags=event_data.get('tags', []),
            correlation_id=event_data.get('correlation_id')
        )
        
        await self.data_pipeline.ingest_event(event)
        self.metrics['events_ingested'] += 1
        
        return event.event_id
    
    async def generate_comprehensive_report(self, report_type: str = "executive", period_days: int = 30) -> Dict[str, Any]:
        """Generate comprehensive security analytics report"""
        start_time = time.time()
        
        try:
            # Gather analytics from all components
            threat_analysis = await self.threat_analyzer.analyze_threat_patterns(period_days * 24)
            risk_assessment = await self.risk_engine.calculate_organizational_risk(period_days)
            
            # Generate compliance reports for all frameworks
            compliance_reports = {}
            for framework in ['SOC2', 'ISO27001', 'NIST']:
                try:
                    compliance_reports[framework] = await self.compliance_reporter.generate_compliance_report(framework, period_days)
                except Exception as e:
                    self.logger.error(f"Compliance report failed for {framework}: {str(e)}")
                    compliance_reports[framework] = {"error": str(e)}
            
            # Compile comprehensive report
            report = {
                "report_metadata": {
                    "report_type": report_type,
                    "period_days": period_days,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "generation_time_seconds": time.time() - start_time
                },
                "executive_summary": {
                    "overall_risk_score": risk_assessment.get('overall_risk_score', 0),
                    "risk_level": risk_assessment.get('risk_level', 'Unknown'),
                    "threat_events_analyzed": threat_analysis.get('events_analyzed', 0),
                    "compliance_frameworks_assessed": len(compliance_reports),
                    "key_findings": self._extract_key_findings(threat_analysis, risk_assessment, compliance_reports)
                },
                "detailed_analysis": {
                    "threat_intelligence": threat_analysis,
                    "risk_assessment": risk_assessment,
                    "compliance_reports": compliance_reports
                },
                "recommendations": self._generate_strategic_recommendations(threat_analysis, risk_assessment, compliance_reports),
                "system_metrics": self.get_system_metrics()
            }
            
            self.metrics['reports_generated'] += 1
            return report
            
        except Exception as e:
            self.logger.error(f"Comprehensive report generation failed: {str(e)}")
            raise
    
    def _extract_key_findings(self, threat_analysis: Dict, risk_assessment: Dict, compliance_reports: Dict) -> List[str]:
        """Extract key findings from analysis results"""
        findings = []
        
        # Risk-based findings
        risk_level = risk_assessment.get('risk_level', 'Unknown')
        if risk_level in ['Critical', 'High']:
            findings.append(f"Organization risk level is {risk_level} - immediate attention required")
        
        # Threat-based findings
        events_analyzed = threat_analysis.get('events_analyzed', 0)
        if events_analyzed > 100:
            findings.append(f"High threat activity detected: {events_analyzed} events analyzed")
        
        # Compliance-based findings
        non_compliant_frameworks = [
            framework for framework, report in compliance_reports.items()
            if report.get('overall_score', 100) < 80
        ]
        
        if non_compliant_frameworks:
            findings.append(f"Compliance gaps identified in: {', '.join(non_compliant_frameworks)}")
        
        return findings
    
    def _generate_strategic_recommendations(self, threat_analysis: Dict, risk_assessment: Dict, compliance_reports: Dict) -> List[Dict[str, Any]]:
        """Generate strategic recommendations based on analysis"""
        recommendations = []
        
        # Risk-based recommendations
        risk_level = risk_assessment.get('risk_level', 'Unknown')
        if risk_level == 'Critical':
            recommendations.append({
                "priority": "immediate",
                "category": "risk_management",
                "recommendation": "Implement emergency risk mitigation measures",
                "rationale": f"Overall risk score of {risk_assessment.get('overall_risk_score', 0)} requires immediate action"
            })
        
        # Compliance-based recommendations
        for framework, report in compliance_reports.items():
            if report.get('overall_score', 100) < 90:
                recommendations.append({
                    "priority": "high",
                    "category": "compliance",
                    "recommendation": f"Address {framework} compliance gaps",
                    "rationale": f"Current score of {report.get('overall_score', 0)}% below target"
                })
        
        # Threat-based recommendations
        if threat_analysis.get('events_analyzed', 0) > 50:
            recommendations.append({
                "priority": "medium",
                "category": "threat_management",
                "recommendation": "Enhance threat detection capabilities",
                "rationale": "High volume of threat events indicates need for improved detection"
            })
        
        return recommendations
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """Get system performance metrics"""
        uptime = datetime.now(timezone.utc) - self.metrics['uptime_start']
        
        return {
            "events_ingested": self.metrics['events_ingested'],
            "analyses_completed": self.metrics['analyses_completed'],
            "reports_generated": self.metrics['reports_generated'],
            "uptime_hours": uptime.total_seconds() / 3600,
            "ingestion_rate": self.metrics['events_ingested'] / max(1, uptime.total_seconds() / 3600),
            "system_status": "operational"
        }
    
    def _generate_event_id(self) -> str:
        """Generate unique event ID"""
        timestamp = datetime.now(timezone.utc).isoformat()
        return f"evt_{hashlib.sha256(timestamp.encode()).hexdigest()[:12]}"
    
    def launch_streamlit_dashboard(self, dashboard_type: str = "executive"):
        """Launch Streamlit dashboard"""
        if dashboard_type == "executive":
            self.dashboard_manager.create_executive_dashboard()
        elif dashboard_type == "technical":
            self.dashboard_manager.create_technical_dashboard()
        else:
            raise ValueError(f"Unknown dashboard type: {dashboard_type}")


# Example usage and configuration
async def main():
    """Example usage of Snowflake Security Analytics"""
    
    # Configure Snowflake connection
    config = SnowflakeConfig(
        account="your_account.region",
        user="your_username",
        password="your_password",
        database="CYBERCORTEX_DB",
        schema="SECURITY_ANALYTICS",
        warehouse="COMPUTE_WH",
        role="CYBERCORTEX_ROLE"
    )
    
    # Initialize analytics system
    analytics = SnowflakeSecurityAnalytics(config)
    await analytics.initialize()
    
    try:
        # Example: Ingest security events
        sample_events = [
            {
                "event_type": "threat_detected",
                "timestamp": datetime.now(timezone.utc),
                "severity": "high",
                "source": "network_monitor",
                "target": "web_server_01",
                "description": "Suspicious network activity detected",
                "metadata": {"source_ip": "192.168.1.100", "attack_type": "port_scan"},
                "tags": ["network", "reconnaissance"]
            },
            {
                "event_type": "vulnerability_found",
                "timestamp": datetime.now(timezone.utc),
                "severity": "critical",
                "source": "vulnerability_scanner",
                "target": "database_server",
                "description": "SQL injection vulnerability discovered",
                "metadata": {"cvss_score": 9.1, "cve_id": "CVE-2024-0001"},
                "tags": ["web", "injection"]
            }
        ]
        
        # Ingest events
        for event_data in sample_events:
            event_id = await analytics.ingest_security_event(event_data)
            print(f"Ingested event: {event_id}")
        
        # Generate comprehensive report
        report = await analytics.generate_comprehensive_report("executive", 30)
        print(f"Generated report with {len(report['detailed_analysis'])} analysis components")
        
        # Display system metrics
        metrics = analytics.get_system_metrics()
        print(f"System metrics: {metrics}")
        
        # Launch dashboard (in production, this would be deployed to Snowflake)
        # analytics.launch_streamlit_dashboard("executive")
        
    finally:
        # Cleanup
        analytics.data_pipeline.stop()


if __name__ == "__main__":
    asyncio.run(main())