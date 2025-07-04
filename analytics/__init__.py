"""
CyberCortex Analytics Framework

Advanced security analytics powered by Snowflake Cortex AI with real-time
data ingestion, intelligent pattern recognition, and automated reporting.
"""

from .snowflake_integration import (
    SnowflakeSecurityAnalytics,
    SecurityDataPipeline,
    ComplianceReporter,
    ThreatIntelligenceAnalyzer,
    RiskAssessmentEngine,
    StreamlitDashboardManager
)

__all__ = [
    'SnowflakeSecurityAnalytics',
    'SecurityDataPipeline',
    'ComplianceReporter',
    'ThreatIntelligenceAnalyzer',
    'RiskAssessmentEngine',
    'StreamlitDashboardManager'
]

__version__ = "1.0.0"
__author__ = "CyberCortex Analytics Team"