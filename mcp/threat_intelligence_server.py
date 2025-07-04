"""
Threat Intelligence MCP Server

Provides unified interface for threat intelligence feeds including MISP, STIX/TAXII,
commercial feeds, and custom threat data with real-time correlation and analysis.
"""

import asyncio
import json
import logging
import aiohttp
import hashlib
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict, field
from pathlib import Path
import sqlite3
import xml.etree.ElementTree as ET
import re

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


@dataclass
class ThreatIndicator:
    """Individual threat indicator (IOC)"""
    indicator_id: str
    indicator_type: str  # ip, domain, url, hash, email, etc.
    value: str
    confidence: float  # 0.0 to 1.0
    threat_types: List[str]
    first_seen: datetime
    last_seen: datetime
    source: str
    tags: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['first_seen'] = self.first_seen.isoformat()
        data['last_seen'] = self.last_seen.isoformat()
        return data


@dataclass
class ThreatActor:
    """Threat actor information"""
    actor_id: str
    name: str
    aliases: List[str]
    country: Optional[str]
    motivation: List[str]
    sophistication: str  # low, medium, high, expert
    first_seen: datetime
    last_activity: datetime
    associated_campaigns: List[str] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)  # MITRE ATT&CK techniques
    indicators: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['first_seen'] = self.first_seen.isoformat()
        data['last_activity'] = self.last_activity.isoformat()
        return data


@dataclass
class ThreatCampaign:
    """Threat campaign information"""
    campaign_id: str
    name: str
    description: str
    first_seen: datetime
    last_activity: datetime
    attributed_actors: List[str]
    target_sectors: List[str]
    target_countries: List[str]
    ttps: List[str]  # MITRE ATT&CK techniques
    indicators: List[str]
    confidence: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['first_seen'] = self.first_seen.isoformat()
        data['last_activity'] = self.last_activity.isoformat()
        return data


@dataclass
class ThreatIntelligenceReport:
    """Comprehensive threat intelligence report"""
    report_id: str
    title: str
    summary: str
    threat_level: str  # low, medium, high, critical
    confidence: float
    published_date: datetime
    source: str
    indicators: List[ThreatIndicator]
    actors: List[ThreatActor]
    campaigns: List[ThreatCampaign]
    ttps: List[str]
    recommendations: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['published_date'] = self.published_date.isoformat()
        data['indicators'] = [ind.to_dict() for ind in self.indicators]
        data['actors'] = [actor.to_dict() for actor in self.actors]
        data['campaigns'] = [camp.to_dict() for camp in self.campaigns]
        return data


class ThreatIntelligenceDatabase:
    """Database for storing threat intelligence data"""
    
    def __init__(self, db_path: str = "threat_intelligence.sqlite"):
        self.db_path = db_path
        self.connection: Optional[sqlite3.Connection] = None
        self.logger = logging.getLogger(__name__)
    
    async def initialize(self):
        """Initialize database schema"""
        self.connection = sqlite3.connect(self.db_path)
        self.connection.row_factory = sqlite3.Row
        
        await self._create_tables()
        await self._create_indexes()
        
        self.logger.info("Threat intelligence database initialized")
    
    async def _create_tables(self):
        """Create database tables"""
        cursor = self.connection.cursor()
        
        # Indicators table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS indicators (
                indicator_id TEXT PRIMARY KEY,
                indicator_type TEXT NOT NULL,
                value TEXT NOT NULL,
                confidence REAL,
                threat_types TEXT,  -- JSON array
                first_seen TEXT,
                last_seen TEXT,
                source TEXT,
                tags TEXT,  -- JSON array
                context TEXT,  -- JSON object
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Threat actors table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_actors (
                actor_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                aliases TEXT,  -- JSON array
                country TEXT,
                motivation TEXT,  -- JSON array
                sophistication TEXT,
                first_seen TEXT,
                last_activity TEXT,
                associated_campaigns TEXT,  -- JSON array
                ttps TEXT,  -- JSON array
                indicators TEXT,  -- JSON array
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Campaigns table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS campaigns (
                campaign_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                first_seen TEXT,
                last_activity TEXT,
                attributed_actors TEXT,  -- JSON array
                target_sectors TEXT,  -- JSON array
                target_countries TEXT,  -- JSON array
                ttps TEXT,  -- JSON array
                indicators TEXT,  -- JSON array
                confidence REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Reports table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                report_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                summary TEXT,
                threat_level TEXT,
                confidence REAL,
                published_date TEXT,
                source TEXT,
                indicators TEXT,  -- JSON array of indicator IDs
                actors TEXT,  -- JSON array of actor IDs
                campaigns TEXT,  -- JSON array of campaign IDs
                ttps TEXT,  -- JSON array
                recommendations TEXT,  -- JSON array
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Feed sources table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS feed_sources (
                source_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT,
                feed_type TEXT,  -- misp, stix, json, xml, csv
                api_key TEXT,
                last_update TIMESTAMP,
                update_frequency INTEGER,  -- minutes
                active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        self.connection.commit()
    
    async def _create_indexes(self):
        """Create database indexes"""
        cursor = self.connection.cursor()
        
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_indicator_type ON indicators(indicator_type)",
            "CREATE INDEX IF NOT EXISTS idx_indicator_value ON indicators(value)",
            "CREATE INDEX IF NOT EXISTS idx_indicator_source ON indicators(source)",
            "CREATE INDEX IF NOT EXISTS idx_indicator_confidence ON indicators(confidence)",
            "CREATE INDEX IF NOT EXISTS idx_actor_name ON threat_actors(name)",
            "CREATE INDEX IF NOT EXISTS idx_actor_country ON threat_actors(country)",
            "CREATE INDEX IF NOT EXISTS idx_campaign_name ON campaigns(name)",
            "CREATE INDEX IF NOT EXISTS idx_report_threat_level ON reports(threat_level)",
            "CREATE INDEX IF NOT EXISTS idx_report_published ON reports(published_date)"
        ]
        
        for index_sql in indexes:
            cursor.execute(index_sql)
        
        self.connection.commit()
    
    async def store_indicator(self, indicator: ThreatIndicator):
        """Store threat indicator"""
        cursor = self.connection.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO indicators (
                indicator_id, indicator_type, value, confidence, threat_types,
                first_seen, last_seen, source, tags, context, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (
            indicator.indicator_id,
            indicator.indicator_type,
            indicator.value,
            indicator.confidence,
            json.dumps(indicator.threat_types),
            indicator.first_seen.isoformat(),
            indicator.last_seen.isoformat(),
            indicator.source,
            json.dumps(indicator.tags),
            json.dumps(indicator.context)
        ))
        
        self.connection.commit()
    
    async def search_indicators(self, query: str = None, indicator_type: str = None,
                              confidence_min: float = None, source: str = None,
                              limit: int = 100) -> List[ThreatIndicator]:
        """Search threat indicators"""
        cursor = self.connection.cursor()
        
        sql = "SELECT * FROM indicators WHERE 1=1"
        params = []
        
        if query:
            sql += " AND (value LIKE ? OR indicator_id LIKE ?)"
            search_term = f"%{query}%"
            params.extend([search_term, search_term])
        
        if indicator_type:
            sql += " AND indicator_type = ?"
            params.append(indicator_type)
        
        if confidence_min is not None:
            sql += " AND confidence >= ?"
            params.append(confidence_min)
        
        if source:
            sql += " AND source = ?"
            params.append(source)
        
        sql += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        
        indicators = []
        for row in rows:
            indicator = ThreatIndicator(
                indicator_id=row['indicator_id'],
                indicator_type=row['indicator_type'],
                value=row['value'],
                confidence=row['confidence'],
                threat_types=json.loads(row['threat_types'] or '[]'),
                first_seen=datetime.fromisoformat(row['first_seen']),
                last_seen=datetime.fromisoformat(row['last_seen']),
                source=row['source'],
                tags=json.loads(row['tags'] or '[]'),
                context=json.loads(row['context'] or '{}')
            )
            indicators.append(indicator)
        
        return indicators
    
    async def get_indicator_by_value(self, value: str) -> Optional[ThreatIndicator]:
        """Get indicator by value"""
        results = await self.search_indicators(query=value, limit=1)
        return results[0] if results else None


class ThreatFeedManager:
    """Manages threat intelligence feeds from multiple sources"""
    
    def __init__(self, database: ThreatIntelligenceDatabase):
        self.database = database
        self.logger = logging.getLogger(__name__)
        
        # Feed configurations
        self.feeds = {
            'misp': {
                'url': None,  # Set from configuration
                'api_key': None,
                'feed_type': 'misp',
                'update_frequency': 60  # minutes
            },
            'otx': {
                'url': 'https://otx.alienvault.com/api/v1/pulses/subscribed',
                'api_key': None,
                'feed_type': 'json',
                'update_frequency': 120
            },
            'threatfox': {
                'url': 'https://threatfox-api.abuse.ch/api/v1/',
                'api_key': None,
                'feed_type': 'json',
                'update_frequency': 30
            },
            'urlhaus': {
                'url': 'https://urlhaus-api.abuse.ch/v1/urls/recent/',
                'api_key': None,
                'feed_type': 'json',
                'update_frequency': 15
            }
        }
    
    async def update_threatfox_feed(self) -> int:
        """Update from ThreatFox feed"""
        try:
            updated_count = 0
            
            async with aiohttp.ClientSession() as session:
                # Get recent IOCs from ThreatFox
                payload = {
                    'query': 'get_iocs',
                    'days': 1
                }
                
                async with session.post(
                    self.feeds['threatfox']['url'],
                    json=payload
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if data.get('query_status') == 'ok':
                            for ioc_data in data.get('data', []):
                                indicator = await self._parse_threatfox_ioc(ioc_data)
                                if indicator:
                                    await self.database.store_indicator(indicator)
                                    updated_count += 1
            
            self.logger.info(f"Updated {updated_count} indicators from ThreatFox")
            return updated_count
            
        except Exception as e:
            self.logger.error(f"Failed to update ThreatFox feed: {str(e)}")
            return 0
    
    async def _parse_threatfox_ioc(self, ioc_data: Dict[str, Any]) -> Optional[ThreatIndicator]:
        """Parse ThreatFox IOC data"""
        try:
            ioc_value = ioc_data.get('ioc')
            ioc_type = ioc_data.get('ioc_type', '').lower()
            
            if not ioc_value or not ioc_type:
                return None
            
            # Map ThreatFox types to standard types
            type_mapping = {
                'md5_hash': 'hash',
                'sha1_hash': 'hash',
                'sha256_hash': 'hash',
                'domain': 'domain',
                'url': 'url',
                'ip:port': 'ip'
            }
            
            indicator_type = type_mapping.get(ioc_type, ioc_type)
            
            # Extract threat types
            threat_types = []
            malware_printable = ioc_data.get('malware_printable', '')
            if malware_printable:
                threat_types.append(malware_printable)
            
            # Calculate confidence based on ThreatFox confidence
            confidence_level = ioc_data.get('confidence_level', 50)
            confidence = confidence_level / 100.0
            
            # Parse dates
            first_seen = datetime.fromisoformat(ioc_data.get('first_seen_utc', '').replace('Z', '+00:00'))
            last_seen = first_seen  # ThreatFox doesn't provide separate last_seen
            
            return ThreatIndicator(
                indicator_id=f"threatfox_{ioc_data.get('id')}",
                indicator_type=indicator_type,
                value=ioc_value,
                confidence=confidence,
                threat_types=threat_types,
                first_seen=first_seen,
                last_seen=last_seen,
                source='threatfox',
                tags=ioc_data.get('tags', []),
                context={
                    'malware_alias': ioc_data.get('malware_alias'),
                    'malware_malpedia': ioc_data.get('malware_malpedia'),
                    'reference': ioc_data.get('reference')
                }
            )
            
        except Exception as e:
            self.logger.error(f"Failed to parse ThreatFox IOC: {str(e)}")
            return None
    
    async def update_urlhaus_feed(self) -> int:
        """Update from URLhaus feed"""
        try:
            updated_count = 0
            
            async with aiohttp.ClientSession() as session:
                async with session.get(self.feeds['urlhaus']['url']) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for url_data in data.get('urls', []):
                            indicator = await self._parse_urlhaus_url(url_data)
                            if indicator:
                                await self.database.store_indicator(indicator)
                                updated_count += 1
            
            self.logger.info(f"Updated {updated_count} indicators from URLhaus")
            return updated_count
            
        except Exception as e:
            self.logger.error(f"Failed to update URLhaus feed: {str(e)}")
            return 0
    
    async def _parse_urlhaus_url(self, url_data: Dict[str, Any]) -> Optional[ThreatIndicator]:
        """Parse URLhaus URL data"""
        try:
            url = url_data.get('url')
            if not url:
                return None
            
            # Parse dates
            date_added = datetime.fromisoformat(url_data.get('date_added', '').replace('Z', '+00:00'))
            
            # Extract threat types
            threat_types = []
            if url_data.get('threat'):
                threat_types.append(url_data['threat'])
            
            return ThreatIndicator(
                indicator_id=f"urlhaus_{url_data.get('id')}",
                indicator_type='url',
                value=url,
                confidence=0.8,  # URLhaus has high confidence
                threat_types=threat_types,
                first_seen=date_added,
                last_seen=date_added,
                source='urlhaus',
                tags=url_data.get('tags', []),
                context={
                    'url_status': url_data.get('url_status'),
                    'threat': url_data.get('threat'),
                    'reporter': url_data.get('reporter')
                }
            )
            
        except Exception as e:
            self.logger.error(f"Failed to parse URLhaus URL: {str(e)}")
            return None


class ThreatCorrelationEngine:
    """Correlates threat intelligence with security events"""
    
    def __init__(self, database: ThreatIntelligenceDatabase):
        self.database = database
        self.logger = logging.getLogger(__name__)
    
    async def correlate_indicators(self, indicators: List[str]) -> Dict[str, Any]:
        """Correlate list of indicators with threat intelligence"""
        correlations = {}
        threat_score = 0.0
        max_confidence = 0.0
        
        for indicator_value in indicators:
            # Search for indicator in database
            threat_indicator = await self.database.get_indicator_by_value(indicator_value)
            
            if threat_indicator:
                correlations[indicator_value] = {
                    'found': True,
                    'indicator': threat_indicator.to_dict(),
                    'threat_level': self._calculate_threat_level(threat_indicator),
                    'age_days': (datetime.now(timezone.utc) - threat_indicator.last_seen).days
                }
                
                # Update overall threat score
                threat_score += threat_indicator.confidence
                max_confidence = max(max_confidence, threat_indicator.confidence)
            else:
                correlations[indicator_value] = {
                    'found': False,
                    'threat_level': 'unknown'
                }
        
        # Calculate overall assessment
        found_indicators = len([c for c in correlations.values() if c['found']])
        overall_threat_level = self._calculate_overall_threat_level(threat_score, found_indicators, max_confidence)
        
        return {
            'correlations': correlations,
            'summary': {
                'total_indicators': len(indicators),
                'found_indicators': found_indicators,
                'overall_threat_level': overall_threat_level,
                'max_confidence': max_confidence,
                'threat_score': threat_score
            }
        }
    
    def _calculate_threat_level(self, indicator: ThreatIndicator) -> str:
        """Calculate threat level for individual indicator"""
        if indicator.confidence >= 0.8:
            return 'high'
        elif indicator.confidence >= 0.6:
            return 'medium'
        elif indicator.confidence >= 0.3:
            return 'low'
        else:
            return 'unknown'
    
    def _calculate_overall_threat_level(self, threat_score: float, found_count: int, max_confidence: float) -> str:
        """Calculate overall threat level"""
        if found_count == 0:
            return 'none'
        
        avg_score = threat_score / found_count
        
        if max_confidence >= 0.8 and avg_score >= 0.7:
            return 'critical'
        elif max_confidence >= 0.6 and avg_score >= 0.5:
            return 'high'
        elif avg_score >= 0.3:
            return 'medium'
        else:
            return 'low'


class ThreatIntelligenceServer:
    """MCP Server for threat intelligence operations"""
    
    def __init__(self, db_path: str = "threat_intelligence.sqlite"):
        self.server = Server("threat-intelligence")
        self.logger = logging.getLogger(__name__)
        self.database = ThreatIntelligenceDatabase(db_path)
        self.feed_manager = ThreatFeedManager(self.database)
        self.correlation_engine = ThreatCorrelationEngine(self.database)
        self.registry = ToolRegistry()
        
        self._register_tools()
        self._setup_handlers()
    
    def _register_tools(self):
        """Register threat intelligence tools"""
        
        self.registry.register_tool(ToolCapability(
            name="search_indicators",
            description="Search threat intelligence indicators",
            parameters=[
                ToolParameter("query", "string", "Search query (IOC value, partial match)", False),
                ToolParameter("indicator_type", "string", "Filter by indicator type", False),
                ToolParameter("confidence_min", "number", "Minimum confidence level (0.0-1.0)", False),
                ToolParameter("source", "string", "Filter by source", False),
                ToolParameter("limit", "integer", "Maximum results to return", False, 100)
            ],
            category="threat_search",
            requires_auth=False,
            risk_level="low"
        ))
        
        self.registry.register_tool(ToolCapability(
            name="lookup_indicator",
            description="Lookup specific threat indicator",
            parameters=[
                ToolParameter("indicator", "string", "Indicator value to lookup", True),
                ToolParameter("include_context", "boolean", "Include additional context", False, True)
            ],
            category="threat_lookup",
            requires_auth=False,
            risk_level="low"
        ))
        
        self.registry.register_tool(ToolCapability(
            name="correlate_indicators",
            description="Correlate multiple indicators with threat intelligence",
            parameters=[
                ToolParameter("indicators", "array", "List of indicators to correlate", True),
                ToolParameter("include_details", "boolean", "Include detailed threat information", False, True)
            ],
            category="threat_correlation",
            requires_auth=False,
            risk_level="low"
        ))
        
        self.registry.register_tool(ToolCapability(
            name="update_threat_feeds",
            description="Update threat intelligence feeds",
            parameters=[
                ToolParameter("feed_sources", "array", "Feed sources to update", False, ["threatfox", "urlhaus"]),
                ToolParameter("force_update", "boolean", "Force update even if recently updated", False, False)
            ],
            category="feed_management",
            requires_auth=True,
            risk_level="low"
        ))
        
        self.registry.register_tool(ToolCapability(
            name="threat_statistics",
            description="Get threat intelligence statistics",
            parameters=[
                ToolParameter("time_period", "string", "Time period for statistics (7d, 30d, 90d)", False, "30d"),
                ToolParameter("group_by", "string", "Group statistics by (type, source, threat_type)", False, "type")
            ],
            category="threat_analytics",
            requires_auth=False,
            risk_level="low"
        ))
        
        self.registry.register_tool(ToolCapability(
            name="enrich_indicators",
            description="Enrich indicators with additional threat intelligence",
            parameters=[
                ToolParameter("indicators", "array", "List of indicators to enrich", True),
                ToolParameter("enrichment_sources", "array", "Sources for enrichment", False, ["all"])
            ],
            category="threat_enrichment",
            requires_auth=False,
            risk_level="medium"
        ))
        
        self.registry.register_tool(ToolCapability(
            name="generate_threat_report",
            description="Generate threat intelligence report",
            parameters=[
                ToolParameter("indicators", "array", "Indicators to include in report", True),
                ToolParameter("report_type", "string", "Report type (summary, detailed, ioc_list)", False, "summary"),
                ToolParameter("include_recommendations", "boolean", "Include security recommendations", False, True)
            ],
            category="threat_reporting",
            requires_auth=False,
            risk_level="low"
        ))
    
    def _setup_handlers(self):
        """Setup MCP request handlers"""
        
        @self.server.list_tools()
        async def handle_list_tools() -> List[Tool]:
            """List available threat intelligence tools"""
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
            """Execute threat intelligence tool"""
            try:
                start_time = datetime.now()
                
                if name == "search_indicators":
                    result = await self._search_indicators(arguments)
                elif name == "lookup_indicator":
                    result = await self._lookup_indicator(arguments)
                elif name == "correlate_indicators":
                    result = await self._correlate_indicators(arguments)
                elif name == "update_threat_feeds":
                    result = await self._update_threat_feeds(arguments)
                elif name == "threat_statistics":
                    result = await self._threat_statistics(arguments)
                elif name == "enrich_indicators":
                    result = await self._enrich_indicators(arguments)
                elif name == "generate_threat_report":
                    result = await self._generate_threat_report(arguments)
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
    
    async def _search_indicators(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Search threat indicators"""
        query = arguments.get('query')
        indicator_type = arguments.get('indicator_type')
        confidence_min = arguments.get('confidence_min')
        source = arguments.get('source')
        limit = arguments.get('limit', 100)
        
        indicators = await self.database.search_indicators(
            query=query,
            indicator_type=indicator_type,
            confidence_min=confidence_min,
            source=source,
            limit=limit
        )
        
        return {
            'query': query,
            'filters': {
                'indicator_type': indicator_type,
                'confidence_min': confidence_min,
                'source': source
            },
            'total_results': len(indicators),
            'indicators': [indicator.to_dict() for indicator in indicators]
        }
    
    async def _lookup_indicator(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Lookup specific indicator"""
        indicator_value = arguments['indicator']
        include_context = arguments.get('include_context', True)
        
        indicator = await self.database.get_indicator_by_value(indicator_value)
        
        if indicator:
            result = {
                'found': True,
                'indicator': indicator.to_dict(),
                'threat_level': self.correlation_engine._calculate_threat_level(indicator),
                'age_days': (datetime.now(timezone.utc) - indicator.last_seen).days
            }
            
            if include_context:
                result['enrichment'] = {
                    'is_recent': (datetime.now(timezone.utc) - indicator.last_seen).days <= 30,
                    'high_confidence': indicator.confidence >= 0.8,
                    'threat_categories': indicator.threat_types
                }
            
            return result
        else:
            return {
                'found': False,
                'indicator': indicator_value,
                'message': 'Indicator not found in threat intelligence database'
            }
    
    async def _correlate_indicators(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate multiple indicators"""
        indicators = arguments['indicators']
        include_details = arguments.get('include_details', True)
        
        correlation_result = await self.correlation_engine.correlate_indicators(indicators)
        
        if include_details:
            # Add additional analysis
            correlation_result['analysis'] = {
                'risk_assessment': self._assess_risk_level(correlation_result),
                'recommendations': self._generate_recommendations(correlation_result)
            }
        
        return correlation_result
    
    async def _update_threat_feeds(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Update threat intelligence feeds"""
        feed_sources = arguments.get('feed_sources', ['threatfox', 'urlhaus'])
        force_update = arguments.get('force_update', False)
        
        results = {}
        
        for feed_source in feed_sources:
            try:
                if feed_source == 'threatfox':
                    updated_count = await self.feed_manager.update_threatfox_feed()
                    results[feed_source] = {
                        'status': 'success',
                        'updated_count': updated_count
                    }
                elif feed_source == 'urlhaus':
                    updated_count = await self.feed_manager.update_urlhaus_feed()
                    results[feed_source] = {
                        'status': 'success',
                        'updated_count': updated_count
                    }
                else:
                    results[feed_source] = {
                        'status': 'error',
                        'message': f"Unknown feed source: {feed_source}"
                    }
            except Exception as e:
                results[feed_source] = {
                    'status': 'error',
                    'message': str(e)
                }
        
        return {
            'update_results': results,
            'total_updated': sum(r.get('updated_count', 0) for r in results.values() if r.get('status') == 'success')
        }
    
    async def _threat_statistics(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get threat intelligence statistics"""
        time_period = arguments.get('time_period', '30d')
        group_by = arguments.get('group_by', 'type')
        
        # Calculate date range
        days = int(time_period.rstrip('d'))
        start_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        # Get recent indicators
        indicators = await self.database.search_indicators(limit=10000)
        recent_indicators = [
            ind for ind in indicators 
            if ind.last_seen >= start_date
        ]
        
        stats = {
            'time_period': time_period,
            'total_indicators': len(recent_indicators),
            'date_range': {
                'start': start_date.isoformat(),
                'end': datetime.now(timezone.utc).isoformat()
            }
        }
        
        if group_by == 'type':
            type_counts = {}
            for indicator in recent_indicators:
                type_counts[indicator.indicator_type] = type_counts.get(indicator.indicator_type, 0) + 1
            stats['breakdown'] = type_counts
        
        elif group_by == 'source':
            source_counts = {}
            for indicator in recent_indicators:
                source_counts[indicator.source] = source_counts.get(indicator.source, 0) + 1
            stats['breakdown'] = source_counts
        
        elif group_by == 'threat_type':
            threat_counts = {}
            for indicator in recent_indicators:
                for threat_type in indicator.threat_types:
                    threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
            stats['breakdown'] = threat_counts
        
        return stats
    
    async def _enrich_indicators(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich indicators with additional intelligence"""
        indicators = arguments['indicators']
        enrichment_sources = arguments.get('enrichment_sources', ['all'])
        
        enriched_indicators = []
        
        for indicator_value in indicators:
            # Get base indicator information
            base_indicator = await self.database.get_indicator_by_value(indicator_value)
            
            enrichment = {
                'indicator': indicator_value,
                'base_intelligence': base_indicator.to_dict() if base_indicator else None,
                'enrichment_data': {}
            }
            
            # Add enrichment based on indicator type
            if base_indicator:
                enrichment['enrichment_data'] = await self._perform_enrichment(base_indicator)
            
            enriched_indicators.append(enrichment)
        
        return {
            'enriched_indicators': enriched_indicators,
            'enrichment_sources': enrichment_sources,
            'total_enriched': len([e for e in enriched_indicators if e['base_intelligence']])
        }
    
    async def _perform_enrichment(self, indicator: ThreatIndicator) -> Dict[str, Any]:
        """Perform enrichment for specific indicator"""
        enrichment = {}
        
        # Add contextual information based on indicator type
        if indicator.indicator_type == 'ip':
            enrichment['geolocation'] = await self._get_ip_geolocation(indicator.value)
            enrichment['reputation'] = await self._get_ip_reputation(indicator.value)
        
        elif indicator.indicator_type == 'domain':
            enrichment['whois'] = await self._get_domain_whois(indicator.value)
            enrichment['dns_records'] = await self._get_dns_records(indicator.value)
        
        elif indicator.indicator_type == 'hash':
            enrichment['file_analysis'] = await self._get_file_analysis(indicator.value)
        
        # Add temporal analysis
        enrichment['temporal_analysis'] = {
            'age_days': (datetime.now(timezone.utc) - indicator.last_seen).days,
            'freshness': 'recent' if (datetime.now(timezone.utc) - indicator.last_seen).days <= 7 else 'old'
        }
        
        return enrichment
    
    async def _get_ip_geolocation(self, ip: str) -> Dict[str, Any]:
        """Get IP geolocation (mock implementation)"""
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'asn': 'Unknown'
        }
    
    async def _get_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Get IP reputation (mock implementation)"""
        return {
            'reputation_score': 0.5,
            'categories': ['unknown']
        }
    
    async def _get_domain_whois(self, domain: str) -> Dict[str, Any]:
        """Get domain WHOIS (mock implementation)"""
        return {
            'registrar': 'Unknown',
            'creation_date': 'Unknown'
        }
    
    async def _get_dns_records(self, domain: str) -> Dict[str, Any]:
        """Get DNS records (mock implementation)"""
        return {
            'a_records': [],
            'mx_records': []
        }
    
    async def _get_file_analysis(self, file_hash: str) -> Dict[str, Any]:
        """Get file analysis (mock implementation)"""
        return {
            'file_type': 'Unknown',
            'malware_family': 'Unknown'
        }
    
    async def _generate_threat_report(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Generate threat intelligence report"""
        indicators = arguments['indicators']
        report_type = arguments.get('report_type', 'summary')
        include_recommendations = arguments.get('include_recommendations', True)
        
        # Correlate all indicators
        correlation_result = await self.correlation_engine.correlate_indicators(indicators)
        
        report = {
            'report_id': f"threat_report_{int(datetime.now().timestamp())}",
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'report_type': report_type,
            'indicators_analyzed': len(indicators),
            'threat_summary': correlation_result['summary']
        }
        
        if report_type == 'summary':
            report['summary'] = {
                'overall_threat_level': correlation_result['summary']['overall_threat_level'],
                'indicators_found': correlation_result['summary']['found_indicators'],
                'max_confidence': correlation_result['summary']['max_confidence']
            }
        
        elif report_type == 'detailed':
            report['detailed_analysis'] = correlation_result['correlations']
            report['threat_breakdown'] = self._analyze_threat_breakdown(correlation_result)
        
        elif report_type == 'ioc_list':
            report['ioc_list'] = [
                {
                    'indicator': ind,
                    'threat_level': corr.get('threat_level', 'unknown'),
                    'confidence': corr.get('indicator', {}).get('confidence', 0.0) if corr.get('found') else 0.0
                }
                for ind, corr in correlation_result['correlations'].items()
            ]
        
        if include_recommendations:
            report['recommendations'] = self._generate_recommendations(correlation_result)
        
        return report
    
    def _assess_risk_level(self, correlation_result: Dict[str, Any]) -> str:
        """Assess overall risk level"""
        summary = correlation_result['summary']
        
        if summary['overall_threat_level'] in ['critical', 'high']:
            return 'high'
        elif summary['overall_threat_level'] == 'medium':
            return 'medium'
        else:
            return 'low'
    
    def _generate_recommendations(self, correlation_result: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        summary = correlation_result['summary']
        
        if summary['found_indicators'] > 0:
            recommendations.append("Block identified malicious indicators in security controls")
            recommendations.append("Monitor for additional related indicators")
            
            if summary['overall_threat_level'] in ['critical', 'high']:
                recommendations.append("Initiate incident response procedures")
                recommendations.append("Conduct forensic analysis of affected systems")
        
        if summary['found_indicators'] == 0:
            recommendations.append("Continue monitoring for emerging threats")
            recommendations.append("Update threat intelligence feeds regularly")
        
        return recommendations
    
    def _analyze_threat_breakdown(self, correlation_result: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze threat breakdown"""
        threat_types = {}
        sources = {}
        
        for correlation in correlation_result['correlations'].values():
            if correlation.get('found'):
                indicator_data = correlation.get('indicator', {})
                
                # Count threat types
                for threat_type in indicator_data.get('threat_types', []):
                    threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
                
                # Count sources
                source = indicator_data.get('source', 'unknown')
                sources[source] = sources.get(source, 0) + 1
        
        return {
            'threat_types': threat_types,
            'sources': sources
        }
    
    async def initialize(self):
        """Initialize the threat intelligence server"""
        await self.database.initialize()
        self.logger.info("Threat Intelligence MCP Server initialized")
    
    async def run(self):
        """Run the MCP server"""
        await self.initialize()
        
        async with ClientSession(StdioServerParameters()) as session:
            await session.initialize()
            
            self.logger.info("Threat Intelligence MCP Server running...")
            
            try:
                while True:
                    await asyncio.sleep(1)
            except KeyboardInterrupt:
                self.logger.info("Shutting down Threat Intelligence MCP Server...")


# Example usage
async def main():
    """Example usage of Threat Intelligence MCP Server"""
    server = ThreatIntelligenceServer()
    await server.run()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())