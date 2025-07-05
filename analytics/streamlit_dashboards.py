"""
Streamlit-in-Snowflake Dashboard Implementations

Interactive security analytics dashboards with real-time data visualization,
AI-powered insights, and executive reporting capabilities.
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import asyncio
import time

# Import our analytics components
from .snowflake_integration import SnowflakeSecurityAnalytics, SnowflakeConfig


class DashboardConfig:
    """Configuration for Streamlit dashboards"""
    
    def __init__(self):
        self.page_config = {
            "page_title": "CyberCortex Security Analytics",
            "page_icon": "🛡️",
            "layout": "wide",
            "initial_sidebar_state": "expanded"
        }
        
        self.theme_colors = {
            "primary": "#0ea5e9",
            "secondary": "#64748b",
            "success": "#10b981",
            "warning": "#f59e0b",
            "danger": "#ef4444",
            "info": "#3b82f6"
        }
        
        self.chart_colors = {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#d97706",
            "low": "#65a30d",
            "info": "#2563eb"
        }


class ExecutiveDashboard:
    """Executive security dashboard with high-level metrics and insights"""
    
    def __init__(self, analytics: SnowflakeSecurityAnalytics):
        self.analytics = analytics
        self.config = DashboardConfig()
    
    def render(self):
        """Render the executive dashboard"""
        st.set_page_config(**self.config.page_config)
        
        # Custom CSS for styling
        st.markdown("""
        <style>
        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 1rem;
            border-radius: 10px;
            color: white;
            margin: 0.5rem 0;
        }
        
        .alert-critical {
            background-color: #fee2e2;
            border-left: 4px solid #dc2626;
            padding: 1rem;
            margin: 0.5rem 0;
        }
        
        .alert-warning {
            background-color: #fef3c7;
            border-left: 4px solid #f59e0b;
            padding: 1rem;
            margin: 0.5rem 0;
        }
        
        .alert-success {
            background-color: #dcfce7;
            border-left: 4px solid #10b981;
            padding: 1rem;
            margin: 0.5rem 0;
        }
        
        .sidebar .sidebar-content {
            background: linear-gradient(180deg, #667eea 0%, #764ba2 100%);
        }
        </style>
        """, unsafe_allow_html=True)
        
        # Header
        st.title("🛡️ CyberCortex Executive Security Dashboard")
        st.markdown("**Real-time security posture and strategic insights**")
        
        # Sidebar controls
        self._render_sidebar()
        
        # Main dashboard content
        self._render_key_metrics()
        self._render_security_overview()
        self._render_threat_landscape()
        self._render_compliance_status()
        self._render_risk_assessment()
        self._render_strategic_insights()
    
    def _render_sidebar(self):
        """Render sidebar controls"""
        st.sidebar.header("🎛️ Dashboard Controls")
        
        # Time range selector
        time_range = st.sidebar.selectbox(
            "📅 Time Range",
            ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "Last 90 Days"],
            index=2
        )
        
        # Auto-refresh toggle
        auto_refresh = st.sidebar.checkbox("🔄 Auto Refresh (30s)", value=False)
        
        if auto_refresh:
            time.sleep(30)
            st.rerun()
        
        # Manual refresh button
        if st.sidebar.button("🔄 Refresh Now"):
            st.rerun()
        
        # Dashboard settings
        st.sidebar.header("⚙️ Settings")
        
        show_details = st.sidebar.checkbox("📊 Show Detailed Analytics", value=True)
        show_ai_insights = st.sidebar.checkbox("🤖 Show AI Insights", value=True)
        
        # Export options
        st.sidebar.header("📤 Export")
        
        if st.sidebar.button("📄 Generate PDF Report"):
            st.sidebar.success("PDF report generation initiated!")
        
        if st.sidebar.button("📊 Export to Excel"):
            st.sidebar.success("Excel export initiated!")
        
        # System status
        st.sidebar.header("🔧 System Status")
        st.sidebar.success("🟢 All Systems Operational")
        st.sidebar.info("🔵 6 Agents Active")
        st.sidebar.info("📡 Real-time Monitoring")
        
        return time_range, show_details, show_ai_insights
    
    def _render_key_metrics(self):
        """Render key security metrics"""
        st.header("📊 Key Security Metrics")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown("""
            <div class="metric-card">
                <h3>Security Score</h3>
                <h1>87/100</h1>
                <p>↗️ +5 from last week</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class="metric-card">
                <h3>Active Threats</h3>
                <h1>3</h1>
                <p>↘️ -2 from yesterday</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown("""
            <div class="metric-card">
                <h3>Compliance Score</h3>
                <h1>94%</h1>
                <p>↗️ +2% this month</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col4:
            st.markdown("""
            <div class="metric-card">
                <h3>Risk Level</h3>
                <h1>Medium</h1>
                <p>→ Stable</p>
            </div>
            """, unsafe_allow_html=True)
    
    def _render_security_overview(self):
        """Render security overview section"""
        st.header("🔍 Security Overview")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Security Posture Trend")
            
            # Generate sample trend data
            dates = pd.date_range(start='2024-01-01', end='2024-01-30', freq='D')
            scores = np.random.normal(85, 5, len(dates))
            scores = np.clip(scores, 70, 100)  # Keep scores realistic
            
            fig = px.line(
                x=dates,
                y=scores,
                title="30-Day Security Score Trend",
                labels={'x': 'Date', 'y': 'Security Score'}
            )
            
            fig.update_traces(line_color=self.config.theme_colors["primary"])
            fig.update_layout(
                showlegend=False,
                height=400,
                margin=dict(l=0, r=0, t=30, b=0)
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("Threat Detection Rate")
            
            # Sample threat detection data
            threat_types = ['Malware', 'Phishing', 'DDoS', 'Insider Threat', 'APT']
            detection_rates = [95, 87, 92, 78, 85]
            
            fig = go.Figure(data=go.Bar(
                x=threat_types,
                y=detection_rates,
                marker_color=[
                    self.config.chart_colors["critical"] if rate < 80 else
                    self.config.chart_colors["warning"] if rate < 90 else
                    self.config.chart_colors["success"]
                    for rate in detection_rates
                ]
            ))
            
            fig.update_layout(
                title="Threat Detection Effectiveness",
                yaxis_title="Detection Rate (%)",
                height=400,
                margin=dict(l=0, r=0, t=30, b=0)
            )
            
            st.plotly_chart(fig, use_container_width=True)
    
    def _render_threat_landscape(self):
        """Render threat landscape analysis"""
        st.header("🎯 Threat Landscape")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.subheader("Threat Distribution")
            
            threat_data = {
                'Threat Type': ['Malware', 'Phishing', 'DDoS', 'Insider', 'APT'],
                'Count': [45, 32, 18, 12, 8],
                'Severity': ['High', 'Medium', 'Low', 'Medium', 'Critical']
            }
            
            df = pd.DataFrame(threat_data)
            
            fig = px.pie(
                df,
                values='Count',
                names='Threat Type',
                title="Threat Type Distribution",
                color_discrete_sequence=px.colors.qualitative.Set3
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("Geographic Threat Sources")
            
            # Sample geographic data
            countries = ['Unknown', 'China', 'Russia', 'USA', 'North Korea']
            threat_counts = [45, 23, 18, 12, 8]
            
            fig = px.bar(
                x=countries,
                y=threat_counts,
                title="Threats by Source Country",
                color=threat_counts,
                color_continuous_scale='Reds'
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        with col3:
            st.subheader("Attack Vector Analysis")
            
            vectors = ['Email', 'Web', 'Network', 'Physical', 'Social']
            percentages = [40, 25, 20, 10, 5]
            
            fig = go.Figure(data=go.Bar(
                x=vectors,
                y=percentages,
                marker_color=self.config.theme_colors["primary"]
            ))
            
            fig.update_layout(
                title="Primary Attack Vectors",
                yaxis_title="Percentage (%)",
                height=300
            )
            
            st.plotly_chart(fig, use_container_width=True)
    
    def _render_compliance_status(self):
        """Render compliance status overview"""
        st.header("📋 Compliance Status")
        
        # Compliance framework data
        frameworks = {
            'SOC 2': {'score': 94, 'status': 'Compliant', 'last_audit': '2024-01-15'},
            'ISO 27001': {'score': 87, 'status': 'Partial', 'last_audit': '2024-01-10'},
            'NIST CSF': {'score': 91, 'status': 'Compliant', 'last_audit': '2024-01-12'},
            'GDPR': {'score': 78, 'status': 'Non-Compliant', 'last_audit': '2024-01-08'}
        }
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Framework Compliance Scores")
            
            framework_names = list(frameworks.keys())
            scores = [frameworks[f]['score'] for f in framework_names]
            
            fig = go.Figure(data=go.Bar(
                x=framework_names,
                y=scores,
                marker_color=[
                    self.config.chart_colors["success"] if score >= 90 else
                    self.config.chart_colors["warning"] if score >= 75 else
                    self.config.chart_colors["danger"]
                    for score in scores
                ],
                text=scores,
                textposition='auto'
            ))
            
            fig.update_layout(
                title="Compliance Framework Scores",
                yaxis_title="Score (%)",
                height=400
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("Compliance Details")
            
            for framework, details in frameworks.items():
                status_color = (
                    "success" if details['status'] == 'Compliant' else
                    "warning" if details['status'] == 'Partial' else
                    "critical"
                )
                
                st.markdown(f"""
                <div class="alert-{status_color}">
                    <strong>{framework}</strong><br>
                    Score: {details['score']}%<br>
                    Status: {details['status']}<br>
                    Last Audit: {details['last_audit']}
                </div>
                """, unsafe_allow_html=True)
    
    def _render_risk_assessment(self):
        """Render risk assessment section"""
        st.header("⚠️ Risk Assessment")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Risk Score Breakdown")
            
            risk_components = {
                'Threat Risk': 6.5,
                'Vulnerability Risk': 7.2,
                'Compliance Risk': 4.8,
                'Operational Risk': 5.5
            }
            
            fig = go.Figure(data=go.Bar(
                x=list(risk_components.keys()),
                y=list(risk_components.values()),
                marker_color=[
                    self.config.chart_colors["danger"] if score >= 7 else
                    self.config.chart_colors["warning"] if score >= 5 else
                    self.config.chart_colors["success"]
                    for score in risk_components.values()
                ]
            ))
            
            fig.update_layout(
                title="Risk Component Scores (0-10 scale)",
                yaxis_title="Risk Score",
                height=400
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("Risk Trend Analysis")
            
            # Generate risk trend data
            dates = pd.date_range(start='2024-01-01', end='2024-01-30', freq='D')
            risk_scores = np.random.normal(6.0, 1.0, len(dates))
            risk_scores = np.clip(risk_scores, 3, 9)
            
            fig = px.line(
                x=dates,
                y=risk_scores,
                title="30-Day Risk Score Trend"
            )
            
            # Add risk level zones
            fig.add_hline(y=7, line_dash="dash", line_color="red", annotation_text="High Risk")
            fig.add_hline(y=4, line_dash="dash", line_color="orange", annotation_text="Medium Risk")
            
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
    
    def _render_strategic_insights(self):
        """Render AI-powered strategic insights"""
        st.header("🤖 AI-Powered Strategic Insights")
        
        # Sample AI insights
        insights = [
            {
                "type": "critical",
                "title": "Vulnerability Management Gap",
                "description": "Critical vulnerabilities in web applications have increased 40% this month. Immediate patching required for CVE-2024-0001.",
                "recommendation": "Deploy emergency patches and implement automated vulnerability scanning."
            },
            {
                "type": "warning",
                "title": "Compliance Drift Detected",
                "description": "GDPR compliance score has decreased due to data retention policy violations.",
                "recommendation": "Review and update data retention policies, implement automated compliance monitoring."
            },
            {
                "type": "success",
                "title": "Threat Detection Improvement",
                "description": "AI-powered threat detection has improved by 15% with new machine learning models.",
                "recommendation": "Continue model training and expand to additional threat vectors."
            }
        ]
        
        for insight in insights:
            alert_class = f"alert-{insight['type']}"
            
            st.markdown(f"""
            <div class="{alert_class}">
                <h4>{insight['title']}</h4>
                <p><strong>Analysis:</strong> {insight['description']}</p>
                <p><strong>Recommendation:</strong> {insight['recommendation']}</p>
            </div>
            """, unsafe_allow_html=True)
        
        # Action items
        st.subheader("📋 Recommended Actions")
        
        actions = [
            {"priority": "High", "action": "Patch critical vulnerabilities", "due": "2024-01-20"},
            {"priority": "Medium", "action": "Update GDPR compliance policies", "due": "2024-01-25"},
            {"priority": "Low", "action": "Review threat detection rules", "due": "2024-01-30"}
        ]
        
        action_df = pd.DataFrame(actions)
        st.dataframe(action_df, use_container_width=True)


class TechnicalDashboard:
    """Technical security analytics dashboard for security analysts"""
    
    def __init__(self, analytics: SnowflakeSecurityAnalytics):
        self.analytics = analytics
        self.config = DashboardConfig()
    
    def render(self):
        """Render the technical dashboard"""
        st.set_page_config(
            page_title="CyberCortex Technical Analytics",
            page_icon="🔬",
            layout="wide"
        )
        
        st.title("🔬 CyberCortex Technical Security Analytics")
        st.markdown("**Deep-dive security analysis and forensics**")
        
        # Sidebar for technical controls
        self._render_technical_sidebar()
        
        # Main content tabs
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "🌐 Network Analysis",
            "👤 Behavioral Analytics", 
            "🎯 Threat Hunting",
            "🔍 Forensic Analysis",
            "📊 Custom Analytics"
        ])
        
        with tab1:
            self._render_network_analysis()
        
        with tab2:
            self._render_behavioral_analytics()
        
        with tab3:
            self._render_threat_hunting()
        
        with tab4:
            self._render_forensic_analysis()
        
        with tab5:
            self._render_custom_analytics()
    
    def _render_technical_sidebar(self):
        """Render technical dashboard sidebar"""
        st.sidebar.header("🔧 Technical Controls")
        
        # Data source selection
        data_sources = st.sidebar.multiselect(
            "📡 Data Sources",
            ["Network Logs", "System Logs", "Application Logs", "Security Events"],
            default=["Security Events"]
        )
        
        # Time granularity
        granularity = st.sidebar.selectbox(
            "⏱️ Time Granularity",
            ["1 minute", "5 minutes", "1 hour", "1 day"],
            index=2
        )
        
        # Analysis depth
        analysis_depth = st.sidebar.slider(
            "🔍 Analysis Depth",
            min_value=1,
            max_value=5,
            value=3,
            help="Higher values provide more detailed analysis"
        )
        
        # Real-time monitoring
        real_time = st.sidebar.checkbox("🔴 Real-time Monitoring", value=False)
        
        if real_time:
            st.sidebar.warning("⚠️ Real-time mode enabled - high resource usage")
        
        return data_sources, granularity, analysis_depth, real_time
    
    def _render_network_analysis(self):
        """Render network security analysis"""
        st.header("🌐 Network Security Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Network Traffic Patterns")
            
            # Generate sample network data
            hours = list(range(24))
            traffic_volume = np.random.poisson(1000, 24)
            
            fig = px.line(
                x=hours,
                y=traffic_volume,
                title="24-Hour Traffic Volume",
                labels={'x': 'Hour of Day', 'y': 'Packets/Hour'}
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
            # Top talkers table
            st.subheader("Top Network Talkers")
            
            talkers_data = {
                'Source IP': ['192.168.1.100', '10.0.0.50', '172.16.1.25', '192.168.1.200'],
                'Destination': ['8.8.8.8', '1.1.1.1', '208.67.222.222', '4.4.4.4'],
                'Bytes': [1024000, 512000, 256000, 128000],
                'Packets': [1500, 800, 400, 200],
                'Risk Score': [7.5, 3.2, 2.1, 1.8]
            }
            
            talkers_df = pd.DataFrame(talkers_data)
            
            # Color code by risk score
            def color_risk(val):
                if val >= 7:
                    return 'background-color: #fee2e2'
                elif val >= 5:
                    return 'background-color: #fef3c7'
                else:
                    return 'background-color: #dcfce7'
            
            styled_df = talkers_df.style.applymap(color_risk, subset=['Risk Score'])
            st.dataframe(styled_df, use_container_width=True)
        
        with col2:
            st.subheader("Protocol Distribution")
            
            protocols = ['HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP', 'SMTP']
            percentages = [35, 45, 15, 3, 1, 1]
            
            fig = px.pie(
                values=percentages,
                names=protocols,
                title="Network Protocol Usage"
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
            # Anomaly detection results
            st.subheader("Network Anomalies")
            
            anomalies = [
                {"Time": "14:30", "Type": "Port Scan", "Source": "192.168.1.100", "Severity": "High"},
                {"Time": "15:45", "Type": "DDoS", "Source": "External", "Severity": "Critical"},
                {"Time": "16:20", "Type": "Data Exfiltration", "Source": "10.0.0.50", "Severity": "Medium"}
            ]
            
            for anomaly in anomalies:
                severity_color = (
                    "🔴" if anomaly["Severity"] == "Critical" else
                    "🟠" if anomaly["Severity"] == "High" else
                    "🟡"
                )
                
                st.write(f"{severity_color} **{anomaly['Time']}** - {anomaly['Type']} from {anomaly['Source']}")
    
    def _render_behavioral_analytics(self):
        """Render user behavior analytics"""
        st.header("👤 User Behavior Analytics")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("User Risk Scores")
            
            users = ['john.doe', 'jane.smith', 'admin', 'service_account', 'contractor1']
            risk_scores = [2.1, 7.5, 3.2, 1.8, 8.9]
            
            fig = go.Figure(data=go.Bar(
                x=users,
                y=risk_scores,
                marker_color=[
                    self.config.chart_colors["danger"] if score >= 7 else
                    self.config.chart_colors["warning"] if score >= 5 else
                    self.config.chart_colors["success"]
                    for score in risk_scores
                ]
            ))
            
            fig.update_layout(
                title="User Risk Assessment",
                yaxis_title="Risk Score (0-10)",
                xaxis_tickangle=-45
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("Behavioral Anomalies")
            
            anomaly_data = {
                'User': ['jane.smith', 'contractor1', 'admin'],
                'Anomaly': ['Unusual Login Time', 'Excessive Data Access', 'Privilege Escalation'],
                'Risk Score': [7.5, 8.9, 6.2],
                'Status': ['Investigating', 'Blocked', 'Monitoring'],
                'First Seen': ['2024-01-15 02:30', '2024-01-15 14:20', '2024-01-15 16:45']
            }
            
            anomaly_df = pd.DataFrame(anomaly_data)
            st.dataframe(anomaly_df, use_container_width=True)
            
            # User activity timeline
            st.subheader("User Activity Timeline")
            
            timeline_data = {
                'Time': ['08:00', '10:30', '12:00', '14:30', '16:00', '18:00'],
                'Normal Activity': [45, 67, 89, 78, 56, 23],
                'Anomalous Activity': [2, 1, 3, 8, 12, 5]
            }
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=timeline_data['Time'],
                y=timeline_data['Normal Activity'],
                mode='lines+markers',
                name='Normal Activity',
                line=dict(color=self.config.chart_colors["success"])
            ))
            
            fig.add_trace(go.Scatter(
                x=timeline_data['Time'],
                y=timeline_data['Anomalous Activity'],
                mode='lines+markers',
                name='Anomalous Activity',
                line=dict(color=self.config.chart_colors["danger"])
            ))
            
            fig.update_layout(title="Daily Activity Pattern")
            st.plotly_chart(fig, use_container_width=True)
    
    def _render_threat_hunting(self):
        """Render threat hunting interface"""
        st.header("🎯 Threat Hunting Console")
        
        # Query builder
        st.subheader("🔍 Threat Hunt Query Builder")
        
        col1, col2 = st.columns(2)
        
        with col1:
            event_type = st.selectbox(
                "Event Type",
                ["All", "Authentication", "Network", "File Access", "Process Execution"]
            )
            
            severity = st.multiselect(
                "Severity",
                ["Critical", "High", "Medium", "Low"],
                default=["Critical", "High"]
            )
        
        with col2:
            time_window = st.selectbox(
                "Time Window",
                ["Last Hour", "Last 24 Hours", "Last 7 Days", "Custom Range"]
            )
            
            source_filter = st.text_input("Source Filter (regex)", placeholder="192\\.168\\..*")
        
        # Custom SQL query
        st.subheader("📝 Custom SQL Query")
        
        default_query = """
SELECT 
    event_id,
    timestamp,
    event_type,
    severity,
    source,
    target,
    description
FROM security_events 
WHERE severity IN ('critical', 'high')
    AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '24 HOURS'
ORDER BY timestamp DESC
LIMIT 100
"""
        
        query = st.text_area(
            "Enter your threat hunting query:",
            value=default_query,
            height=200
        )
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("🚀 Execute Hunt", type="primary"):
                with st.spinner("Executing threat hunt..."):
                    time.sleep(2)  # Simulate query execution
                    st.success("Hunt completed successfully!")
                    
                    # Mock results
                    hunt_results = {
                        'Event ID': ['evt_001', 'evt_002', 'evt_003', 'evt_004'],
                        'Timestamp': ['2024-01-15 10:30:00', '2024-01-15 11:45:00', '2024-01-15 12:15:00', '2024-01-15 13:20:00'],
                        'Event Type': ['Authentication', 'Network', 'File Access', 'Process'],
                        'Severity': ['Critical', 'High', 'High', 'Medium'],
                        'Source': ['192.168.1.100', '10.0.0.50', '172.16.1.25', '192.168.1.200'],
                        'Description': [
                            'Failed login attempts from suspicious IP',
                            'Unusual network traffic pattern detected',
                            'Unauthorized file access attempt',
                            'Suspicious process execution'
                        ]
                    }
                    
                    results_df = pd.DataFrame(hunt_results)
                    st.dataframe(results_df, use_container_width=True)
        
        with col2:
            if st.button("💾 Save Hunt"):
                st.success("Hunt query saved!")
        
        with col3:
            if st.button("📊 Visualize Results"):
                st.info("Visualization feature coming soon!")
        
        # Saved hunts
        st.subheader("📚 Saved Threat Hunts")
        
        saved_hunts = [
            {"Name": "Lateral Movement Detection", "Last Run": "2024-01-15 09:30", "Results": 12},
            {"Name": "Data Exfiltration Hunt", "Last Run": "2024-01-14 16:45", "Results": 3},
            {"Name": "Privilege Escalation", "Last Run": "2024-01-14 14:20", "Results": 7}
        ]
        
        for hunt in saved_hunts:
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.write(f"**{hunt['Name']}**")
            with col2:
                st.write(hunt['Last Run'])
            with col3:
                st.write(f"{hunt['Results']} results")
            with col4:
                if st.button(f"Run", key=f"run_{hunt['Name']}"):
                    st.info(f"Running {hunt['Name']}...")
    
    def _render_forensic_analysis(self):
        """Render forensic analysis interface"""
        st.header("🔍 Digital Forensic Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📅 Incident Timeline")
            
            # Timeline visualization
            timeline_events = [
                {"Time": "10:00", "Event": "Initial Access", "Severity": 8, "Actor": "External"},
                {"Time": "10:15", "Event": "Privilege Escalation", "Severity": 9, "Actor": "Attacker"},
                {"Time": "10:30", "Event": "Lateral Movement", "Severity": 7, "Actor": "Attacker"},
                {"Time": "10:45", "Event": "Data Discovery", "Severity": 6, "Actor": "Attacker"},
                {"Time": "11:00", "Event": "Data Exfiltration", "Severity": 10, "Actor": "Attacker"},
                {"Time": "11:15", "Event": "Cleanup", "Severity": 5, "Actor": "Attacker"}
            ]
            
            times = [event["Time"] for event in timeline_events]
            severities = [event["Severity"] for event in timeline_events]
            events = [event["Event"] for event in timeline_events]
            
            fig = go.Figure()
            
            fig.add_trace(go.Scatter(
                x=times,
                y=severities,
                mode='lines+markers+text',
                text=events,
                textposition="top center",
                marker=dict(
                    size=10,
                    color=severities,
                    colorscale='Reds',
                    showscale=True,
                    colorbar=dict(title="Severity")
                ),
                line=dict(width=3)
            ))
            
            fig.update_layout(
                title="Attack Timeline Analysis",
                xaxis_title="Time",
                yaxis_title="Severity (1-10)",
                height=400
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("🗂️ Evidence Collection")
            
            evidence_items = [
                {"Type": "Memory Dump", "Size": "2.1 GB", "Status": "Collected", "Hash": "a1b2c3d4..."},
                {"Type": "Network Logs", "Size": "450 MB", "Status": "Analyzing", "Hash": "e5f6g7h8..."},
                {"Type": "File System", "Size": "1.8 GB", "Status": "Collected", "Hash": "i9j0k1l2..."},
                {"Type": "Registry", "Size": "125 MB", "Status": "Pending", "Hash": "m3n4o5p6..."},
                {"Type": "Event Logs", "Size": "89 MB", "Status": "Collected", "Hash": "q7r8s9t0..."}
            ]
            
            evidence_df = pd.DataFrame(evidence_items)
            
            # Color code by status
            def color_status(val):
                if val == "Collected":
                    return 'background-color: #dcfce7'
                elif val == "Analyzing":
                    return 'background-color: #fef3c7'
                else:
                    return 'background-color: #fee2e2'
            
            styled_evidence = evidence_df.style.applymap(color_status, subset=['Status'])
            st.dataframe(styled_evidence, use_container_width=True)
            
            # Chain of custody
            st.subheader("🔗 Chain of Custody")
            
            custody_events = [
                {"Time": "09:30", "Action": "Evidence Identified", "Officer": "J. Smith"},
                {"Time": "09:45", "Action": "Collection Started", "Officer": "J. Smith"},
                {"Time": "10:30", "Action": "Transfer to Lab", "Officer": "M. Johnson"},
                {"Time": "11:00", "Action": "Analysis Started", "Officer": "A. Wilson"}
            ]
            
            for event in custody_events:
                st.write(f"**{event['Time']}** - {event['Action']} by {event['Officer']}")
        
        # Artifact analysis
        st.subheader("🔬 Artifact Analysis")
        
        tab1, tab2, tab3 = st.tabs(["File Analysis", "Network Analysis", "Memory Analysis"])
        
        with tab1:
            st.write("**Suspicious Files Detected:**")
            
            files_data = {
                'Filename': ['malware.exe', 'backdoor.dll', 'keylogger.sys'],
                'Path': ['C:\\temp\\', 'C:\\windows\\system32\\', 'C:\\windows\\drivers\\'],
                'Size': ['2.1 MB', '450 KB', '89 KB'],
                'Hash': ['a1b2c3d4e5f6...', 'g7h8i9j0k1l2...', 'm3n4o5p6q7r8...'],
                'Threat Score': [9.5, 8.7, 7.2]
            }
            
            st.dataframe(pd.DataFrame(files_data), use_container_width=True)
        
        with tab2:
            st.write("**Network Connections:**")
            
            connections_data = {
                'Source': ['192.168.1.100', '192.168.1.100', '10.0.0.50'],
                'Destination': ['185.220.101.42', '198.51.100.25', '203.0.113.15'],
                'Port': [443, 80, 22],
                'Protocol': ['HTTPS', 'HTTP', 'SSH'],
                'Status': ['Suspicious', 'Malicious', 'Monitoring']
            }
            
            st.dataframe(pd.DataFrame(connections_data), use_container_width=True)
        
        with tab3:
            st.write("**Memory Artifacts:**")
            
            memory_data = {
                'Process': ['explorer.exe', 'svchost.exe', 'unknown.exe'],
                'PID': [1234, 5678, 9012],
                'Memory Usage': ['45 MB', '23 MB', '12 MB'],
                'Suspicious': ['No', 'No', 'Yes'],
                'Analysis': ['Clean', 'Clean', 'Malware']
            }
            
            st.dataframe(pd.DataFrame(memory_data), use_container_width=True)
    
    def _render_custom_analytics(self):
        """Render custom analytics builder"""
        st.header("📊 Custom Analytics Builder")
        
        st.subheader("🛠️ Build Custom Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Data source selection
            data_source = st.selectbox(
                "Select Data Source",
                ["Security Events", "Network Logs", "System Logs", "User Activity"]
            )
            
            # Metric selection
            metric = st.selectbox(
                "Select Metric",
                ["Count", "Average", "Sum", "Min", "Max", "Distinct Count"]
            )
            
            # Grouping
            group_by = st.multiselect(
                "Group By",
                ["Event Type", "Severity", "Source", "Target", "Time (Hour)", "Time (Day)"]
            )
        
        with col2:
            # Filters
            st.write("**Filters:**")
            
            severity_filter = st.multiselect(
                "Severity",
                ["Critical", "High", "Medium", "Low"],
                default=["Critical", "High"]
            )
            
            time_filter = st.selectbox(
                "Time Range",
                ["Last Hour", "Last 24 Hours", "Last 7 Days", "Last 30 Days"]
            )
            
            custom_filter = st.text_input(
                "Custom Filter (SQL WHERE clause)",
                placeholder="source LIKE '192.168.%'"
            )
        
        # Visualization type
        viz_type = st.selectbox(
            "Visualization Type",
            ["Bar Chart", "Line Chart", "Pie Chart", "Heatmap", "Scatter Plot", "Table"]
        )
        
        if st.button("🚀 Generate Analysis", type="primary"):
            with st.spinner("Generating custom analysis..."):
                time.sleep(2)  # Simulate analysis
                
                st.success("Custom analysis generated!")
                
                # Generate sample visualization based on selection
                if viz_type == "Bar Chart":
                    sample_data = {
                        'Category': ['Malware', 'Phishing', 'DDoS', 'Insider'],
                        'Count': [45, 32, 18, 12]
                    }
                    
                    fig = px.bar(
                        x=sample_data['Category'],
                        y=sample_data['Count'],
                        title=f"Custom Analysis: {metric} by {', '.join(group_by) if group_by else 'Category'}"
                    )
                    
                    st.plotly_chart(fig, use_container_width=True)
                
                elif viz_type == "Line Chart":
                    dates = pd.date_range(start='2024-01-01', end='2024-01-30', freq='D')
                    values = np.random.poisson(20, len(dates))
                    
                    fig = px.line(
                        x=dates,
                        y=values,
                        title=f"Custom Analysis: {metric} over Time"
                    )
                    
                    st.plotly_chart(fig, use_container_width=True)
                
                elif viz_type == "Table":
                    sample_table = {
                        'Event Type': ['Authentication', 'Network', 'File Access'],
                        'Count': [156, 89, 234],
                        'Average Severity': [6.5, 7.2, 5.8]
                    }
                    
                    st.dataframe(pd.DataFrame(sample_table), use_container_width=True)
        
        # Save analysis
        if st.button("💾 Save Analysis"):
            analysis_name = st.text_input("Analysis Name", placeholder="My Custom Analysis")
            if analysis_name:
                st.success(f"Analysis '{analysis_name}' saved to dashboard!")


def main():
    """Main function to run Streamlit dashboards"""
    
    # Initialize analytics (in production, this would use real Snowflake config)
    config = SnowflakeConfig(
        account="demo_account",
        user="demo_user", 
        password="demo_password",
        database="CYBERCORTEX_DB",
        schema="SECURITY_ANALYTICS",
        warehouse="COMPUTE_WH",
        role="CYBERCORTEX_ROLE"
    )
    
    # Create analytics instance (mock for demo)
    analytics = None  # In production: SnowflakeSecurityAnalytics(config)
    
    # Dashboard selection
    dashboard_type = st.sidebar.selectbox(
        "Select Dashboard",
        ["Executive Dashboard", "Technical Dashboard"]
    )
    
    if dashboard_type == "Executive Dashboard":
        dashboard = ExecutiveDashboard(analytics)
        dashboard.render()
    else:
        dashboard = TechnicalDashboard(analytics)
        dashboard.render()


if __name__ == "__main__":
    main()