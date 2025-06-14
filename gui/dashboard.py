#!/usr/bin/env python3
"""
Streamlit GUI Dashboard for SOC Firewall Log Analyzer
Interactive web interface for viewing alerts, statistics, and managing analysis
Author: SOC Team
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
import time
from typing import Dict, List, Optional

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import FirewallLogAnalyzer
from utils.live_tailer import LiveLogTailer
import threading


class DashboardApp:
    """Streamlit Dashboard Application"""
    
    def __init__(self):
        self.analyzer = FirewallLogAnalyzer()
        self.live_tailer = None
        self.setup_page_config()
        
    def setup_page_config(self):
        """Configure Streamlit page"""
        st.set_page_config(
            page_title="SOC Firewall Log Analyzer",
            page_icon="🔥",
            layout="wide",
            initial_sidebar_state="expanded"
        )
        
        # Custom CSS
        st.markdown("""
        <style>
        .main-header {
            font-size: 2.5rem;
            color: #FF6B6B;
            text-align: center;
            margin-bottom: 2rem;
        }
        .metric-card {
            background-color: #f0f2f6;
            padding: 1rem;
            border-radius: 0.5rem;
            border-left: 4px solid #FF6B6B;
        }
        .alert-high {
            background-color: #ffebee;
            border-left: 4px solid #f44336;
            padding: 10px;
            margin: 5px 0;
        }
        .alert-medium {
            background-color: #fff3e0;
            border-left: 4px solid #ff9800;
            padding: 10px;
            margin: 5px 0;
        }
        .alert-low {
            background-color: #e8f5e8;
            border-left: 4px solid #4caf50;
            padding: 10px;
            margin: 5px 0;
        }
        </style>
        """, unsafe_allow_html=True)

    def run(self):
        """Main dashboard application"""
        
        # Header
        st.markdown('<h1 class="main-header">🔥 SOC Firewall Log Analyzer Dashboard</h1>', 
                   unsafe_allow_html=True)
        
        # Sidebar
        self.render_sidebar()
        
        # Main content
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "📊 Overview", "🚨 Alerts", "📈 Analytics", "🔴 Live Monitor", "⚙️ Analysis"
        ])
        
        with tab1:
            self.render_overview()
        
        with tab2:
            self.render_alerts()
        
        with tab3:
            self.render_analytics()
        
        with tab4:
            self.render_live_monitor()
        
        with tab5:
            self.render_analysis()

    def render_sidebar(self):
        """Render sidebar with controls"""
        
        st.sidebar.header("🎛️ Controls")
        
        # Status indicators
        st.sidebar.subheader("📡 System Status")
        
        # Check if alert files exist
        alert_file = Path("logs/alert_output.json")
        if alert_file.exists():
            st.sidebar.success("✅ Alert System Active")
        else:
            st.sidebar.warning("⚠️ No alerts detected")
        
        # Check if live monitoring is active
        if hasattr(st.session_state, 'live_monitoring') and st.session_state.live_monitoring:
            st.sidebar.success("🔴 Live Monitoring Active")
        else:
            st.sidebar.info("⭕ Live Monitoring Inactive")
        
        # Quick actions
        st.sidebar.subheader("🚀 Quick Actions")
        
        if st.sidebar.button("🔄 Refresh Data"):
            st.rerun()
        
        if st.sidebar.button("📊 Generate Report"):
            self.generate_dashboard_report()
        
        # Settings
        st.sidebar.subheader("⚙️ Settings")
        
        auto_refresh = st.sidebar.checkbox("Auto Refresh (30s)", value=False)
        if auto_refresh:
            time.sleep(30)
            st.rerun()
        
        # Filter options
        st.sidebar.subheader("🔍 Filters")
        
        severity_filter = st.sidebar.multiselect(
            "Severity Level",
            ["High", "Medium", "Low"],
            default=["High", "Medium", "Low"]
        )
        
        time_filter = st.sidebar.selectbox(
            "Time Range",
            ["Last Hour", "Last 24 Hours", "Last 7 Days", "All Time"],
            index=1
        )
        
        return severity_filter, time_filter

    def render_overview(self):
        """Render overview dashboard"""
        
        st.header("📊 System Overview")
        
        # Load alert data
        alerts = self.load_alerts()
        
        # Key metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            total_alerts = len(alerts)
            st.metric("🚨 Total Alerts", total_alerts, delta=None)
        
        with col2:
            high_severity = len([a for a in alerts if a.get('severity') == 'High'])
            st.metric("🔴 High Severity", high_severity, delta=None)
        
        with col3:
            unique_ips = len(set(a.get('source_ip', '') for a in alerts))
            st.metric("🌐 Unique IPs", unique_ips, delta=None)
        
        with col4:
            latest_alert = max([a.get('timestamp', 0) for a in alerts]) if alerts else 0
            latest_time = datetime.fromtimestamp(latest_alert).strftime("%H:%M:%S") if latest_alert else "N/A"
            st.metric("⏰ Latest Alert", latest_time, delta=None)
        
        # Recent activity timeline
        st.subheader("📅 Recent Activity Timeline")
        
        if alerts:
            # Create timeline chart
            df_alerts = pd.DataFrame(alerts)
            df_alerts['datetime'] = pd.to_datetime(df_alerts['timestamp'], unit='s')
            df_alerts['hour'] = df_alerts['datetime'].dt.floor('H')
            
            hourly_counts = df_alerts.groupby(['hour', 'severity']).size().reset_index(name='count')
            
            fig = px.bar(hourly_counts, x='hour', y='count', color='severity',
                        title="Alerts by Hour and Severity",
                        color_discrete_map={'High': '#FF4444', 'Medium': '#FFA500', 'Low': '#4CAF50'})
            
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No alerts to display")
        
        # System health indicators
        st.subheader("💚 System Health")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Check log file freshness
            log_files = ["logs/analyzer.log", "logs/alert_output.json"]
            for log_file in log_files:
                if Path(log_file).exists():
                    mod_time = Path(log_file).stat().st_mtime
                    age = time.time() - mod_time
                    if age < 3600:  # Less than 1 hour
                        st.success(f"✅ {Path(log_file).name} - Fresh")
                    else:
                        st.warning(f"⚠️ {Path(log_file).name} - {age/3600:.1f}h old")
                else:
                    st.error(f"❌ {Path(log_file).name} - Missing")
        
        with col2:
            # Detection module status
            detectors = ["Suspicious Ports", "Brute Force", "Data Exfiltration", "Reverse Shell"]
            for detector in detectors:
                detector_alerts = [a for a in alerts if detector.lower() in a.get('title', '').lower()]
                if detector_alerts:
                    st.success(f"✅ {detector} - {len(detector_alerts)} alerts")
                else:
                    st.info(f"ℹ️ {detector} - No alerts")

    def render_alerts(self):
        """Render alerts dashboard"""
        
        st.header("🚨 Active Alerts")
        
        # Load alerts
        alerts = self.load_alerts()
        
        if not alerts:
            st.info("No alerts found. Run analysis to generate alerts.")
            return
        
        # Alert summary
        severity_counts = {}
        for alert in alerts:
            severity = alert.get('severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("🔴 High Priority", severity_counts.get('High', 0))
        with col2:
            st.metric("🟡 Medium Priority", severity_counts.get('Medium', 0))
        with col3:
            st.metric("🟢 Low Priority", severity_counts.get('Low', 0))
        
        # Alert filters
        col1, col2 = st.columns(2)
        
        with col1:
            severity_filter = st.selectbox(
                "Filter by Severity",
                ["All", "High", "Medium", "Low"]
            )
        
        with col2:
            search_term = st.text_input("Search alerts", placeholder="IP address, port, etc.")
        
        # Filter alerts
        filtered_alerts = alerts
        
        if severity_filter != "All":
            filtered_alerts = [a for a in filtered_alerts if a.get('severity') == severity_filter]
        
        if search_term:
            filtered_alerts = [a for a in filtered_alerts 
                             if search_term.lower() in str(a).lower()]
        
        # Display alerts
        st.subheader(f"📋 Alert Details ({len(filtered_alerts)} alerts)")
        
        for alert in sorted(filtered_alerts, key=lambda x: x.get('timestamp', 0), reverse=True):
            self.render_alert_card(alert)

    def render_alert_card(self, alert: Dict):
        """Render individual alert card"""
        
        severity = alert.get('severity', 'Low')
        css_class = f"alert-{severity.lower()}"
        
        timestamp = datetime.fromtimestamp(alert.get('timestamp', 0)).strftime("%Y-%m-%d %H:%M:%S")
        
        with st.container():
            st.markdown(f"""
            <div class="{css_class}">
                <h4>🚨 {alert.get('title', 'Unknown Alert')}</h4>
                <p><strong>Severity:</strong> {severity}</p>
                <p><strong>Time:</strong> {timestamp}</p>
                <p><strong>Source IP:</strong> {alert.get('source_ip', 'N/A')}</p>
                <p><strong>Details:</strong> {alert.get('description', 'No description available')}</p>
            </div>
            """, unsafe_allow_html=True)
            
            # Additional details in expander
            with st.expander("View Full Details"):
                st.json(alert)

    def render_analytics(self):
        """Render analytics dashboard"""
        
        st.header("📈 Security Analytics")
        
        alerts = self.load_alerts()
        
        if not alerts:
            st.info("No data available for analytics")
            return
        
        df = pd.DataFrame(alerts)
        df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
        
        # Top source IPs
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🌐 Top Source IPs")
            ip_counts = df['source_ip'].value_counts().head(10)
            fig = px.bar(x=ip_counts.values, y=ip_counts.index, orientation='h',
                        title="Most Active Source IPs")
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("🎯 Attack Types")
            alert_types = df['title'].value_counts()
            fig = px.pie(values=alert_types.values, names=alert_types.index,
                        title="Distribution of Alert Types")
            st.plotly_chart(fig, use_container_width=True)
        
        # Time series analysis
        st.subheader("📊 Alert Trends")
        
        # Group by time intervals
        time_interval = st.selectbox("Time Interval", ["Hour", "Day", "Week"])
        
        if time_interval == "Hour":
            df['period'] = df['datetime'].dt.floor('H')
        elif time_interval == "Day":
            df['period'] = df['datetime'].dt.floor('D')
        else:
            df['period'] = df['datetime'].dt.floor('W')
        
        trend_data = df.groupby(['period', 'severity']).size().reset_index(name='count')
        
        fig = px.line(trend_data, x='period', y='count', color='severity',
                     title=f"Alert Trends by {time_interval}")
        st.plotly_chart(fig, use_container_width=True)
        
        # Geographic analysis (if available)
        st.subheader("🗺️ Geographic Distribution")
        
        # This would require IP geolocation - placeholder for now
        st.info("Geographic analysis requires IP geolocation service (future enhancement)")
        
        # Statistical summary
        st.subheader("📋 Statistical Summary")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("📊 Total Events", len(df))
            st.metric("📅 Date Range", f"{df['datetime'].min().date()} to {df['datetime'].max().date()}")
        
        with col2:
            st.metric("🎯 Unique IPs", df['source_ip'].nunique())
            st.metric("⚡ Avg Alerts/Day", f"{len(df) / max(1, (df['datetime'].max() - df['datetime'].min()).days):.1f}")
        
        with col3:
            st.metric("🔴 High Severity %", f"{(df['severity'] == 'High').sum() / len(df) * 100:.1f}%")
            st.metric("🕐 Peak Hour", df['datetime'].dt.hour.mode().values[0] if len(df) > 0 else "N/A")

    def render_live_monitor(self):
        """Render live monitoring dashboard"""
        
        st.header("🔴 Live Monitoring")
        
        # Live monitoring controls
        col1, col2 = st.columns(2)
        
        with col1:
            log_file = st.text_input("Log File Path", placeholder="Enter path to log file to monitor")
            parser_type = st.selectbox("Parser Type", ["windows", "pfsense"])
        
        with col2:
            check_interval = st.number_input("Check Interval (seconds)", min_value=0.5, max_value=60.0, value=1.0)
            
            # Start/Stop buttons
            col_start, col_stop = st.columns(2)
            
            with col_start:
                if st.button("▶️ Start Monitoring"):
                    if log_file and Path(log_file).exists():
                        self.start_live_monitoring(log_file, parser_type, check_interval)
                    else:
                        st.error("Please provide a valid log file path")
            
            with col_stop:
                if st.button("⏹️ Stop Monitoring"):
                    self.stop_live_monitoring()
        
        # Live monitoring status
        if hasattr(st.session_state, 'live_monitoring') and st.session_state.live_monitoring:
            st.success("🟢 Live monitoring is active")
            
            # Display live statistics
            if hasattr(st.session_state, 'live_tailer') and st.session_state.live_tailer:
                stats = st.session_state.live_tailer.get_statistics()
                
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric("⏱️ Runtime", stats['runtime_formatted'])
                
                with col2:
                    st.metric("📄 Lines Processed", stats['lines_processed'])
                
                with col3:
                    st.metric("🚨 Alerts Generated", stats['alerts_generated'])
                
                with col4:
                    st.metric("📊 Processing Rate", f"{stats['lines_per_second']:.1f}/sec")
                
                # Auto-refresh for live data
                if st.checkbox("Auto-refresh live data"):
                    time.sleep(5)
                    st.rerun()
        else:
            st.info("Live monitoring is not active. Configure and start monitoring above.")
        
        # Recent live alerts
        st.subheader("🔔 Recent Live Alerts")
        
        live_alerts = [alert for alert in self.load_alerts() if alert.get('live_detected', False)]
        
        if live_alerts:
            # Show last 10 live alerts
            for alert in sorted(live_alerts, key=lambda x: x.get('timestamp', 0), reverse=True)[:10]:
                self.render_alert_card(alert)
        else:
            st.info("No live alerts detected yet")

    def render_analysis(self):
        """Render manual analysis interface"""
        
        st.header("⚙️ Manual Analysis")
        
        # File upload
        st.subheader("📁 Upload Log Files")
        
        uploaded_files = st.file_uploader(
            "Choose log files",
            accept_multiple_files=True,
            type=['csv', 'log', 'txt']
        )
        
        if uploaded_files:
            for uploaded_file in uploaded_files:
                st.write(f"📄 {uploaded_file.name} ({uploaded_file.size} bytes)")
        
        # Analysis options
        col1, col2 = st.columns(2)
        
        with col1:
            parser_type = st.selectbox("Parser Type", ["windows", "pfsense"], key="analysis_parser")
            
            detectors = st.multiselect(
                "Select Detectors",
                ["Suspicious Ports", "Brute Force", "Data Exfiltration", "Reverse Shell"],
                default=["Suspicious Ports", "Brute Force", "Data Exfiltration", "Reverse Shell"]
            )
        
        with col2:
            output_format = st.selectbox("Output Format", ["JSON", "Excel", "Both"])
            
            enable_notifications = st.checkbox("Enable Notifications", value=True)
        
        # Run analysis
        if st.button("🚀 Run Analysis"):
            if uploaded_files:
                self.run_manual_analysis(uploaded_files, parser_type, detectors, output_format, enable_notifications)
            else:
                st.error("Please upload log files first")
        
        # Batch processing
        st.subheader("📦 Batch Processing")
        
        batch_directory = st.text_input("Batch Directory", placeholder="Enter directory path with log files")
        
        if st.button("📁 Process Directory") and batch_directory:
            if Path(batch_directory).exists():
                self.run_batch_analysis(batch_directory, parser_type, detectors, output_format)
            else:
                st.error("Directory does not exist")

    def load_alerts(self) -> List[Dict]:
        """Load alerts from JSON file"""
        
        alert_file = Path("logs/alert_output.json")
        alerts = []
        
        if alert_file.exists():
            try:
                with open(alert_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            alert = json.loads(line)
                            alerts.append(alert)
            except Exception as e:
                st.error(f"Error loading alerts: {e}")
        
        return alerts

    def start_live_monitoring(self, log_file: str, parser_type: str, check_interval: float):
        """Start live monitoring"""
        
        try:
            self.live_tailer = LiveLogTailer(log_file, parser_type, check_interval=check_interval)
            
            if self.live_tailer.start_monitoring():
                st.session_state.live_monitoring = True
                st.session_state.live_tailer = self.live_tailer
                st.success("✅ Live monitoring started successfully!")
            else:
                st.error("❌ Failed to start live monitoring")
                
        except Exception as e:
            st.error(f"Error starting live monitoring: {e}")

    def stop_live_monitoring(self):
        """Stop live monitoring"""
        
        if hasattr(st.session_state, 'live_tailer') and st.session_state.live_tailer:
            st.session_state.live_tailer.stop_monitoring()
            st.session_state.live_monitoring = False
            st.success("✅ Live monitoring stopped")

    def run_manual_analysis(self, uploaded_files, parser_type: str, detectors: List[str], 
                          output_format: str, enable_notifications: bool):
        """Run manual analysis on uploaded files"""
        
        with st.spinner("Running analysis..."):
            try:
                # Save uploaded files temporarily
                temp_files = []
                for uploaded_file in uploaded_files:
                    temp_path = Path(f"temp_{uploaded_file.name}")
                    with open(temp_path, "wb") as f:
                        f.write(uploaded_file.getbuffer())
                    temp_files.append(str(temp_path))
                
                # Run analysis
                results = self.analyzer.analyze_logs(temp_files, parser_type, output_format)
                
                # Clean up temp files
                for temp_file in temp_files:
                    Path(temp_file).unlink(missing_ok=True)
                
                st.success(f"✅ Analysis completed! Generated {results.get('alert_count', 0)} alerts")
                
                # Show results
                if results.get('alerts'):
                    st.subheader("Analysis Results")
                    for alert in results['alerts'][:5]:  # Show first 5 alerts
                        self.render_alert_card(alert)
                
            except Exception as e:
                st.error(f"Analysis failed: {e}")

    def run_batch_analysis(self, directory: str, parser_type: str, detectors: List[str], output_format: str):
        """Run batch analysis on directory"""
        
        with st.spinner("Processing directory..."):
            try:
                log_files = list(Path(directory).glob("*.csv")) + list(Path(directory).glob("*.log"))
                
                if not log_files:
                    st.warning("No log files found in directory")
                    return
                
                st.info(f"Found {len(log_files)} log files")
                
                # Process each file
                total_alerts = 0
                for log_file in log_files:
                    results = self.analyzer.analyze_logs([str(log_file)], parser_type, output_format)
                    total_alerts += results.get('alert_count', 0)
                
                st.success(f"✅ Batch processing completed! Generated {total_alerts} total alerts")
                
            except Exception as e:
                st.error(f"Batch processing failed: {e}")

    def generate_dashboard_report(self):
        """Generate comprehensive dashboard report"""
        
        with st.spinner("Generating report..."):
            try:
                alerts = self.load_alerts()
                
                report = {
                    'timestamp': datetime.now().isoformat(),
                    'total_alerts': len(alerts),
                    'severity_breakdown': {},
                    'top_source_ips': {},
                    'alert_types': {},
                    'time_range': None
                }
                
                if alerts:
                    df = pd.DataFrame(alerts)
                    
                    # Severity breakdown
                    report['severity_breakdown'] = df['severity'].value_counts().to_dict()
                    
                    # Top IPs
                    report['top_source_ips'] = df['source_ip'].value_counts().head(10).to_dict()
                    
                    # Alert types
                    report['alert_types'] = df['title'].value_counts().to_dict()
                    
                    # Time range
                    if 'timestamp' in df.columns:
                        df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
                        report['time_range'] = {
                            'start': df['datetime'].min().isoformat(),
                            'end': df['datetime'].max().isoformat()
                        }
                
                # Save report
                report_path = Path("reports/dashboard_report.json")
                report_path.parent.mkdir(exist_ok=True)
                
                with open(report_path, 'w') as f:
                    json.dump(report, f, indent=2)
                
                st.success(f"✅ Report generated: {report_path}")
                
                # Show download button
                with open(report_path, 'r') as f:
                    st.download_button(
                        label="📥 Download Report",
                        data=f.read(),
                        file_name="dashboard_report.json",
                        mime="application/json"
                    )
                
            except Exception as e:
                st.error(f"Report generation failed: {e}")


def main():
    """Main function to run the dashboard"""
    
    # Initialize session state
    if 'live_monitoring' not in st.session_state:
        st.session_state.live_monitoring = False
    
    # Create and run dashboard
    dashboard = DashboardApp()
    dashboard.run()


if __name__ == "__main__":
    main()
