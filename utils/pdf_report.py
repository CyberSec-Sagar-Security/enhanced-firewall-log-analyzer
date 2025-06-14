#!/usr/bin/env python3
"""
PDF Report Generator for SOC Firewall Log Analyzer
Generates professional PDF reports from JSON alerts using Jinja2 templates
Author: SOC Team
"""

import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import base64
from loguru import logger

# Report generation dependencies
JINJA2_AVAILABLE = False
WEASYPRINT_AVAILABLE = False
PLOTLY_AVAILABLE = False
PANDAS_AVAILABLE = False

try:
    from jinja2 import Environment, FileSystemLoader, Template
    JINJA2_AVAILABLE = True
except ImportError:
    pass

# Test WeasyPrint availability without importing it at module level
WEASYPRINT_AVAILABLE = False

try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.offline import plot
    PLOTLY_AVAILABLE = True
except ImportError:
    pass

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    pass

REPORTING_AVAILABLE = JINJA2_AVAILABLE and WEASYPRINT_AVAILABLE and PLOTLY_AVAILABLE and PANDAS_AVAILABLE


class PDFReportGenerator:
    """Generates professional PDF reports from security alerts"""
    
    def __init__(self, template_dir: Optional[str] = None):
        """
        Initialize PDF report generator
        
        Args:
            template_dir: Directory containing Jinja2 templates
        """
        if not REPORTING_AVAILABLE:
            missing = []
            if not JINJA2_AVAILABLE: missing.append("jinja2")
            if not WEASYPRINT_AVAILABLE: missing.append("weasyprint")
            if not PLOTLY_AVAILABLE: missing.append("plotly")
            if not PANDAS_AVAILABLE: missing.append("pandas")
            raise ImportError(f"PDF reporting dependencies not available: {', '.join(missing)}")
        
        self.template_dir = template_dir or "templates/reports"
        Path(self.template_dir).mkdir(parents=True, exist_ok=True)
        
        # Initialize Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=True
        )
        
        # Add custom filters
        self.jinja_env.filters['datetime'] = self._format_datetime
        self.jinja_env.filters['severity_color'] = self._get_severity_color
        self.jinja_env.filters['truncate'] = self._truncate_text
        
        logger.add("logs/pdf_generator.log", rotation="10 MB")
        logger.info("PDF report generator initialized")
        
        # Create default templates if they don't exist
        self._create_default_templates()
    
    def generate_security_report(self, alerts: List[Dict], output_path: str, 
                               correlations: Optional[List[Dict]] = None,
                               summary_stats: Optional[Dict] = None) -> bool:
        """
        Generate comprehensive security report
        
        Args:
            alerts: List of alert dictionaries
            output_path: Path for output PDF file
            correlations: Optional correlated alerts
            summary_stats: Optional summary statistics
            
        Returns:
            True if successful, False otherwise
        """
        
        try:
            logger.info(f"Generating security report with {len(alerts)} alerts")
            
            # Prepare report data
            report_data = self._prepare_report_data(alerts, correlations, summary_stats)
            
            # Generate charts
            charts = self._generate_charts(report_data)
            
            # Render HTML from template
            html_content = self._render_html_report(report_data, charts)
            
            # Generate PDF
            self._generate_pdf(html_content, output_path)
            
            logger.info(f"Security report generated: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error generating security report: {e}")
            return False
    
    def generate_executive_summary(self, alerts: List[Dict], output_path: str,
                                 time_period: str = "24 hours") -> bool:
        """
        Generate executive summary report
        
        Args:
            alerts: List of alert dictionaries
            output_path: Path for output PDF file
            time_period: Time period for the report
            
        Returns:
            True if successful, False otherwise
        """
        
        try:
            logger.info(f"Generating executive summary for {time_period}")
            
            # Prepare executive data
            exec_data = self._prepare_executive_data(alerts, time_period)
            
            # Generate executive charts
            exec_charts = self._generate_executive_charts(exec_data)
            
            # Render executive template
            html_content = self._render_executive_report(exec_data, exec_charts)
            
            # Generate PDF
            self._generate_pdf(html_content, output_path)
            
            logger.info(f"Executive summary generated: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error generating executive summary: {e}")
            return False
    
    def generate_incident_report(self, incident_data: Dict, output_path: str) -> bool:
        """
        Generate incident-specific report
        
        Args:
            incident_data: Incident data including alerts, timeline, response
            output_path: Path for output PDF file
            
        Returns:
            True if successful, False otherwise
        """
        
        try:
            logger.info(f"Generating incident report: {incident_data.get('incident_id', 'Unknown')}")
            
            # Prepare incident data
            report_data = self._prepare_incident_data(incident_data)
            
            # Generate incident timeline
            timeline_chart = self._generate_incident_timeline(report_data)
            
            # Render incident template
            html_content = self._render_incident_report(report_data, timeline_chart)
            
            # Generate PDF
            self._generate_pdf(html_content, output_path)
            
            logger.info(f"Incident report generated: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error generating incident report: {e}")
            return False
    
    def _prepare_report_data(self, alerts: List[Dict], correlations: Optional[List[Dict]], 
                           summary_stats: Optional[Dict]) -> Dict:
        """Prepare data for security report"""
        
        if not alerts:
            return self._get_empty_report_data()
        
        # Convert to DataFrame for analysis
        df = pd.DataFrame(alerts)
        
        # Ensure timestamp column
        if 'timestamp' in df.columns:
            df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
        else:
            df['datetime'] = pd.to_datetime('now')
        
        # Calculate report metrics
        report_data = {
            'metadata': {
                'generated_at': datetime.now(),
                'report_type': 'Security Analysis Report',
                'time_range': {
                    'start': df['datetime'].min() if len(df) > 0 else datetime.now(),
                    'end': df['datetime'].max() if len(df) > 0 else datetime.now()
                },
                'total_alerts': len(alerts)
            },
            'summary': {
                'total_alerts': len(alerts),
                'unique_ips': df['source_ip'].nunique() if 'source_ip' in df.columns else 0,
                'severity_breakdown': df['severity'].value_counts().to_dict() if 'severity' in df.columns else {},
                'top_attack_types': df['title'].value_counts().head(5).to_dict() if 'title' in df.columns else {},
                'peak_activity_hour': df['datetime'].dt.hour.mode().values[0] if len(df) > 0 else 0
            },
            'alerts': alerts[:50],  # Limit to top 50 for report
            'correlations': correlations or [],
            'statistics': summary_stats or {},
            'recommendations': self._generate_recommendations(df, correlations)
        }
        
        return report_data
    
    def _prepare_executive_data(self, alerts: List[Dict], time_period: str) -> Dict:
        """Prepare data for executive summary"""
        
        if not alerts:
            return self._get_empty_executive_data(time_period)
        
        df = pd.DataFrame(alerts)
        
        if 'timestamp' in df.columns:
            df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
        
        # Executive-level metrics
        exec_data = {
            'metadata': {
                'generated_at': datetime.now(),
                'report_type': 'Executive Security Summary',
                'time_period': time_period,
                'organization': 'SOC Team'
            },
            'key_metrics': {
                'total_incidents': len(alerts),
                'critical_alerts': len(df[df['severity'] == 'Critical']) if 'severity' in df.columns else 0,
                'high_priority': len(df[df['severity'] == 'High']) if 'severity' in df.columns else 0,
                'security_score': self._calculate_security_score(df),
                'trend': self._calculate_trend(df)
            },
            'threat_landscape': {
                'top_threats': df['title'].value_counts().head(3).to_dict() if 'title' in df.columns else {},
                'attack_sources': df['source_ip'].value_counts().head(5).to_dict() if 'source_ip' in df.columns else {},
                'geographic_distribution': {}  # Placeholder for geo analysis
            },
            'business_impact': {
                'risk_level': self._assess_risk_level(df),
                'affected_systems': df['destination_ip'].nunique() if 'destination_ip' in df.columns else 0,
                'estimated_exposure': self._estimate_exposure(df)
            },
            'recommendations': self._generate_executive_recommendations(df)
        }
        
        return exec_data
    
    def _prepare_incident_data(self, incident_data: Dict) -> Dict:
        """Prepare data for incident report"""
        
        return {
            'metadata': {
                'generated_at': datetime.now(),
                'report_type': 'Security Incident Report',
                'incident_id': incident_data.get('incident_id', 'UNKNOWN'),
                'severity': incident_data.get('severity', 'Medium')
            },
            'incident': incident_data,
            'timeline': incident_data.get('timeline', []),
            'affected_systems': incident_data.get('affected_systems', []),
            'response_actions': incident_data.get('response_actions', []),
            'lessons_learned': incident_data.get('lessons_learned', [])
        }
    
    def _generate_charts(self, report_data: Dict) -> Dict:
        """Generate charts for security report"""
        
        charts = {}
        
        try:
            # Severity distribution pie chart
            if report_data['summary']['severity_breakdown']:
                fig_severity = px.pie(
                    values=list(report_data['summary']['severity_breakdown'].values()),
                    names=list(report_data['summary']['severity_breakdown'].keys()),
                    title="Alert Severity Distribution",
                    color_discrete_map={'Critical': '#FF0000', 'High': '#FF6600', 'Medium': '#FFAA00', 'Low': '#00AA00'}
                )
                charts['severity_distribution'] = plot(fig_severity, output_type='div', include_plotlyjs=False)
            
            # Attack types bar chart
            if report_data['summary']['top_attack_types']:
                fig_attacks = px.bar(
                    x=list(report_data['summary']['top_attack_types'].values()),
                    y=list(report_data['summary']['top_attack_types'].keys()),
                    orientation='h',
                    title="Top Attack Types",
                    labels={'x': 'Count', 'y': 'Attack Type'}
                )
                charts['attack_types'] = plot(fig_attacks, output_type='div', include_plotlyjs=False)
            
            # Timeline chart
            if report_data['alerts']:
                df_alerts = pd.DataFrame(report_data['alerts'])
                if 'timestamp' in df_alerts.columns:
                    df_alerts['datetime'] = pd.to_datetime(df_alerts['timestamp'], unit='s')
                    df_alerts['hour'] = df_alerts['datetime'].dt.floor('H')
                    
                    hourly_counts = df_alerts['hour'].value_counts().sort_index()
                    
                    fig_timeline = px.line(
                        x=hourly_counts.index,
                        y=hourly_counts.values,
                        title="Alert Timeline",
                        labels={'x': 'Time', 'y': 'Alert Count'}
                    )
                    charts['timeline'] = plot(fig_timeline, output_type='div', include_plotlyjs=False)
            
        except Exception as e:
            logger.error(f"Error generating charts: {e}")
        
        return charts
    
    def _generate_executive_charts(self, exec_data: Dict) -> Dict:
        """Generate charts for executive summary"""
        
        charts = {}
        
        try:
            # Security score gauge
            score = exec_data['key_metrics']['security_score']
            
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number+delta",
                value=score,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "Security Score"},
                delta={'reference': 80},
                gauge={
                    'axis': {'range': [None, 100]},
                    'bar': {'color': "darkblue"},
                    'steps': [
                        {'range': [0, 50], 'color': "lightgray"},
                        {'range': [50, 80], 'color': "gray"}
                    ],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': 90
                    }
                }
            ))
            
            charts['security_score'] = plot(fig_gauge, output_type='div', include_plotlyjs=False)
            
        except Exception as e:
            logger.error(f"Error generating executive charts: {e}")
        
        return charts
    
    def _generate_incident_timeline(self, incident_data: Dict) -> str:
        """Generate incident timeline chart"""
        
        try:
            timeline = incident_data.get('timeline', [])
            
            if not timeline:
                return ""
            
            df_timeline = pd.DataFrame(timeline)
            
            fig_timeline = px.timeline(
                df_timeline,
                x_start="start_time",
                x_end="end_time",
                y="activity",
                title="Incident Timeline"
            )
            
            return plot(fig_timeline, output_type='div', include_plotlyjs=False)
            
        except Exception as e:
            logger.error(f"Error generating incident timeline: {e}")
            return ""
    
    def _render_html_report(self, report_data: Dict, charts: Dict) -> str:
        """Render HTML report from template"""
        
        try:
            template = self.jinja_env.get_template('security_report.html')
            return template.render(data=report_data, charts=charts)
        
        except Exception as e:
            logger.error(f"Error rendering HTML report: {e}")
            return self._get_fallback_html(report_data)
    
    def _render_executive_report(self, exec_data: Dict, charts: Dict) -> str:
        """Render executive summary HTML"""
        
        try:
            template = self.jinja_env.get_template('executive_summary.html')
            return template.render(data=exec_data, charts=charts)
        
        except Exception as e:
            logger.error(f"Error rendering executive report: {e}")
            return self._get_fallback_executive_html(exec_data)
    
    def _render_incident_report(self, incident_data: Dict, timeline_chart: str) -> str:
        """Render incident report HTML"""        
        try:
            template = self.jinja_env.get_template('incident_report.html')
            return template.render(data=incident_data, timeline_chart=timeline_chart)
        
        except Exception as e:
            logger.error(f"Error rendering incident report: {e}")
            return self._get_fallback_incident_html(incident_data)
    
    def _generate_pdf(self, html_content: str, output_path: str):
        """Generate PDF from HTML content"""
        
        try:
            # Import weasyprint here to avoid module-level import issues
            from weasyprint import HTML, CSS
            
            # Create output directory
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            
            # CSS for styling
            css_content = self._get_report_css()
            
            # Generate PDF
            HTML(string=html_content).write_pdf(
                output_path,
                stylesheets=[CSS(string=css_content)]
            )
            
        except ImportError:
            logger.error("WeasyPrint not available. Cannot generate PDF reports.")
            raise ImportError("WeasyPrint is required for PDF generation. Install with: pip install weasyprint")
        except Exception as e:
            logger.error(f"Error generating PDF: {e}")
            raise
    
    def _create_default_templates(self):
        """Create default Jinja2 templates"""
        
        # Security report template
        security_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Security Analysis Report</title>
    <meta charset="utf-8">
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
</head>
<body>
    <div class="header">
        <h1>🔥 Security Analysis Report</h1>
        <p>Generated on {{ data.metadata.generated_at | datetime }}</p>
    </div>
    
    <div class="executive-summary">
        <h2>Executive Summary</h2>
        <div class="metrics">
            <div class="metric">
                <h3>{{ data.summary.total_alerts }}</h3>
                <p>Total Alerts</p>
            </div>
            <div class="metric">
                <h3>{{ data.summary.unique_ips }}</h3>
                <p>Unique Source IPs</p>
            </div>
        </div>
    </div>
    
    <div class="charts">
        <h2>Security Analytics</h2>
        {% if charts.severity_distribution %}
            {{ charts.severity_distribution | safe }}
        {% endif %}
        
        {% if charts.attack_types %}
            {{ charts.attack_types | safe }}
        {% endif %}
        
        {% if charts.timeline %}
            {{ charts.timeline | safe }}
        {% endif %}
    </div>
    
    <div class="alerts-section">
        <h2>Critical Alerts</h2>
        {% for alert in data.alerts[:10] %}
        <div class="alert-item {{ alert.severity | lower }}">
            <h4>{{ alert.title }}</h4>
            <p><strong>Source IP:</strong> {{ alert.source_ip }}</p>
            <p><strong>Time:</strong> {{ alert.timestamp | datetime }}</p>
            <p><strong>Severity:</strong> {{ alert.severity }}</p>
            <p>{{ alert.description }}</p>
        </div>
        {% endfor %}
    </div>
    
    <div class="recommendations">
        <h2>Security Recommendations</h2>
        {% for rec in data.recommendations %}
        <div class="recommendation">
            <h4>{{ rec.title }}</h4>
            <p>{{ rec.description }}</p>
            <p><strong>Priority:</strong> {{ rec.priority }}</p>
        </div>
        {% endfor %}
    </div>
</body>
</html>
        '''
        
        # Save security report template
        template_path = Path(self.template_dir) / 'security_report.html'
        if not template_path.exists():
            with open(template_path, 'w') as f:
                f.write(security_template)
    
    def _get_report_css(self) -> str:
        """Get CSS styling for reports"""
        
        return '''
        body {
            font-family: Arial, sans-serif;
            margin: 40px;
            line-height: 1.6;
            color: #333;
        }
        
        .header {
            text-align: center;
            border-bottom: 2px solid #ff6b6b;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        
        .header h1 {
            color: #ff6b6b;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .metrics {
            display: flex;
            justify-content: space-around;
            margin: 20px 0;
        }
        
        .metric {
            text-align: center;
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #ff6b6b;
        }
        
        .metric h3 {
            font-size: 2em;
            margin: 0;
            color: #ff6b6b;
        }
        
        .alert-item {
            margin: 15px 0;
            padding: 15px;
            border-left: 4px solid #ccc;
            background: #f8f9fa;
        }
        
        .alert-item.critical {
            border-left-color: #dc3545;
            background: #f8d7da;
        }
        
        .alert-item.high {
            border-left-color: #fd7e14;
            background: #fff3cd;
        }
        
        .alert-item.medium {
            border-left-color: #ffc107;
            background: #fff3cd;
        }
        
        .alert-item.low {
            border-left-color: #28a745;
            background: #d4edda;
        }
        
        .recommendation {
            margin: 15px 0;
            padding: 15px;
            background: #e7f3ff;
            border-left: 4px solid #007bff;
        }
        
        h2 {
            color: #333;
            border-bottom: 1px solid #ccc;
            padding-bottom: 10px;
        }
        
        .charts {
            margin: 30px 0;
        }
        '''
    
    def _format_datetime(self, timestamp) -> str:
        """Format datetime for templates"""
        
        if isinstance(timestamp, (int, float)):
            dt = datetime.fromtimestamp(timestamp)
        elif isinstance(timestamp, str):
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        else:
            dt = timestamp
        
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level"""
        
        colors = {
            'Critical': '#dc3545',
            'High': '#fd7e14',
            'Medium': '#ffc107',
            'Low': '#28a745'
        }
        
        return colors.get(severity, '#6c757d')
    
    def _truncate_text(self, text: str, length: int = 100) -> str:
        """Truncate text to specified length"""
        
        if len(text) <= length:
            return text
        
        return text[:length] + "..."
    
    def _calculate_security_score(self, df: pd.DataFrame) -> int:
        """Calculate overall security score"""
        
        if len(df) == 0:
            return 85  # Default good score
        
        # Base score
        score = 100
        
        # Deduct points for alerts
        critical_count = len(df[df['severity'] == 'Critical']) if 'severity' in df.columns else 0
        high_count = len(df[df['severity'] == 'High']) if 'severity' in df.columns else 0
        
        score -= (critical_count * 15)  # 15 points per critical
        score -= (high_count * 8)      # 8 points per high
        score -= (len(df) * 2)         # 2 points per alert
        
        return max(0, min(100, score))
    
    def _calculate_trend(self, df: pd.DataFrame) -> str:
        """Calculate security trend"""
        
        if len(df) < 2:
            return "Stable"
        
        # Simple trend based on recent vs older alerts
        if 'timestamp' in df.columns:
            df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
            recent_threshold = datetime.now() - timedelta(hours=12)
            
            recent_alerts = len(df[df['datetime'] > recent_threshold])
            older_alerts = len(df[df['datetime'] <= recent_threshold])
            
            if recent_alerts > older_alerts * 1.5:
                return "Increasing"
            elif recent_alerts < older_alerts * 0.5:
                return "Decreasing"
        
        return "Stable"
    
    def _assess_risk_level(self, df: pd.DataFrame) -> str:
        """Assess overall risk level"""
        
        if len(df) == 0:
            return "Low"
        
        critical_count = len(df[df['severity'] == 'Critical']) if 'severity' in df.columns else 0
        high_count = len(df[df['severity'] == 'High']) if 'severity' in df.columns else 0
        
        if critical_count > 5 or high_count > 20:
            return "Critical"
        elif critical_count > 2 or high_count > 10:
            return "High"
        elif high_count > 5:
            return "Medium"
        else:
            return "Low"
    
    def _estimate_exposure(self, df: pd.DataFrame) -> str:
        """Estimate security exposure"""
        
        if len(df) == 0:
            return "Minimal"
        
        unique_ips = df['source_ip'].nunique() if 'source_ip' in df.columns else 0
        
        if unique_ips > 50:
            return "Widespread"
        elif unique_ips > 20:
            return "Significant"
        elif unique_ips > 5:
            return "Moderate"
        else:
            return "Limited"
    
    def _generate_recommendations(self, df: pd.DataFrame, correlations: List[Dict]) -> List[Dict]:
        """Generate security recommendations"""
        
        recommendations = []
        
        if len(df) > 0:
            # High-level recommendations based on data
            if 'severity' in df.columns:
                critical_count = len(df[df['severity'] == 'Critical'])
                if critical_count > 0:
                    recommendations.append({
                        'title': 'Critical Alert Response',
                        'description': f'Address {critical_count} critical alerts immediately',
                        'priority': 'High'
                    })
            
            if 'source_ip' in df.columns:
                top_ips = df['source_ip'].value_counts().head(3)
                if len(top_ips) > 0:
                    recommendations.append({
                        'title': 'Source IP Investigation',
                        'description': f'Investigate top attacking IPs: {", ".join(top_ips.index[:3])}',
                        'priority': 'Medium'
                    })
        
        # Generic recommendations
        recommendations.extend([
            {
                'title': 'Update Security Policies',
                'description': 'Review and update firewall rules based on detected patterns',
                'priority': 'Medium'
            },
            {
                'title': 'Monitor Implementation',
                'description': 'Implement continuous monitoring for detected attack patterns',
                'priority': 'Low'
            }
        ])
        
        return recommendations
    
    def _generate_executive_recommendations(self, df: pd.DataFrame) -> List[Dict]:
        """Generate executive-level recommendations"""
        
        return [
            {
                'title': 'Security Investment',
                'description': 'Consider additional security tools based on threat volume',
                'priority': 'Strategic'
            },
            {
                'title': 'Staff Training',
                'description': 'Enhance security awareness training for staff',
                'priority': 'Operational'
            },
            {
                'title': 'Incident Response',
                'description': 'Review and test incident response procedures',
                'priority': 'Tactical'
            }
        ]
    
    def _get_empty_report_data(self) -> Dict:
        """Get empty report data structure"""
        
        return {
            'metadata': {
                'generated_at': datetime.now(),
                'report_type': 'Security Analysis Report',
                'total_alerts': 0
            },
            'summary': {
                'total_alerts': 0,
                'unique_ips': 0,
                'severity_breakdown': {},
                'top_attack_types': {},
                'peak_activity_hour': 0
            },
            'alerts': [],
            'correlations': [],
            'statistics': {},
            'recommendations': []
        }
    
    def _get_empty_executive_data(self, time_period: str) -> Dict:
        """Get empty executive data structure"""
        
        return {
            'metadata': {
                'generated_at': datetime.now(),
                'report_type': 'Executive Security Summary',
                'time_period': time_period
            },
            'key_metrics': {
                'total_incidents': 0,
                'critical_alerts': 0,
                'high_priority': 0,
                'security_score': 85,
                'trend': 'Stable'
            },
            'threat_landscape': {
                'top_threats': {},
                'attack_sources': {},
                'geographic_distribution': {}
            },
            'business_impact': {
                'risk_level': 'Low',
                'affected_systems': 0,
                'estimated_exposure': 'Minimal'
            },
            'recommendations': []
        }
    
    def _get_fallback_html(self, data: Dict) -> str:
        """Get fallback HTML if template fails"""
        
        return f'''
        <!DOCTYPE html>
        <html>
        <head><title>Security Report</title></head>
        <body>
            <h1>Security Analysis Report</h1>
            <p>Generated: {data['metadata']['generated_at']}</p>
            <h2>Summary</h2>
            <p>Total Alerts: {data['summary']['total_alerts']}</p>
            <p>Unique IPs: {data['summary']['unique_ips']}</p>
        </body>
        </html>
        '''
    
    def _get_fallback_executive_html(self, data: Dict) -> str:
        """Get fallback executive HTML"""
        
        return f'''
        <!DOCTYPE html>
        <html>
        <head><title>Executive Summary</title></head>
        <body>
            <h1>Executive Security Summary</h1>
            <p>Generated: {data['metadata']['generated_at']}</p>
            <h2>Key Metrics</h2>
            <p>Total Incidents: {data['key_metrics']['total_incidents']}</p>
            <p>Security Score: {data['key_metrics']['security_score']}</p>
        </body>
        </html>
        '''
    
    def _get_fallback_incident_html(self, data: Dict) -> str:
        """Get fallback incident HTML"""
        
        return f'''
        <!DOCTYPE html>
        <html>
        <head><title>Incident Report</title></head>
        <body>
            <h1>Security Incident Report</h1>
            <p>Incident ID: {data['metadata']['incident_id']}</p>
            <p>Generated: {data['metadata']['generated_at']}</p>
        </body>
        </html>
        '''


def main():
    """Main function for testing PDF report generation"""
    
    if not REPORTING_AVAILABLE:
        print("❌ PDF reporting dependencies not available")
        print("Install required packages: pip install jinja2 weasyprint plotly")
        return
    
    # Create test data
    test_alerts = [
        {
            'title': 'Suspicious Port Access',
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.5',
            'timestamp': time.time() - 3600,
            'severity': 'High',
            'description': 'Suspicious access to high-risk port detected'
        },
        {
            'title': 'Brute Force Attack',
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.5',
            'timestamp': time.time() - 1800,
            'severity': 'Critical',
            'description': 'Multiple failed authentication attempts detected'
        }
    ]
    
    # Create PDF generator
    generator = PDFReportGenerator()
    
    # Generate security report
    success = generator.generate_security_report(
        alerts=test_alerts,
        output_path="reports/security_report.pdf"
    )
    
    if success:
        print("✅ Security report generated: reports/security_report.pdf")
    else:
        print("❌ Failed to generate security report")
    
    # Generate executive summary
    success = generator.generate_executive_summary(
        alerts=test_alerts,
        output_path="reports/executive_summary.pdf"
    )
    
    if success:
        print("✅ Executive summary generated: reports/executive_summary.pdf")
    else:
        print("❌ Failed to generate executive summary")


if __name__ == "__main__":
    import time
    
    main()
