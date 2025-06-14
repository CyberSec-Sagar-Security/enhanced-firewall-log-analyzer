#!/usr/bin/env python3
"""
Log Writer Utility
Writes alerts and analysis results to JSON files
Author: SOC Team
"""

import json
import os
from datetime import datetime
from typing import Dict, List


class LogWriter:
    """Handles writing alerts and logs to JSON files"""
    
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = log_dir
        self.alert_file = os.path.join(log_dir, "alert_output.json")
        self.analysis_file = os.path.join(log_dir, "analysis_results.json")
        
        # Ensure log directory exists
        os.makedirs(log_dir, exist_ok=True)
        
        # Initialize log files if they don't exist
        self._initialize_log_files()
    
    def _initialize_log_files(self):
        """Initialize JSON log files with proper structure"""
        
        # Initialize alert output file
        if not os.path.exists(self.alert_file):
            initial_data = {
                "metadata": {
                    "created": datetime.now().isoformat(),
                    "version": "1.0",
                    "description": "SOC Firewall Log Analyzer - Security Alerts"
                },
                "alerts": []
            }
            
            with open(self.alert_file, 'w', encoding='utf-8') as f:
                json.dump(initial_data, f, indent=2, ensure_ascii=False)
        
        # Initialize analysis results file
        if not os.path.exists(self.analysis_file):
            initial_data = {
                "metadata": {
                    "created": datetime.now().isoformat(),
                    "version": "1.0",
                    "description": "SOC Firewall Log Analyzer - Analysis Results"
                },
                "analysis_sessions": []
            }
            
            with open(self.analysis_file, 'w', encoding='utf-8') as f:
                json.dump(initial_data, f, indent=2, ensure_ascii=False)
    
    def write_alert(self, alert: Dict):
        """
        Write a single alert to the JSON log file
        
        Args:
            alert: Alert dictionary to write
        """
        
        try:
            # Add metadata to alert
            enhanced_alert = alert.copy()
            enhanced_alert.update({
                'alert_id': self._generate_alert_id(),
                'logged_at': datetime.now().isoformat(),
                'analyzer_version': '1.0'
            })
            
            # Read current alerts
            with open(self.alert_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Add new alert
            data['alerts'].append(enhanced_alert)
            
            # Update metadata
            data['metadata']['last_updated'] = datetime.now().isoformat()
            data['metadata']['total_alerts'] = len(data['alerts'])
            
            # Write back to file
            with open(self.alert_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            print(f"❌ Error writing alert to log: {str(e)}")
    
    def write_analysis_session(self, session_data: Dict):
        """
        Write analysis session results
        
        Args:
            session_data: Analysis session information
        """
        
        try:
            # Enhanced session data
            enhanced_session = {
                'session_id': self._generate_session_id(),
                'start_time': session_data.get('start_time', datetime.now().isoformat()),
                'end_time': datetime.now().isoformat(),
                'log_file': session_data.get('log_file', ''),
                'parser_type': session_data.get('parser_type', ''),
                'total_log_entries': session_data.get('total_log_entries', 0),
                'total_alerts': session_data.get('total_alerts', 0),
                'high_severity_alerts': session_data.get('high_severity_alerts', 0),
                'detector_results': session_data.get('detector_results', {}),
                'analysis_duration': session_data.get('analysis_duration', ''),
                'top_threats': session_data.get('top_threats', [])
            }
            
            # Read current analysis data
            with open(self.analysis_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Add new session
            data['analysis_sessions'].append(enhanced_session)
            
            # Update metadata
            data['metadata']['last_updated'] = datetime.now().isoformat()
            data['metadata']['total_sessions'] = len(data['analysis_sessions'])
            
            # Write back to file
            with open(self.analysis_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            print(f"❌ Error writing analysis session: {str(e)}")
    
    def write_bulk_alerts(self, alerts: List[Dict]):
        """
        Write multiple alerts at once for better performance
        
        Args:
            alerts: List of alert dictionaries
        """
        
        if not alerts:
            return
        
        try:
            # Read current alerts
            with open(self.alert_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Enhance and add all alerts
            for alert in alerts:
                enhanced_alert = alert.copy()
                enhanced_alert.update({
                    'alert_id': self._generate_alert_id(),
                    'logged_at': datetime.now().isoformat(),
                    'analyzer_version': '1.0'
                })
                data['alerts'].append(enhanced_alert)
            
            # Update metadata
            data['metadata']['last_updated'] = datetime.now().isoformat()
            data['metadata']['total_alerts'] = len(data['alerts'])
            
            # Write back to file
            with open(self.alert_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                
            print(f"✅ Wrote {len(alerts)} alerts to {self.alert_file}")
            
        except Exception as e:
            print(f"❌ Error writing bulk alerts: {str(e)}")
    
    def export_alerts_by_severity(self, severity: str = "HIGH") -> List[Dict]:
        """
        Export alerts filtered by severity level
        
        Args:
            severity: Severity level to filter by
            
        Returns:
            List of alerts matching the severity
        """
        
        try:
            with open(self.alert_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            filtered_alerts = [
                alert for alert in data['alerts'] 
                if alert.get('severity', '').upper() == severity.upper()
            ]
            
            return filtered_alerts
            
        except Exception as e:
            print(f"❌ Error exporting alerts by severity: {str(e)}")
            return []
    
    def export_alerts_by_type(self, alert_type: str) -> List[Dict]:
        """
        Export alerts filtered by type
        
        Args:
            alert_type: Alert type to filter by
            
        Returns:
            List of alerts matching the type
        """
        
        try:
            with open(self.alert_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            filtered_alerts = [
                alert for alert in data['alerts'] 
                if alert.get('type', '').upper() == alert_type.upper()
            ]
            
            return filtered_alerts
            
        except Exception as e:
            print(f"❌ Error exporting alerts by type: {str(e)}")
            return []
    
    def export_recent_alerts(self, hours: int = 24) -> List[Dict]:
        """
        Export recent alerts from the last N hours
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            List of recent alerts
        """
        
        try:
            from datetime import timedelta
            
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            with open(self.alert_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            recent_alerts = []
            for alert in data['alerts']:
                try:
                    alert_time = datetime.fromisoformat(alert.get('logged_at', ''))
                    if alert_time >= cutoff_time:
                        recent_alerts.append(alert)
                except (ValueError, TypeError):
                    continue
            
            return recent_alerts
            
        except Exception as e:
            print(f"❌ Error exporting recent alerts: {str(e)}")
            return []
    
    def get_alert_statistics(self) -> Dict:
        """
        Get statistics about all alerts
        
        Returns:
            Dictionary with alert statistics
        """
        
        try:
            with open(self.alert_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            alerts = data.get('alerts', [])
            
            # Count by severity
            severity_counts = {}
            type_counts = {}
            daily_counts = {}
            
            for alert in alerts:
                # Severity stats
                severity = alert.get('severity', 'UNKNOWN')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                # Type stats
                alert_type = alert.get('type', 'UNKNOWN')
                type_counts[alert_type] = type_counts.get(alert_type, 0) + 1
                
                # Daily stats
                try:
                    alert_date = alert.get('timestamp', alert.get('logged_at', ''))[:10]
                    daily_counts[alert_date] = daily_counts.get(alert_date, 0) + 1
                except:
                    pass
            
            return {
                'total_alerts': len(alerts),
                'severity_breakdown': severity_counts,
                'type_breakdown': type_counts,
                'daily_breakdown': daily_counts,
                'most_common_severity': max(severity_counts.items(), key=lambda x: x[1])[0] if severity_counts else None,
                'most_common_type': max(type_counts.items(), key=lambda x: x[1])[0] if type_counts else None
            }
            
        except Exception as e:
            print(f"❌ Error getting alert statistics: {str(e)}")
            return {}
    
    def cleanup_old_alerts(self, days: int = 30):
        """
        Remove alerts older than specified days
        
        Args:
            days: Number of days to keep alerts
        """
        
        try:
            from datetime import timedelta
            
            cutoff_time = datetime.now() - timedelta(days=days)
            
            with open(self.alert_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            original_count = len(data['alerts'])
            
            # Filter alerts
            filtered_alerts = []
            for alert in data['alerts']:
                try:
                    alert_time = datetime.fromisoformat(alert.get('logged_at', ''))
                    if alert_time >= cutoff_time:
                        filtered_alerts.append(alert)
                except (ValueError, TypeError):
                    # Keep alerts with invalid timestamps
                    filtered_alerts.append(alert)
            
            data['alerts'] = filtered_alerts
            data['metadata']['last_cleanup'] = datetime.now().isoformat()
            data['metadata']['total_alerts'] = len(filtered_alerts)
            
            # Write back to file
            with open(self.alert_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            removed_count = original_count - len(filtered_alerts)
            print(f"✅ Cleaned up {removed_count} old alerts (kept {len(filtered_alerts)})")
            
        except Exception as e:
            print(f"❌ Error cleaning up old alerts: {str(e)}")
    
    def create_summary_report(self, output_file: str = None) -> str:
        """
        Create a summary report of all alerts
        
        Args:
            output_file: Optional output file path
            
        Returns:
            Summary report as string
        """
        
        try:
            stats = self.get_alert_statistics()
            
            if not stats:
                return "No alert data available"
            
            report_lines = [
                "🔥 SOC FIREWALL LOG ANALYZER - SECURITY REPORT",
                "=" * 60,
                f"📊 Total Alerts: {stats['total_alerts']}",
                f"📅 Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "",
                "🚨 SEVERITY BREAKDOWN:",
                "-" * 30
            ]
            
            # Severity breakdown
            for severity, count in sorted(stats['severity_breakdown'].items()):
                percentage = (count / stats['total_alerts'] * 100) if stats['total_alerts'] > 0 else 0
                report_lines.append(f"  {severity}: {count} ({percentage:.1f}%)")
            
            report_lines.extend([
                "",
                "🔍 THREAT TYPE BREAKDOWN:",
                "-" * 30
            ])
            
            # Type breakdown
            for alert_type, count in sorted(stats['type_breakdown'].items(), key=lambda x: x[1], reverse=True):
                percentage = (count / stats['total_alerts'] * 100) if stats['total_alerts'] > 0 else 0
                report_lines.append(f"  {alert_type.replace('_', ' ').title()}: {count} ({percentage:.1f}%)")
            
            # Recent activity
            recent_alerts = self.export_recent_alerts(24)
            report_lines.extend([
                "",
                "📈 RECENT ACTIVITY (24 hours):",
                "-" * 30,
                f"  Recent Alerts: {len(recent_alerts)}"
            ])
            
            # Recommendations
            report_lines.extend([
                "",
                "💡 KEY RECOMMENDATIONS:",
                "-" * 30
            ])
            
            if stats['severity_breakdown'].get('CRITICAL', 0) > 0:
                report_lines.append("  🚨 CRITICAL: Immediate action required - investigate critical alerts")
            
            if stats['severity_breakdown'].get('HIGH', 0) > 5:
                report_lines.append("  🔥 HIGH: Multiple high-severity threats detected - review security posture")
            
            if stats['type_breakdown'].get('BRUTE_FORCE', 0) > 0:
                report_lines.append("  🔒 Implement additional authentication controls to prevent brute force")
            
            if stats['type_breakdown'].get('REVERSE_SHELL', 0) > 0:
                report_lines.append("  🐚 Check for malware infection - reverse shells detected")
            
            report_lines.extend([
                "",
                "=" * 60,
                f"📋 Detailed alerts available in: {self.alert_file}",
                "=" * 60
            ])
            
            report = "\n".join(report_lines)
            
            # Write to file if specified
            if output_file:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(report)
                print(f"✅ Summary report saved to: {output_file}")
            
            return report
            
        except Exception as e:
            print(f"❌ Error creating summary report: {str(e)}")
            return f"Error generating report: {str(e)}"
    
    def _generate_alert_id(self) -> str:
        """Generate unique alert ID"""
        
        from uuid import uuid4
        return f"ALERT-{datetime.now().strftime('%Y%m%d')}-{str(uuid4())[:8].upper()}"
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        
        from uuid import uuid4
        return f"SESSION-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{str(uuid4())[:8].upper()}"
