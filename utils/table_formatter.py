"""
Table Formatter for SOC Firewall Log Analyzer
Provides concise table output for alerts
"""

from typing import List, Dict, Any
from colorama import Fore, Style, init
import os

# Initialize colorama for Windows
init()


class AlertTableFormatter:
    """Formats alerts into concise table output"""
    
    def __init__(self):
        """Initialize table formatter"""
        self.severity_colors = {
            'Critical': Fore.RED + Style.BRIGHT,
            'High': Fore.YELLOW + Style.BRIGHT,
            'Medium': Fore.CYAN + Style.BRIGHT,
            'Low': Fore.GREEN + Style.BRIGHT
        }
    
    def format_alerts_table(self, alerts: List[Dict[str, Any]]) -> str:
        """
        Format alerts into a concise table
        
        Args:
            alerts: List of alert dictionaries
            
        Returns:
            Formatted table string
        """
        if not alerts:
            return f"{Fore.YELLOW}No alerts detected{Style.RESET_ALL}"
        
        # Sort alerts by severity and timestamp
        sorted_alerts = sorted(alerts, key=lambda x: (
            self._get_severity_priority(x.get('severity', 'Low')),
            x.get('timestamp', '')
        ))
        
        # Build table
        table_lines = []
        
        # Header
        table_lines.append(self._create_header())
        table_lines.append(self._create_separator())
        
        # Data rows
        for i, alert in enumerate(sorted_alerts[:50]):  # Limit to top 50 alerts
            table_lines.append(self._format_alert_row(alert, i + 1))
        
        # Footer
        if len(alerts) > 50:
            table_lines.append(self._create_separator())
            table_lines.append(f"{Fore.YELLOW}... and {len(alerts) - 50} more alerts (see Excel export for full list){Style.RESET_ALL}")
        
        return '\n'.join(table_lines)
    
    def format_summary_stats(self, alerts: List[Dict[str, Any]]) -> str:
        """
        Format summary statistics
        
        Args:
            alerts: List of alert dictionaries
            
        Returns:
            Formatted summary string
        """
        if not alerts:
            return ""
        
        # Calculate statistics
        total_alerts = len(alerts)
        severity_counts = {}
        threat_counts = {}
        
        for alert in alerts:
            severity = alert.get('severity', 'Low')
            threat_type = alert.get('threat_type', 'Unknown')
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
        
        # Build summary
        summary_lines = []
        summary_lines.append(f"\n{Fore.CYAN + Style.BRIGHT}═══ THREAT DETECTION SUMMARY ═══{Style.RESET_ALL}")
        summary_lines.append(f"📊 Total Alerts: {Fore.WHITE + Style.BRIGHT}{total_alerts}{Style.RESET_ALL}")
        
        # Severity breakdown
        summary_lines.append(f"\n🚨 By Severity:")
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                color = self.severity_colors.get(severity, Fore.WHITE)
                summary_lines.append(f"   {color}{severity}: {count}{Style.RESET_ALL}")
        
        # Threat type breakdown
        summary_lines.append(f"\n🎯 By Threat Type:")
        for threat_type, count in sorted(threat_counts.items(), key=lambda x: x[1], reverse=True):
            summary_lines.append(f"   {Fore.WHITE}{threat_type}: {Fore.YELLOW}{count}{Style.RESET_ALL}")
        
        return '\n'.join(summary_lines)
    
    def _create_header(self) -> str:
        """Create table header"""
        header = f"{Fore.CYAN + Style.BRIGHT}"
        header += f"{'#':<3} {'Severity':<8} {'Threat Type':<15} {'Source IP':<15} {'Dest IP':<15} {'Port':<6} {'Description':<30}"
        header += f"{Style.RESET_ALL}"
        return header
    
    def _create_separator(self) -> str:
        """Create table separator line"""
        return f"{Fore.CYAN}{'─' * 95}{Style.RESET_ALL}"
    
    def _format_alert_row(self, alert: Dict[str, Any], row_num: int) -> str:
        """
        Format a single alert row
        
        Args:
            alert: Alert dictionary
            row_num: Row number
            
        Returns:
            Formatted row string
        """
        severity = alert.get('severity', 'Low')
        threat_type = alert.get('threat_type', 'Unknown')
        source_ip = alert.get('source_ip', 'N/A')
        dest_ip = alert.get('destination_ip', 'N/A')
        port = str(alert.get('port', 'N/A'))
        description = alert.get('description', 'No description')
        
        # Truncate long fields
        threat_type = self._truncate(threat_type, 15)
        source_ip = self._truncate(source_ip, 15)
        dest_ip = self._truncate(dest_ip, 15)
        port = self._truncate(port, 6)
        description = self._truncate(description, 30)
        
        # Color based on severity
        severity_color = self.severity_colors.get(severity, Fore.WHITE)
        
        row = f"{Fore.WHITE}{row_num:<3} "
        row += f"{severity_color}{severity:<8}{Style.RESET_ALL} "
        row += f"{Fore.WHITE}{threat_type:<15} "
        row += f"{source_ip:<15} "
        row += f"{dest_ip:<15} "
        row += f"{port:<6} "
        row += f"{description:<30}{Style.RESET_ALL}"
        
        return row
    
    def _truncate(self, text: str, max_length: int) -> str:
        """
        Truncate text to fit column width
        
        Args:
            text: Text to truncate
            max_length: Maximum length
            
        Returns:
            Truncated text
        """
        if len(text) <= max_length:
            return text
        return text[:max_length-3] + "..."
    
    def _get_severity_priority(self, severity: str) -> int:
        """
        Get numeric priority for severity sorting
        
        Args:
            severity: Severity level
            
        Returns:
            Priority number (lower = higher priority)
        """
        priorities = {
            'Critical': 1,
            'High': 2,
            'Medium': 3,
            'Low': 4
        }
        return priorities.get(severity, 5)
    
    def print_alerts_table(self, alerts: List[Dict[str, Any]]):
        """
        Print alerts table to console
        
        Args:
            alerts: List of alert dictionaries
        """
        print(self.format_summary_stats(alerts))
        print(f"\n{self.format_alerts_table(alerts)}")
        
        if alerts:
            print(f"\n{Fore.GREEN}💾 Detailed logs saved to: logs/alert_output.json{Style.RESET_ALL}")
            print(f"{Fore.GREEN}📊 Excel export available in: logs/{Style.RESET_ALL}")


def format_alerts_as_table(alerts: List[Dict[str, Any]]) -> str:
    """
    Convenience function to format alerts as table
    
    Args:
        alerts: List of alert dictionaries
        
    Returns:
        Formatted table string
    """
    formatter = AlertTableFormatter()
    return formatter.format_alerts_table(alerts)


def print_alerts_summary(alerts: List[Dict[str, Any]]):
    """
    Convenience function to print alerts summary and table
    
    Args:
        alerts: List of alert dictionaries
    """
    formatter = AlertTableFormatter()
    formatter.print_alerts_table(alerts)
