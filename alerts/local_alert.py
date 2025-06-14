#!/usr/bin/env python3
"""
Local Alert System
Handles color-coded terminal output and Windows toast notifications
Author: SOC Team
"""

import sys
from typing import Dict
from colorama import init, Fore, Back, Style
from win10toast import ToastNotifier


class LocalAlert:
    """Local alert system with toast notifications and colored terminal output"""
    
    def __init__(self):
        # Initialize colorama for Windows
        init(autoreset=True)
        
        # Initialize toast notifier
        self.toaster = ToastNotifier()
        
        # Quiet mode flag (disables toast notifications)
        self.quiet_mode = False
        
        # Alert type colors
        self.colors = {
            'CRITICAL': Fore.WHITE + Back.RED,
            'HIGH': Fore.RED + Style.BRIGHT,
            'MEDIUM': Fore.YELLOW + Style.BRIGHT,
            'LOW': Fore.CYAN,
            'INFO': Fore.BLUE,
            'SUCCESS': Fore.GREEN + Style.BRIGHT,
            'WARNING': Fore.YELLOW,
            'ERROR': Fore.RED + Style.BRIGHT
        }
        
        # Alert type symbols
        self.symbols = {
            'CRITICAL': '🚨',
            'HIGH': '🔥',
            'MEDIUM': '⚠️ ',
            'LOW': 'ℹ️ ',
            'INFO': '💡',
            'SUCCESS': '✅',
            'WARNING': '⚠️ ',
            'ERROR': '❌'
        }
        
        print(f"{self.colors['SUCCESS']}🔥 SOC Alert System Initialized{Style.RESET_ALL}")
    
    def show_alert(self, alert: Dict):
        """
        Display alert with color coding and toast notification
        
        Args:
            alert: Alert dictionary containing alert information
        """
        
        severity = alert.get('severity', 'INFO').upper()
        alert_type = alert.get('type', 'UNKNOWN')
        title = alert.get('title', 'Security Alert')
        description = alert.get('description', 'No description available')
        timestamp = alert.get('timestamp', '')
        
        # Color-coded terminal output
        color = self.colors.get(severity, Fore.WHITE)
        symbol = self.symbols.get(severity, '🔔')
        
        print(f"\n{color}{symbol} [{severity}] {title}{Style.RESET_ALL}")
        print(f"{color}{'─' * 60}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Description: {description}{Style.RESET_ALL}")
        
        if timestamp:
            print(f"{Fore.CYAN}Timestamp: {timestamp}{Style.RESET_ALL}")
        
        # Additional alert details
        self._print_alert_details(alert)
        
        print(f"{color}{'─' * 60}{Style.RESET_ALL}")
        
        # Toast notification (if not in quiet mode)
        if not self.quiet_mode:
            self._show_toast_notification(severity, title, description)
    
    def _print_alert_details(self, alert: Dict):
        """Print detailed alert information"""
        
        # Source/Destination information
        if alert.get('source_ip'):
            print(f"{Fore.MAGENTA}Source IP: {alert['source_ip']}{Style.RESET_ALL}")
        
        if alert.get('destination_ip'):
            print(f"{Fore.MAGENTA}Destination IP: {alert['destination_ip']}{Style.RESET_ALL}")
        
        if alert.get('destination_port'):
            port_info = f"{alert['destination_port']}"
            if alert.get('port_description'):
                port_info += f" ({alert['port_description']})"
            print(f"{Fore.MAGENTA}Port: {port_info}{Style.RESET_ALL}")
        
        # Connection/Pattern information
        if alert.get('connection_count'):
            print(f"{Fore.YELLOW}Connections: {alert['connection_count']}{Style.RESET_ALL}")
        
        if alert.get('failed_attempts'):
            print(f"{Fore.RED}Failed Attempts: {alert['failed_attempts']}{Style.RESET_ALL}")
        
        if alert.get('unique_destinations'):
            print(f"{Fore.CYAN}Unique Destinations: {alert['unique_destinations']}{Style.RESET_ALL}")
        
        # Risk indicators
        if alert.get('risk_indicators'):
            print(f"{Fore.RED}Risk Indicators:{Style.RESET_ALL}")
            for indicator in alert['risk_indicators'][:3]:  # Show top 3
                print(f"  • {indicator}")
        
        # Recommendations
        if alert.get('recommendation'):
             recommendation = alert['recommendation'][:200] + "..." if len(alert['recommendation']) > 200 else alert['recommendation']
             print(f"{Fore.GREEN}Recommendation: {recommendation}{Style.RESET_ALL}")
        
        # Pattern/Service specific info
        if alert.get('service'):
            print(f"{Fore.CYAN}Service: {alert['service']}{Style.RESET_ALL}")
        
        if alert.get('pattern_type'):
            print(f"{Fore.YELLOW}Pattern: {alert['pattern_type']}{Style.RESET_ALL}")
        
        # Attack duration/timing
        if alert.get('attack_duration'):
            print(f"{Fore.YELLOW}Duration: {alert['attack_duration']}{Style.RESET_ALL}")
        
        if alert.get('time_window_minutes'):
            print(f"{Fore.YELLOW}Time Window: {alert['time_window_minutes']} minutes{Style.RESET_ALL}")
    
    def _show_toast_notification(self, severity: str, title: str, description: str):
        """Show Windows toast notification"""
        
        try:
            # Truncate description for toast
            toast_description = description[:100] + "..." if len(description) > 100 else description
            
            # Icon path (you can customize this)
            icon_path = None  # Default Windows notification icon
            
            # Duration based on severity
            duration = 10 if severity in ['CRITICAL', 'HIGH'] else 5
            
            # Show toast
            self.toaster.show_toast(
                title=f"[{severity}] {title}",
                msg=toast_description,
                icon_path=icon_path,
                duration=duration,
                threaded=True  # Non-blocking
            )
            
        except Exception as e:
            print(f"{Fore.YELLOW}⚠️  Toast notification failed: {str(e)}{Style.RESET_ALL}")
    
    def show_info(self, message: str):
        """Show info message"""
        
        symbol = self.symbols['INFO']
        color = self.colors['INFO']
        print(f"{color}{symbol} {message}{Style.RESET_ALL}")
    
    def show_success(self, message: str):
        """Show success message"""
        
        symbol = self.symbols['SUCCESS']
        color = self.colors['SUCCESS']
        print(f"{color}{symbol} {message}{Style.RESET_ALL}")
    
    def show_warning(self, message: str):
        """Show warning message"""
        
        symbol = self.symbols['WARNING']
        color = self.colors['WARNING']
        print(f"{color}{symbol} {message}{Style.RESET_ALL}")
        
        if not self.quiet_mode:
            try:
                self.toaster.show_toast(
                    title="Warning",
                    msg=message,
                    duration=3,
                    threaded=True
                )
            except:
                pass
    
    def show_error(self, message: str):
        """Show error message"""
        
        symbol = self.symbols['ERROR']
        color = self.colors['ERROR']
        print(f"{color}{symbol} {message}{Style.RESET_ALL}")
        
        if not self.quiet_mode:
            try:
                self.toaster.show_toast(
                    title="Error",
                    msg=message,
                    duration=5,
                    threaded=True
                )
            except:
                pass
    
    def show_summary(self, total_alerts: int, high_severity_alerts: int):
        """Show analysis summary"""
        
        print(f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📊 ANALYSIS SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
        
        if total_alerts == 0:
            print(f"{self.colors['SUCCESS']}✅ No security alerts detected{Style.RESET_ALL}")
        else:
            # Color-code based on severity
            if high_severity_alerts > 0:
                summary_color = self.colors['HIGH']
                summary_symbol = self.symbols['HIGH']
            elif total_alerts > 10:
                summary_color = self.colors['MEDIUM']
                summary_symbol = self.symbols['MEDIUM']
            else:
                summary_color = self.colors['LOW']
                summary_symbol = self.symbols['LOW']
            
            print(f"{summary_color}{summary_symbol} Total Alerts: {total_alerts}{Style.RESET_ALL}")
            print(f"{self.colors['HIGH']}🔥 High Severity: {high_severity_alerts}{Style.RESET_ALL}")
            print(f"{self.colors['MEDIUM']}⚠️  Medium/Low Severity: {total_alerts - high_severity_alerts}{Style.RESET_ALL}")
            
            # Show toast for summary if significant alerts
            if not self.quiet_mode and total_alerts > 0:
                try:
                    self.toaster.show_toast(
                        title="Firewall Analysis Complete",
                        msg=f"Found {total_alerts} security alerts ({high_severity_alerts} high severity)",
                        duration=5,
                        threaded=True
                    )
                except:
                    pass
        
        print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
    
    def show_progress(self, message: str):
        """Show progress message"""
        
        print(f"{Fore.BLUE}⏳ {message}...{Style.RESET_ALL}")
    
    def show_banner(self):
        """Show application banner"""
        
        banner = f"""
{Fore.CYAN}{'=' * 70}
{Fore.YELLOW}🔥 SOC FIREWALL LOG ANALYZER - THREAT DETECTION SYSTEM 🔥
{Fore.CYAN}{'=' * 70}
{Fore.GREEN}🎯 Detecting: Brute Force | Port Scans | C2 | Reverse Shells | Exfiltration
{Fore.GREEN}📊 Output: Color-coded alerts + JSON logs + Toast notifications
{Fore.GREEN}🔒 100% Offline | No Cloud Dependencies | SOC-Ready Analysis
{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}
        """
        
        print(banner)
    
    def print_detection_stats(self, detector_name: str, alert_count: int):
        """Print detector statistics"""
        
        if alert_count > 0:
            color = self.colors['WARNING'] if alert_count > 5 else self.colors['INFO']
            print(f"{color}🔍 {detector_name}: {alert_count} alerts{Style.RESET_ALL}")
        else:
            print(f"{self.colors['SUCCESS']}✅ {detector_name}: Clean{Style.RESET_ALL}")
    
    def show_file_processing(self, filename: str, entries_count: int):
        """Show file processing information"""
        
        print(f"{self.colors['INFO']}📁 Processing: {filename}{Style.RESET_ALL}")
        print(f"{self.colors['INFO']}📊 Log Entries: {entries_count:,}{Style.RESET_ALL}")
    
    def show_parser_info(self, parser_type: str):
        """Show parser information"""
        
        parser_descriptions = {
            'pfsense': '🛡️  pfSense Firewall Parser',
            'windows': '🪟 Windows Defender Firewall Parser',
            'iptables': '🐧 Linux iptables Parser'
        }
        
        description = parser_descriptions.get(parser_type, f'📊 {parser_type.title()} Parser')
        print(f"{self.colors['INFO']}{description}{Style.RESET_ALL}")
    
    def show_critical_alert_header(self):
        """Show critical alert header"""
        
        print(f"\n{Back.RED + Fore.WHITE}{'!' * 60}")
        print(f"🚨 CRITICAL SECURITY ALERTS DETECTED 🚨")
        print(f"{'!' * 60}{Style.RESET_ALL}\n")
    
    def show_detection_complete(self, detector_name: str):
        """Show detector completion"""
        
        print(f"{self.colors['SUCCESS']}✓ {detector_name} analysis complete{Style.RESET_ALL}")
    
    def format_ip_info(self, ip: str, ip_type: str = "") -> str:
        """Format IP address with color coding"""
        
        if self._is_internal_ip(ip):
            return f"{Fore.GREEN}{ip} (Internal){Style.RESET_ALL}"
        else:
            return f"{Fore.RED}{ip} (External){Style.RESET_ALL}"
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is internal/private"""
        
        if not ip:
            return False
            
        private_ranges = ['10.', '172.16.', '172.17.', '172.18.', '172.19.',
                         '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                         '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                         '172.30.', '172.31.', '192.168.', '127.', '169.254.']
        
        return any(ip.startswith(prefix) for prefix in private_ranges)
