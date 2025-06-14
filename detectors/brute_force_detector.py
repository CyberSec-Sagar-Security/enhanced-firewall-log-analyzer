#!/usr/bin/env python3
"""
Brute Force Detector
Detects brute force attacks based on repeated failed connection attempts
Author: SOC Team
"""

from typing import List, Dict
from collections import defaultdict
from datetime import datetime, timedelta


class BruteForceDetector:
    """Detector for brute force attack patterns"""
    
    def __init__(self):
        # Brute force detection thresholds
        self.failed_attempts_threshold = 5      # Failed attempts in time window
        self.time_window_minutes = 5            # Time window for counting attempts
        self.high_severity_threshold = 15       # High severity threshold
        self.critical_threshold = 50            # Critical threshold
        
        # Commonly targeted services for brute force
        self.brute_force_ports = {
            21: "FTP",
            22: "SSH", 
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            1433: "SQL Server",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC"
        }
    
    def detect(self, log_entries: List[Dict]) -> List[Dict]:
        """
        Detect brute force patterns in firewall logs
        
        Args:
            log_entries: List of normalized log entries
            
        Returns:
            List of alert dictionaries
        """
        
        alerts = []
        
        # Group entries by source IP for analysis
        ip_activity = defaultdict(list)
        
        for entry in log_entries:
            src_ip = entry.get('src_ip', '')
            if src_ip:
                ip_activity[src_ip].append(entry)
        
        # Analyze each source IP for brute force patterns
        for src_ip, entries in ip_activity.items():
            # Sort entries by timestamp
            entries.sort(key=lambda x: x.get('timestamp', ''))
            
            # Detect failed connection patterns
            brute_force_alerts = self._detect_failed_connections(src_ip, entries)
            alerts.extend(brute_force_alerts)
            
            # Detect rapid connection attempts (successful or failed)
            rapid_connection_alerts = self._detect_rapid_connections(src_ip, entries)
            alerts.extend(rapid_connection_alerts)
            
            # Detect service-specific brute force patterns
            service_alerts = self._detect_service_brute_force(src_ip, entries)
            alerts.extend(service_alerts)
        
        return alerts
    
    def _detect_failed_connections(self, src_ip: str, entries: List[Dict]) -> List[Dict]:
        """Detect patterns of failed/blocked connections"""
        
        alerts = []
        blocked_entries = [e for e in entries if e.get('action', '').upper() in ['BLOCK', 'DENY', 'DROP']]
        
        if len(blocked_entries) < self.failed_attempts_threshold:
            return alerts
        
        # Group blocked entries by destination and time windows
        destination_blocks = defaultdict(list)
        
        for entry in blocked_entries:
            dst_key = f"{entry.get('dst_ip', '')}:{entry.get('dst_port', 0)}"
            destination_blocks[dst_key].append(entry)
        
        # Check each destination for brute force patterns
        for dst_key, dst_entries in destination_blocks.items():
            if len(dst_entries) >= self.failed_attempts_threshold:
                # Check if attempts are within time window
                time_windows = self._group_by_time_window(dst_entries)
                
                for window_start, window_entries in time_windows.items():
                    if len(window_entries) >= self.failed_attempts_threshold:
                        severity = self._calculate_severity(len(window_entries))
                        
                        dst_ip, dst_port = dst_key.split(':')
                        service_name = self.brute_force_ports.get(int(dst_port), f"Port {dst_port}")
                        
                        alert = {
                            'severity': severity,
                            'type': 'BRUTE_FORCE',
                            'title': f'Brute Force Attack Detected',
                            'description': f'Source {src_ip} made {len(window_entries)} failed connection attempts to {service_name} on {dst_ip}:{dst_port} within {self.time_window_minutes} minutes',
                            'timestamp': window_entries[0].get('timestamp', ''),
                            'source_ip': src_ip,
                            'destination_ip': dst_ip,
                            'destination_port': int(dst_port),
                            'service': service_name,
                            'failed_attempts': len(window_entries),
                            'time_window_minutes': self.time_window_minutes,
                            'attack_duration': self._calculate_duration(window_entries),
                            'recommendation': self._get_brute_force_recommendation(service_name, len(window_entries)),
                            'first_attempt': window_entries[0].get('timestamp', ''),
                            'last_attempt': window_entries[-1].get('timestamp', ''),
                            'sample_logs': [e.get('raw_log', '') for e in window_entries[:3]]
                        }
                        alerts.append(alert)
        
        return alerts
    
    def _detect_rapid_connections(self, src_ip: str, entries: List[Dict]) -> List[Dict]:
        """Detect rapid connection attempts (potential scanning)"""
        
        alerts = []
        
        # Group entries by 1-minute time windows
        time_windows = self._group_by_time_window(entries, window_minutes=1)
        
        for window_start, window_entries in time_windows.items():
            if len(window_entries) > 20:  # More than 20 connections per minute
                unique_ports = len(set(e.get('dst_port', 0) for e in window_entries))
                unique_destinations = len(set(e.get('dst_ip', '') for e in window_entries))
                
                if unique_ports > 10 or unique_destinations > 5:
                    alert = {
                        'severity': 'HIGH',
                        'type': 'RAPID_CONNECTIONS', 
                        'title': f'Rapid Connection Pattern Detected',
                        'description': f'Source {src_ip} made {len(window_entries)} connections to {unique_destinations} hosts on {unique_ports} different ports within 1 minute',
                        'timestamp': window_entries[0].get('timestamp', ''),
                        'source_ip': src_ip,
                        'connections_per_minute': len(window_entries),
                        'unique_destinations': unique_destinations,
                        'unique_ports': unique_ports,
                        'pattern_type': 'Port Scan' if unique_ports > unique_destinations else 'Host Scan',
                        'recommendation': 'Block source IP and investigate for reconnaissance activity',
                        'sample_destinations': list(set(e.get('dst_ip', '') for e in window_entries))[:5],
                        'sample_ports': list(set(e.get('dst_port', 0) for e in window_entries))[:10]
                    }
                    alerts.append(alert)
        
        return alerts
    
    def _detect_service_brute_force(self, src_ip: str, entries: List[Dict]) -> List[Dict]:
        """Detect brute force attacks on specific services"""
        
        alerts = []
        
        # Group by service port
        service_activity = defaultdict(list)
        
        for entry in entries:
            dst_port = entry.get('dst_port', 0)
            if dst_port in self.brute_force_ports:
                service_activity[dst_port].append(entry)
        
        # Analyze each service
        for port, service_entries in service_activity.items():
            service_name = self.brute_force_ports[port]
            
            # Count blocked/failed attempts
            blocked_count = len([e for e in service_entries if e.get('action', '').upper() in ['BLOCK', 'DENY', 'DROP']])
            allowed_count = len([e for e in service_entries if e.get('action', '').upper() in ['ALLOW', 'ACCEPT']])
            
            # High number of blocked attempts to critical services
            if blocked_count >= 10 and port in [22, 3389, 1433, 3306]:
                severity = 'CRITICAL' if blocked_count >= 50 else 'HIGH'
                
                alert = {
                    'severity': severity,
                    'type': 'SERVICE_BRUTE_FORCE',
                    'title': f'{service_name} Brute Force Attack',
                    'description': f'Source {src_ip} attempted {blocked_count} blocked connections to {service_name} service',
                    'timestamp': service_entries[0].get('timestamp', ''),
                    'source_ip': src_ip,
                    'service': service_name,
                    'service_port': port,
                    'blocked_attempts': blocked_count,
                    'allowed_attempts': allowed_count,
                    'total_attempts': len(service_entries),
                    'success_rate': f"{(allowed_count/len(service_entries)*100):.1f}%" if service_entries else "0%",
                    'attack_pattern': self._classify_attack_pattern(blocked_count, allowed_count),
                    'recommendation': self._get_service_specific_recommendation(service_name, blocked_count, allowed_count),
                    'destinations': list(set(e.get('dst_ip', '') for e in service_entries))
                }
                alerts.append(alert)
        
        return alerts
    
    def _group_by_time_window(self, entries: List[Dict], window_minutes: int = None) -> Dict:
        """Group log entries by time windows"""
        
        if window_minutes is None:
            window_minutes = self.time_window_minutes
            
        time_windows = defaultdict(list)
        
        for entry in entries:
            timestamp_str = entry.get('timestamp', '')
            if not timestamp_str:
                continue
                
            try:
                # Parse timestamp
                if 'T' in timestamp_str:
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                else:
                    timestamp = datetime.fromisoformat(timestamp_str)
                
                # Create window key (rounded to window_minutes)
                window_start = timestamp.replace(
                    minute=(timestamp.minute // window_minutes) * window_minutes,
                    second=0,
                    microsecond=0
                )
                
                time_windows[window_start].append(entry)
                
            except (ValueError, TypeError):
                continue
        
        return time_windows
    
    def _calculate_severity(self, attempt_count: int) -> str:
        """Calculate severity based on number of attempts"""
        
        if attempt_count >= self.critical_threshold:
            return 'CRITICAL'
        elif attempt_count >= self.high_severity_threshold:
            return 'HIGH'
        else:
            return 'MEDIUM'
    
    def _calculate_duration(self, entries: List[Dict]) -> str:
        """Calculate attack duration"""
        
        if len(entries) < 2:
            return "0 seconds"
            
        try:
            first_time = datetime.fromisoformat(entries[0].get('timestamp', '').replace('Z', '+00:00'))
            last_time = datetime.fromisoformat(entries[-1].get('timestamp', '').replace('Z', '+00:00'))
            
            duration = last_time - first_time
            
            if duration.total_seconds() < 60:
                return f"{int(duration.total_seconds())} seconds"
            elif duration.total_seconds() < 3600:
                return f"{int(duration.total_seconds() / 60)} minutes"
            else:
                return f"{int(duration.total_seconds() / 3600)} hours"
                
        except (ValueError, TypeError):
            return "unknown"
    
    def _classify_attack_pattern(self, blocked_count: int, allowed_count: int) -> str:
        """Classify the type of attack pattern"""
        
        total = blocked_count + allowed_count
        success_rate = allowed_count / total if total > 0 else 0
        
        if success_rate == 0:
            return "Failed brute force (all blocked)"
        elif success_rate < 0.1:
            return "Mostly unsuccessful brute force"
        elif success_rate < 0.5:
            return "Partially successful brute force"
        else:
            return "Successful brute force (high success rate)"
    
    def _get_brute_force_recommendation(self, service: str, attempt_count: int) -> str:
        """Get recommendation based on service and attempt count"""
        
        base_actions = [
            "Immediately block the source IP address",
            "Review and strengthen authentication mechanisms",
            "Enable account lockout policies",
            "Implement rate limiting"
        ]
        
        service_specific = {
            "SSH": ["Use key-based authentication", "Change default SSH port", "Implement fail2ban"],
            "RDP": ["Enable Network Level Authentication", "Use strong passwords", "Restrict RDP access by IP"],
            "SQL Server": ["Use Windows Authentication", "Disable SQL Server Browser if not needed", "Use VPN for remote access"],
            "FTP": ["Use SFTP instead of FTP", "Implement IP whitelisting", "Use strong passwords"],
            "HTTP/HTTPS": ["Implement CAPTCHA", "Use multi-factor authentication", "Rate limit login attempts"]
        }
        
        recommendations = base_actions.copy()
        if service in service_specific:
            recommendations.extend(service_specific[service])
        
        if attempt_count >= self.critical_threshold:
            recommendations.insert(0, "URGENT: This appears to be an active attack - take immediate action")
        
        return "; ".join(recommendations)
    
    def _get_service_specific_recommendation(self, service: str, blocked: int, allowed: int) -> str:
        """Get service-specific recommendations"""
        
        if allowed > 0:
            return f"CRITICAL: {service} brute force may have been successful ({allowed} allowed connections). Immediately verify account security and check for unauthorized access."
        else:
            return f"Block source IP and review {service} security configuration. Consider implementing additional authentication layers."
