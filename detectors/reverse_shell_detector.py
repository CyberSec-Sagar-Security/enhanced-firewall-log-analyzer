#!/usr/bin/env python3
"""
Reverse Shell Detector
Detects reverse shell connections and suspicious outbound connection patterns
Author: SOC Team
"""

from typing import List, Dict
from collections import defaultdict
from datetime import datetime, timedelta


class ReverseShellDetector:
    """Detector for reverse shell and backdoor connections"""
    
    def __init__(self):
        # Common reverse shell ports
        self.reverse_shell_ports = {
            4444: "Metasploit default reverse shell",
            1234: "Common netcat reverse shell",
            4445: "Alternative metasploit port",
            4446: "Alternative metasploit port", 
            5555: "Common reverse shell port",
            6666: "Common reverse shell port",
            7777: "Common reverse shell port",
            8888: "Common reverse shell port",
            9999: "Common reverse shell port",
            1337: "Elite/Leet port - often used by attackers",
            31337: "Back Orifice - classic backdoor",
            12345: "NetBus - remote access trojan",
            54321: "Back Orifice 2000",
            6969: "Common reverse shell port",
            8080: "HTTP proxy - potential tunneling",
            8443: "HTTPS alternative - potential tunneling"
        }
        
        # Suspicious shell-related patterns
        self.shell_indicators = {
            'quick_connection': 'Very short-lived connections (potential shell testing)',
            'persistent_connection': 'Long-lived connection (potential interactive shell)',
            'high_frequency': 'Multiple rapid connections (potential automated shell)',
            'off_hours': 'Connections during off-hours (potential malicious activity)',
            'external_destination': 'Connection to external IP (potential reverse shell)',
            'uncommon_port': 'Connection to uncommon high port'
        }
        
        # Time thresholds
        self.quick_connection_threshold = 5      # seconds
        self.persistent_connection_threshold = 300  # seconds (5 minutes)
        self.rapid_connection_window = 60       # seconds
        self.rapid_connection_count = 5         # connections in window
    
    def detect(self, log_entries: List[Dict]) -> List[Dict]:
        """
        Detect reverse shell and backdoor connection patterns
        
        Args:
            log_entries: List of normalized log entries
            
        Returns:
            List of alert dictionaries
        """
        
        alerts = []
        
        # Filter for outbound connections to external IPs
        outbound_entries = self._filter_outbound_connections(log_entries)
        
        if not outbound_entries:
            return alerts
        
        # Group by source IP
        source_activity = defaultdict(list)
        for entry in outbound_entries:
            src_ip = entry.get('src_ip', '')
            if src_ip:
                source_activity[src_ip].append(entry)
        
        # Analyze each source for reverse shell patterns
        for src_ip, entries in source_activity.items():
            # Detect connections to known reverse shell ports
            shell_port_alerts = self._detect_shell_port_connections(src_ip, entries)
            alerts.extend(shell_port_alerts)
            
            # Detect suspicious connection patterns
            pattern_alerts = self._detect_suspicious_patterns(src_ip, entries)
            alerts.extend(pattern_alerts)
            
            # Detect rapid sequential connections
            rapid_alerts = self._detect_rapid_connections(src_ip, entries)
            alerts.extend(rapid_alerts)
            
            # Detect persistent outbound connections
            persistent_alerts = self._detect_persistent_connections(src_ip, entries)
            alerts.extend(persistent_alerts)
            
            # Detect off-hours shell activity
            timing_alerts = self._detect_off_hours_shells(src_ip, entries)
            alerts.extend(timing_alerts)
        
        return alerts
    
    def _filter_outbound_connections(self, log_entries: List[Dict]) -> List[Dict]:
        """Filter for outbound connections (internal to external)"""
        
        outbound = []
        
        for entry in log_entries:
            src_ip = entry.get('src_ip', '')
            dst_ip = entry.get('dst_ip', '')
            action = entry.get('action', '').upper()
            
            # Only analyze allowed outbound connections
            if action == 'ALLOW' and src_ip and dst_ip:
                if self._is_internal_ip(src_ip) and not self._is_internal_ip(dst_ip):
                    outbound.append(entry)
        
        return outbound
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP address is internal/private"""
        
        if not ip:
            return False
            
        private_ranges = [
            '10.',           # 10.0.0.0/8
            '172.16.', '172.17.', '172.18.', '172.19.',  # 172.16.0.0/12
            '172.20.', '172.21.', '172.22.', '172.23.',
            '172.24.', '172.25.', '172.26.', '172.27.',
            '172.28.', '172.29.', '172.30.', '172.31.',
            '192.168.',      # 192.168.0.0/16
            '127.',          # Loopback
            '169.254.'       # Link-local
        ]
        
        return any(ip.startswith(prefix) for prefix in private_ranges)
    
    def _detect_shell_port_connections(self, src_ip: str, entries: List[Dict]) -> List[Dict]:
        """Detect connections to known reverse shell ports"""
        
        alerts = []
        
        # Group by destination and port
        shell_connections = defaultdict(list)
        
        for entry in entries:
            dst_port = entry.get('dst_port', 0)
            dst_ip = entry.get('dst_ip', '')
            
            if dst_port in self.reverse_shell_ports:
                key = f"{dst_ip}:{dst_port}"
                shell_connections[key].append(entry)
        
        # Analyze each potential reverse shell connection
        for dst_key, shell_entries in shell_connections.items():
            dst_ip, dst_port = dst_key.split(':')
            dst_port = int(dst_port)
            port_description = self.reverse_shell_ports[dst_port]
            
            # Calculate connection characteristics
            connection_analysis = self._analyze_connection_characteristics(shell_entries)
            
            severity = self._calculate_shell_severity(dst_port, len(shell_entries), connection_analysis)
            
            alert = {
                'severity': severity,
                'type': 'REVERSE_SHELL',
                'title': f'Potential Reverse Shell Connection',
                'description': f'Host {src_ip} connected to known reverse shell port {dst_port} on {dst_ip} ({port_description})',
                'timestamp': shell_entries[0].get('timestamp', ''),
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'destination_port': dst_port,
                'port_description': port_description,
                'connection_count': len(shell_entries),
                'connection_analysis': connection_analysis,
                'time_span': self._calculate_time_span_description(shell_entries),
                'risk_indicators': self._identify_shell_risk_indicators(shell_entries, dst_port),
                'recommendation': self._get_shell_recommendation(dst_port, len(shell_entries), connection_analysis),
                'first_connection': shell_entries[0].get('timestamp', ''),
                'last_connection': shell_entries[-1].get('timestamp', ''),
                'sample_logs': [e.get('raw_log', '') for e in shell_entries[:3]]
            }
            alerts.append(alert)
        
        return alerts
    
    def _detect_suspicious_patterns(self, src_ip: str, entries: List[Dict]) -> List[Dict]:
        """Detect suspicious connection patterns that may indicate reverse shells"""
        
        alerts = []
        
        # Analyze high ports (> 1024) for suspicious activity
        high_port_connections = defaultdict(list)
        
        for entry in entries:
            dst_port = entry.get('dst_port', 0)
            if dst_port > 1024:  # High ports
                dst_ip = entry.get('dst_ip', '')
                key = f"{dst_ip}:{dst_port}"
                high_port_connections[key].append(entry)
        
        # Look for suspicious patterns in high ports
        for dst_key, port_entries in high_port_connections.items():
            if len(port_entries) >= 3:  # Multiple connections to same high port
                dst_ip, dst_port = dst_key.split(':')
                dst_port = int(dst_port)
                
                # Analyze pattern characteristics
                pattern_analysis = self._analyze_pattern_suspiciousness(port_entries)
                
                if pattern_analysis['suspicion_score'] > 0.6:  # Threshold for suspicious pattern
                    alert = {
                        'severity': 'MEDIUM',
                        'type': 'SUSPICIOUS_OUTBOUND_PATTERN',
                        'title': f'Suspicious Outbound Connection Pattern',
                        'description': f'Host {src_ip} shows suspicious connection pattern to {dst_ip}:{dst_port}',
                        'timestamp': port_entries[0].get('timestamp', ''),
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'destination_port': dst_port,
                        'connection_count': len(port_entries),
                        'suspicion_score': f"{pattern_analysis['suspicion_score']:.2f}",
                        'suspicious_indicators': pattern_analysis['indicators'],
                        'pattern_type': pattern_analysis['pattern_type'],
                        'recommendation': 'Investigate connection purpose and consider blocking if unauthorized',
                        'time_span': self._calculate_time_span_description(port_entries)
                    }
                    alerts.append(alert)
        
        return alerts
    
    def _detect_rapid_connections(self, src_ip: str, entries: List[Dict]) -> List[Dict]:
        """Detect rapid sequential connections (potential shell testing)"""
        
        alerts = []
        
        # Group entries by time windows
        time_windows = self._group_by_time_window(entries, self.rapid_connection_window)
        
        for window_start, window_entries in time_windows.items():
            if len(window_entries) >= self.rapid_connection_count:
                # Analyze the rapid connections
                unique_ports = set(e.get('dst_port', 0) for e in window_entries)
                unique_destinations = set(e.get('dst_ip', '') for e in window_entries)
                
                # Check if connections are to potentially suspicious ports
                suspicious_ports = [p for p in unique_ports if p in self.reverse_shell_ports or p > 8000]
                
                if suspicious_ports or len(unique_destinations) == 1:  # Rapid connections to single host
                    alert = {
                        'severity': 'HIGH',
                        'type': 'RAPID_SHELL_CONNECTIONS',
                        'title': f'Rapid Outbound Connections Detected',
                        'description': f'Host {src_ip} made {len(window_entries)} rapid connections within {self.rapid_connection_window} seconds',
                        'timestamp': window_entries[0].get('timestamp', ''),
                        'source_ip': src_ip,
                        'connections_in_window': len(window_entries),
                        'time_window_seconds': self.rapid_connection_window,
                        'unique_destinations': len(unique_destinations),
                        'unique_ports': len(unique_ports),
                        'suspicious_ports': list(suspicious_ports),
                        'destinations': list(unique_destinations),
                        'pattern_type': 'Potential shell testing or automated connection attempts',
                        'recommendation': 'Investigate for malware or unauthorized access attempts',
                        'risk_level': 'HIGH'
                    }
                    alerts.append(alert)
        
        return alerts
    
    def _detect_persistent_connections(self, src_ip: str, entries: List[Dict]) -> List[Dict]:
        """Detect long-lived connections (potential interactive shells)"""
        
        alerts = []
        
        # Group by destination for analysis
        dest_connections = defaultdict(list)
        
        for entry in entries:
            dst_key = f"{entry.get('dst_ip', '')}:{entry.get('dst_port', 0)}"
            dest_connections[dst_key].append(entry)
        
        # Analyze each destination
        for dst_key, dest_entries in dest_connections.items():
            if len(dest_entries) >= 2:
                # Calculate connection duration approximation
                time_span = self._calculate_time_span(dest_entries)
                
                if time_span.total_seconds() > self.persistent_connection_threshold:
                    dst_ip, dst_port = dst_key.split(':')
                    dst_port = int(dst_port)
                    
                    # Check if it's a suspicious port or pattern
                    is_suspicious_port = dst_port in self.reverse_shell_ports
                    has_shell_characteristics = self._has_shell_characteristics(dest_entries)
                    
                    if is_suspicious_port or has_shell_characteristics:
                        severity = 'HIGH' if is_suspicious_port else 'MEDIUM'
                        
                        alert = {
                            'severity': severity,
                            'type': 'PERSISTENT_OUTBOUND_CONNECTION',
                            'title': f'Persistent Outbound Connection',
                            'description': f'Host {src_ip} maintained connection to {dst_ip}:{dst_port} for {self._format_duration(time_span)}',
                            'timestamp': dest_entries[0].get('timestamp', ''),
                            'source_ip': src_ip,
                            'destination_ip': dst_ip,
                            'destination_port': dst_port,
                            'connection_duration': self._format_duration(time_span),
                            'connection_events': len(dest_entries),
                            'is_known_shell_port': is_suspicious_port,
                            'shell_characteristics': has_shell_characteristics,
                            'pattern_analysis': 'Potential interactive shell session' if is_suspicious_port else 'Suspicious long-lived connection',
                            'recommendation': 'Investigate connection purpose - may indicate compromise or unauthorized access',
                            'first_connection': dest_entries[0].get('timestamp', ''),
                            'last_connection': dest_entries[-1].get('timestamp', '')
                        }
                        alerts.append(alert)
        
        return alerts
    
    def _detect_off_hours_shells(self, src_ip: str, entries: List[Dict]) -> List[Dict]:
        """Detect potential shell activity during off-hours"""
        
        alerts = []
        
        # Filter for entries to suspicious ports during off-hours
        off_hours_shells = []
        
        for entry in entries:
            try:
                timestamp = datetime.fromisoformat(entry.get('timestamp', '').replace('Z', '+00:00'))
                hour = timestamp.hour
                weekday = timestamp.weekday()
                dst_port = entry.get('dst_port', 0)
                
                # Define off-hours: before 7 AM, after 8 PM on weekdays, or any time on weekends
                is_off_hours = (
                    (weekday < 5 and (hour < 7 or hour > 20)) or  # Weekday off-hours
                    (weekday >= 5)  # Weekend
                )
                
                # Check for suspicious ports during off-hours
                if is_off_hours and (dst_port in self.reverse_shell_ports or dst_port > 8000):
                    off_hours_shells.append(entry)
                    
            except (ValueError, TypeError):
                continue
        
        if len(off_hours_shells) >= 3:  # Multiple off-hours connections
            unique_destinations = set(f"{e.get('dst_ip', '')}:{e.get('dst_port', 0)}" for e in off_hours_shells)
            suspicious_ports = [e.get('dst_port', 0) for e in off_hours_shells if e.get('dst_port', 0) in self.reverse_shell_ports]
            
            alert = {
                'severity': 'HIGH' if suspicious_ports else 'MEDIUM',
                'type': 'OFF_HOURS_SHELL_ACTIVITY',
                'title': f'Off-Hours Shell Activity Detected',
                'description': f'Host {src_ip} made {len(off_hours_shells)} suspicious outbound connections during off-hours',
                'timestamp': off_hours_shells[0].get('timestamp', ''),
                'source_ip': src_ip,
                'off_hours_connections': len(off_hours_shells),
                'unique_destinations': len(unique_destinations),
                'known_shell_ports': list(set(suspicious_ports)),
                'destinations': list(unique_destinations)[:5],
                'time_pattern': 'Off-hours/weekend activity',
                'recommendation': 'Investigate immediate - off-hours shell activity often indicates compromise',
                'risk_level': 'HIGH',
                'first_activity': off_hours_shells[0].get('timestamp', ''),
                'last_activity': off_hours_shells[-1].get('timestamp', '')
            }
            alerts.append(alert)
        
        return alerts
    
    def _analyze_connection_characteristics(self, entries: List[Dict]) -> Dict:
        """Analyze characteristics of connections"""
        
        if not entries:
            return {}
        
        # Time analysis
        time_span = self._calculate_time_span(entries)
        avg_frequency = len(entries) / max(1, time_span.total_seconds() / 60)  # per minute
        
        # Pattern analysis
        is_rapid = avg_frequency > 0.5  # More than 0.5 connections per minute
        is_persistent = time_span.total_seconds() > self.persistent_connection_threshold
        is_sporadic = len(entries) < 5 and time_span.total_seconds() > 3600  # Few connections over long time
        
        return {
            'connection_count': len(entries),
            'time_span_seconds': time_span.total_seconds(),
            'average_frequency_per_minute': avg_frequency,
            'is_rapid': is_rapid,
            'is_persistent': is_persistent,
            'is_sporadic': is_sporadic,
            'pattern_description': self._describe_connection_pattern(is_rapid, is_persistent, is_sporadic)
        }
    
    def _describe_connection_pattern(self, is_rapid: bool, is_persistent: bool, is_sporadic: bool) -> str:
        """Describe connection pattern"""
        
        if is_rapid and is_persistent:
            return "High-frequency persistent connection (likely interactive shell)"
        elif is_rapid:
            return "Rapid connection attempts (possible shell testing)"
        elif is_persistent:
            return "Long-lived connection (possible persistent shell)"
        elif is_sporadic:
            return "Sporadic connection attempts (possible periodic callback)"
        else:
            return "Normal connection pattern"
    
    def _analyze_pattern_suspiciousness(self, entries: List[Dict]) -> Dict:
        """Analyze how suspicious a connection pattern is"""
        
        suspicion_score = 0.0
        indicators = []
        
        # Port analysis
        ports = [e.get('dst_port', 0) for e in entries]
        unique_ports = set(ports)
        
        # High ports are more suspicious for shells
        high_ports = [p for p in unique_ports if p > 8000]
        if high_ports:
            suspicion_score += 0.3
            indicators.append(f"High ports used: {high_ports}")
        
        # Known shell ports
        shell_ports = [p for p in unique_ports if p in self.reverse_shell_ports]
        if shell_ports:
            suspicion_score += 0.5
            indicators.append(f"Known shell ports: {shell_ports}")
        
        # Frequency analysis
        time_span = self._calculate_time_span(entries)
        if time_span.total_seconds() > 0:
            frequency = len(entries) / (time_span.total_seconds() / 60)  # per minute
            if frequency > 1:  # More than 1 connection per minute
                suspicion_score += 0.2
                indicators.append("High connection frequency")
        
        # Single destination (focused attack)
        destinations = set(e.get('dst_ip', '') for e in entries)
        if len(destinations) == 1:
            suspicion_score += 0.1
            indicators.append("Single destination targeted")
        
        # Pattern type classification
        if suspicion_score > 0.7:
            pattern_type = "Highly suspicious (likely reverse shell)"
        elif suspicion_score > 0.5:
            pattern_type = "Moderately suspicious (potential reverse shell)"
        elif suspicion_score > 0.3:
            pattern_type = "Somewhat suspicious (requires investigation)"
        else:
            pattern_type = "Low suspicion (likely legitimate)"
        
        return {
            'suspicion_score': suspicion_score,
            'indicators': indicators,
            'pattern_type': pattern_type
        }
    
    def _calculate_shell_severity(self, port: int, connection_count: int, analysis: Dict) -> str:
        """Calculate severity level for shell connections"""
        
        # Base severity on port risk
        if port in [4444, 31337, 12345]:  # Highly notorious ports
            base_severity = 'HIGH'
        elif port in self.reverse_shell_ports:
            base_severity = 'MEDIUM'
        else:
            base_severity = 'LOW'
        
        # Upgrade based on pattern
        if analysis.get('is_persistent') and analysis.get('is_rapid'):
            return 'CRITICAL'
        elif connection_count > 10:
            return 'HIGH' if base_severity == 'MEDIUM' else base_severity
        elif analysis.get('is_persistent'):
            return 'HIGH' if base_severity != 'LOW' else 'MEDIUM'
        
        return base_severity
    
    def _has_shell_characteristics(self, entries: List[Dict]) -> bool:
        """Check if connections have shell-like characteristics"""
        
        # Multiple connections to same destination/port
        if len(entries) >= 3:
            return True
        
        # Long time span (potential persistent shell)
        time_span = self._calculate_time_span(entries)
        if time_span.total_seconds() > 300:  # 5 minutes
            return True
        
        return False
    
    def _identify_shell_risk_indicators(self, entries: List[Dict], port: int) -> List[str]:
        """Identify risk indicators for shell connections"""
        
        indicators = []
        
        # Port-based indicators
        if port == 4444:
            indicators.append("Metasploit default port - high risk")
        elif port == 31337:
            indicators.append("Back Orifice port - known backdoor")
        elif port in self.reverse_shell_ports:
            indicators.append("Known reverse shell port")
        
        # Pattern-based indicators
        if len(entries) > 5:
            indicators.append("Multiple connection attempts")
        
        time_span = self._calculate_time_span(entries)
        if time_span.total_seconds() > 600:  # 10 minutes
            indicators.append("Long-duration connection pattern")
        
        # Timing indicators
        off_hours_count = 0
        for entry in entries:
            try:
                timestamp = datetime.fromisoformat(entry.get('timestamp', '').replace('Z', '+00:00'))
                hour = timestamp.hour
                weekday = timestamp.weekday()
                
                if (weekday < 5 and (hour < 7 or hour > 20)) or weekday >= 5:
                    off_hours_count += 1
            except (ValueError, TypeError):
                continue
        
        if off_hours_count > len(entries) * 0.5:
            indicators.append("Predominantly off-hours activity")
        
        return indicators
    
    def _get_shell_recommendation(self, port: int, connection_count: int, analysis: Dict) -> str:
        """Get specific recommendations for shell connections"""
        
        base_recommendations = [
            "Immediately investigate the affected host for compromise",
            "Block outbound connections to the destination IP",
            "Run antivirus/anti-malware scans on the source host",
            "Check for unauthorized processes or services"
        ]
        
        if port in [4444, 31337, 12345]:
            base_recommendations.insert(0, "CRITICAL: Known malware port - isolate host immediately")
        
        if analysis.get('is_persistent'):
            base_recommendations.append("Connection appears persistent - check for active shell sessions")
        
        if connection_count > 10:
            base_recommendations.append("High connection count suggests active exploitation")
        
        return "; ".join(base_recommendations)
    
    def _group_by_time_window(self, entries: List[Dict], window_seconds: int) -> Dict:
        """Group entries by time windows"""
        
        time_windows = defaultdict(list)
        
        for entry in entries:
            try:
                timestamp = datetime.fromisoformat(entry.get('timestamp', '').replace('Z', '+00:00'))
                
                # Create window key
                window_start = timestamp.replace(
                    second=(timestamp.second // window_seconds) * window_seconds,
                    microsecond=0
                )
                
                time_windows[window_start].append(entry)
                
            except (ValueError, TypeError):
                continue
        
        return time_windows
    
    def _calculate_time_span(self, entries: List[Dict]) -> timedelta:
        """Calculate time span between first and last entry"""
        
        if len(entries) < 2:
            return timedelta(0)
        
        try:
            timestamps = []
            for entry in entries:
                ts_str = entry.get('timestamp', '')
                if ts_str:
                    timestamp = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                    timestamps.append(timestamp)
            
            if len(timestamps) >= 2:
                timestamps.sort()
                return timestamps[-1] - timestamps[0]
                
        except (ValueError, TypeError):
            pass
        
        return timedelta(0)
    
    def _calculate_time_span_description(self, entries: List[Dict]) -> str:
        """Get human-readable time span description"""
        
        time_span = self._calculate_time_span(entries)
        return self._format_duration(time_span)
    
    def _format_duration(self, duration: timedelta) -> str:
        """Format duration in human-readable format"""
        
        total_seconds = int(duration.total_seconds())
        
        if total_seconds < 60:
            return f"{total_seconds} seconds"
        elif total_seconds < 3600:
            minutes = total_seconds // 60
            return f"{minutes} minutes"
        else:
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            return f"{hours} hours {minutes} minutes"
