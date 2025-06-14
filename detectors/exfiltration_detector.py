#!/usr/bin/env python3
"""
Data Exfiltration Detector
Detects potential data exfiltration patterns and C2 communication
Author: SOC Team
"""

from typing import List, Dict
from collections import defaultdict
from datetime import datetime, timedelta


class ExfiltrationDetector:
    """Detector for data exfiltration and command & control patterns"""
    
    def __init__(self):
        # Exfiltration detection thresholds
        self.large_transfer_threshold = 100 * 1024 * 1024  # 100MB in bytes
        self.high_connection_count = 100      # High number of outbound connections
        self.suspicious_connection_count = 50  # Suspicious connection count
        self.time_window_minutes = 30         # Time window for analysis
        
        # Known C2 ports (common command & control ports)
        self.c2_ports = {
            53: "DNS (potential DNS tunneling)",
            80: "HTTP (potential HTTP C2)",
            443: "HTTPS (potential HTTPS C2)", 
            8080: "HTTP-Alt (common C2 port)",
            8443: "HTTPS-Alt (common C2 port)",
            4444: "Metasploit default",
            5555: "Common C2 port",
            6666: "IRC/C2 communication",
            7777: "Common C2 port",
            8888: "Common C2 port",
            9999: "Common C2 port"
        }
        
        # Suspicious outbound patterns
        self.suspicious_patterns = {
            'beaconing': 'Regular periodic connections (potential C2 beacon)',
            'bulk_transfer': 'Large data transfer (potential exfiltration)',
            'multiple_destinations': 'Connections to many external IPs',
            'off_hours': 'Activity during non-business hours',
            'encrypted_tunneling': 'Potential encrypted tunneling'
        }
    
    def detect(self, log_entries: List[Dict]) -> List[Dict]:
        """
        Detect data exfiltration and C2 communication patterns
        
        Args:
            log_entries: List of normalized log entries
            
        Returns:
            List of alert dictionaries
        """
        
        alerts = []
        
        # Filter for outbound connections (internal to external)
        outbound_entries = self._filter_outbound_connections(log_entries)
        
        if not outbound_entries:
            return alerts
        
        # Group by source IP for analysis
        source_activity = defaultdict(list)
        for entry in outbound_entries:
            src_ip = entry.get('src_ip', '')
            if src_ip:
                source_activity[src_ip].append(entry)
        
        # Analyze each internal source
        for src_ip, entries in source_activity.items():
            # Detect high-volume outbound connections
            volume_alerts = self._detect_high_volume_outbound(src_ip, entries)
            alerts.extend(volume_alerts)
            
            # Detect C2 communication patterns
            c2_alerts = self._detect_c2_patterns(src_ip, entries)
            alerts.extend(c2_alerts)
            
            # Detect beaconing behavior
            beacon_alerts = self._detect_beaconing(src_ip, entries)
            alerts.extend(beacon_alerts)
            
            # Detect large data transfers
            transfer_alerts = self._detect_large_transfers(src_ip, entries)
            alerts.extend(transfer_alerts)
            
            # Detect off-hours activity
            timing_alerts = self._detect_suspicious_timing(src_ip, entries)
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
            
        # Common private IP ranges
        private_ranges = [
            '10.',           # 10.0.0.0/8
            '172.16.',       # 172.16.0.0/12 (first subnet)
            '172.17.',
            '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.',
            '172.24.', '172.25.', '172.26.', '172.27.',
            '172.28.', '172.29.', '172.30.', '172.31.',
            '192.168.',      # 192.168.0.0/16
            '127.',          # Loopback
            '169.254.'       # Link-local
        ]
        
        return any(ip.startswith(prefix) for prefix in private_ranges)
    
    def _detect_high_volume_outbound(self, src_ip: str, entries: List[Dict]) -> List[Dict]:
        """Detect high volume of outbound connections"""
        
        alerts = []
        
        # Count unique destinations
        unique_destinations = set(e.get('dst_ip', '') for e in entries)
        total_connections = len(entries)
        
        if len(unique_destinations) >= self.suspicious_connection_count:
            severity = 'HIGH' if len(unique_destinations) >= self.high_connection_count else 'MEDIUM'
            
            # Analyze port distribution
            port_distribution = defaultdict(int)
            for entry in entries:
                port_distribution[entry.get('dst_port', 0)] += 1
            
            top_ports = sorted(port_distribution.items(), key=lambda x: x[1], reverse=True)[:5]
            
            alert = {
                'severity': severity,
                'type': 'HIGH_VOLUME_OUTBOUND',
                'title': f'High Volume Outbound Connections',
                'description': f'Host {src_ip} made {total_connections} outbound connections to {len(unique_destinations)} unique external destinations',
                'timestamp': entries[0].get('timestamp', ''),
                'source_ip': src_ip,
                'total_connections': total_connections,
                'unique_destinations': len(unique_destinations),
                'connection_rate': f"{total_connections / max(1, len(set(e.get('timestamp', '')[:10] for e in entries)))} connections/day",
                'top_ports': [f"Port {p}({c} connections)" for p, c in top_ports],
                'sample_destinations': list(unique_destinations)[:10],
                'risk_indicators': self._identify_risk_indicators(entries),
                'recommendation': 'Investigate host for potential malware infection or data exfiltration',
                'pattern_type': 'Potential C2 communication or data exfiltration'
            }
            alerts.append(alert)
        
        return alerts
    
    def _detect_c2_patterns(self, src_ip: str, entries: List[Dict]) -> List[Dict]:
        """Detect command and control communication patterns"""
        
        alerts = []
        
        # Group by destination and port
        c2_connections = defaultdict(list)
        
        for entry in entries:
            dst_ip = entry.get('dst_ip', '')
            dst_port = entry.get('dst_port', 0)
            
            if dst_port in self.c2_ports:
                key = f"{dst_ip}:{dst_port}"
                c2_connections[key].append(entry)
        
        # Analyze each potential C2 connection
        for dst_key, c2_entries in c2_connections.items():
            if len(c2_entries) >= 10:  # Multiple connections to same C2 port
                dst_ip, dst_port = dst_key.split(':')
                dst_port = int(dst_port)
                service_desc = self.c2_ports[dst_port]
                
                # Calculate connection frequency
                time_span = self._calculate_time_span(c2_entries)
                frequency = len(c2_entries) / max(1, time_span.total_seconds() / 3600)  # connections per hour
                
                severity = 'HIGH' if frequency > 5 or len(c2_entries) > 50 else 'MEDIUM'
                
                alert = {
                    'severity': severity,
                    'type': 'C2_COMMUNICATION',
                    'title': f'Potential C2 Communication Detected',
                    'description': f'Host {src_ip} made {len(c2_entries)} connections to {dst_ip}:{dst_port} ({service_desc})',
                    'timestamp': c2_entries[0].get('timestamp', ''),
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'destination_port': dst_port,
                    'service_description': service_desc,
                    'connection_count': len(c2_entries),
                    'connection_frequency': f"{frequency:.2f} connections/hour",
                    'time_span': str(time_span),
                    'pattern_analysis': self._analyze_connection_pattern(c2_entries),
                    'recommendation': f'Block communication to {dst_ip} and investigate host {src_ip} for malware',
                    'first_connection': c2_entries[0].get('timestamp', ''),
                    'last_connection': c2_entries[-1].get('timestamp', '')
                }
                alerts.append(alert)
        
        return alerts
    
    def _detect_beaconing(self, src_ip: str, entries: List[Dict]) -> List[Dict]:
        """Detect beaconing behavior (regular periodic connections)"""
        
        alerts = []
        
        # Group by destination
        dest_connections = defaultdict(list)
        
        for entry in entries:
            dst_ip = entry.get('dst_ip', '')
            if dst_ip:
                dest_connections[dst_ip].append(entry)
        
        # Analyze each destination for beaconing
        for dst_ip, dest_entries in dest_connections.items():
            if len(dest_entries) >= 20:  # Minimum connections for pattern analysis
                beacon_analysis = self._analyze_beaconing_pattern(dest_entries)
                
                if beacon_analysis['is_beaconing']:
                    alert = {
                        'severity': 'HIGH',
                        'type': 'BEACONING',
                        'title': f'Beaconing Behavior Detected',
                        'description': f'Host {src_ip} shows regular periodic connections to {dst_ip} (potential C2 beacon)',
                        'timestamp': dest_entries[0].get('timestamp', ''),
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'connection_count': len(dest_entries),
                        'average_interval': beacon_analysis['avg_interval'],
                        'interval_consistency': f"{beacon_analysis['consistency']:.1f}%",
                        'beacon_period': beacon_analysis['period_description'],
                        'time_span': str(self._calculate_time_span(dest_entries)),
                        'pattern_confidence': beacon_analysis['confidence'],
                        'recommendation': f'Immediately block {dst_ip} and investigate {src_ip} for malware infection',
                        'risk_level': 'CRITICAL'
                    }
                    alerts.append(alert)
        
        return alerts
    
    def _detect_large_transfers(self, src_ip: str, entries: List[Dict]) -> List[Dict]:
        """Detect large data transfers (potential exfiltration)"""
        
        alerts = []
        
        # Calculate total transfer volume (if available in logs)
        total_bytes = 0
        large_transfers = []
        
        for entry in entries:
            transfer_size = entry.get('size', 0) or entry.get('length', 0) or entry.get('bytes', 0)
            if transfer_size > 0:
                total_bytes += transfer_size
                if transfer_size > 10 * 1024 * 1024:  # 10MB+ transfers
                    large_transfers.append(entry)
        
        # Alert on large total volume
        if total_bytes > self.large_transfer_threshold:
            alert = {
                'severity': 'HIGH',
                'type': 'LARGE_DATA_TRANSFER',
                'title': f'Large Data Transfer Detected',
                'description': f'Host {src_ip} transferred {self._format_bytes(total_bytes)} of data externally',
                'timestamp': entries[0].get('timestamp', ''),
                'source_ip': src_ip,
                'total_bytes': total_bytes,
                'total_size_formatted': self._format_bytes(total_bytes),
                'large_transfer_count': len(large_transfers),
                'unique_destinations': len(set(e.get('dst_ip', '') for e in entries)),
                'transfer_timespan': str(self._calculate_time_span(entries)),
                'recommendation': 'Investigate potential data exfiltration - verify if data transfer was authorized',
                'risk_indicators': ['Large volume outbound transfer', 'Multiple external destinations'],
                'sample_destinations': list(set(e.get('dst_ip', '') for e in large_transfers))[:5]
            }
            alerts.append(alert)
        
        return alerts
    
    def _detect_suspicious_timing(self, src_ip: str, entries: List[Dict]) -> List[Dict]:
        """Detect suspicious timing patterns (off-hours activity)"""
        
        alerts = []
        
        # Analyze timing of connections
        time_analysis = self._analyze_connection_timing(entries)
        
        if time_analysis['off_hours_percentage'] > 70:  # More than 70% off-hours
            alert = {
                'severity': 'MEDIUM',
                'type': 'OFF_HOURS_ACTIVITY',
                'title': f'Suspicious Off-Hours Activity',
                'description': f'Host {src_ip} made {time_analysis["off_hours_count"]} outbound connections during off-hours ({time_analysis["off_hours_percentage"]:.1f}%)',
                'timestamp': entries[0].get('timestamp', ''),
                'source_ip': src_ip,
                'total_connections': len(entries),
                'off_hours_connections': time_analysis['off_hours_count'],
                'off_hours_percentage': f"{time_analysis['off_hours_percentage']:.1f}%",
                'peak_activity_hours': time_analysis['peak_hours'],
                'weekend_activity': time_analysis['weekend_count'],
                'recommendation': 'Investigate why this host is active during off-hours - potential automated malware activity',
                'pattern_type': 'Temporal anomaly'
            }
            alerts.append(alert)
        
        return alerts
    
    def _analyze_beaconing_pattern(self, entries: List[Dict]) -> Dict:
        """Analyze connection pattern for beaconing behavior"""
        
        if len(entries) < 5:
            return {'is_beaconing': False}
        
        # Sort by timestamp
        entries.sort(key=lambda x: x.get('timestamp', ''))
        
        # Calculate intervals between connections
        intervals = []
        for i in range(1, len(entries)):
            try:
                prev_time = datetime.fromisoformat(entries[i-1].get('timestamp', '').replace('Z', '+00:00'))
                curr_time = datetime.fromisoformat(entries[i].get('timestamp', '').replace('Z', '+00:00'))
                interval = (curr_time - prev_time).total_seconds()
                intervals.append(interval)
            except (ValueError, TypeError):
                continue
        
        if not intervals:
            return {'is_beaconing': False}
        
        # Calculate statistics
        avg_interval = sum(intervals) / len(intervals)
        
        # Check for consistency (low standard deviation indicates regular pattern)
        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = variance ** 0.5
        
        # Coefficient of variation (std_dev / mean)
        cv = std_dev / avg_interval if avg_interval > 0 else float('inf')
        
        # Consider it beaconing if:
        # 1. Regular intervals (low coefficient of variation)
        # 2. Reasonable beacon frequency (not too fast, not too slow)
        is_beaconing = (
            cv < 0.3 and  # Less than 30% variation
            30 <= avg_interval <= 3600  # Between 30 seconds and 1 hour
        )
        
        consistency = max(0, (1 - cv) * 100)  # Convert to percentage
        
        # Determine period description
        if avg_interval < 60:
            period_desc = f"Every {avg_interval:.0f} seconds"
        elif avg_interval < 3600:
            period_desc = f"Every {avg_interval/60:.1f} minutes"
        else:
            period_desc = f"Every {avg_interval/3600:.1f} hours"
        
        return {
            'is_beaconing': is_beaconing,
            'avg_interval': avg_interval,
            'consistency': consistency,
            'period_description': period_desc,
            'confidence': 'HIGH' if cv < 0.2 else 'MEDIUM' if cv < 0.3 else 'LOW'
        }
    
    def _analyze_connection_timing(self, entries: List[Dict]) -> Dict:
        """Analyze timing patterns of connections"""
        
        off_hours_count = 0
        weekend_count = 0
        hour_distribution = defaultdict(int)
        
        for entry in entries:
            try:
                timestamp = datetime.fromisoformat(entry.get('timestamp', '').replace('Z', '+00:00'))
                hour = timestamp.hour
                weekday = timestamp.weekday()  # 0=Monday, 6=Sunday
                
                hour_distribution[hour] += 1
                
                # Off-hours: before 7 AM or after 7 PM on weekdays
                if weekday < 5:  # Weekday
                    if hour < 7 or hour > 19:
                        off_hours_count += 1
                else:  # Weekend
                    weekend_count += 1
                    off_hours_count += 1  # Consider all weekend as off-hours
                    
            except (ValueError, TypeError):
                continue
        
        total_connections = len(entries)
        off_hours_percentage = (off_hours_count / total_connections * 100) if total_connections > 0 else 0
        
        # Find peak activity hours
        peak_hours = sorted(hour_distribution.items(), key=lambda x: x[1], reverse=True)[:3]
        peak_hours_formatted = [f"{hour:02d}:00 ({count} connections)" for hour, count in peak_hours]
        
        return {
            'off_hours_count': off_hours_count,
            'off_hours_percentage': off_hours_percentage,
            'weekend_count': weekend_count,
            'peak_hours': peak_hours_formatted,
            'hour_distribution': dict(hour_distribution)
        }
    
    def _calculate_time_span(self, entries: List[Dict]) -> timedelta:
        """Calculate time span between first and last entry"""
        
        if len(entries) < 2:
            return timedelta(0)
        
        try:
            entries_sorted = sorted(entries, key=lambda x: x.get('timestamp', ''))
            first_time = datetime.fromisoformat(entries_sorted[0].get('timestamp', '').replace('Z', '+00:00'))
            last_time = datetime.fromisoformat(entries_sorted[-1].get('timestamp', '').replace('Z', '+00:00'))
            return last_time - first_time
        except (ValueError, TypeError):
            return timedelta(0)
    
    def _analyze_connection_pattern(self, entries: List[Dict]) -> str:
        """Analyze and describe connection pattern"""
        
        patterns = []
        
        # Frequency analysis
        time_span = self._calculate_time_span(entries)
        if time_span.total_seconds() > 0:
            frequency = len(entries) / (time_span.total_seconds() / 3600)
            if frequency > 10:
                patterns.append("High frequency")
            elif frequency > 1:
                patterns.append("Regular frequency")
            else:
                patterns.append("Low frequency")
        
        # Port analysis
        ports = set(e.get('dst_port', 0) for e in entries)
        if len(ports) == 1:
            patterns.append("Single port")
        else:
            patterns.append(f"Multiple ports ({len(ports)})")
        
        # Size analysis (if available)
        sizes = [e.get('size', 0) or e.get('length', 0) for e in entries]
        sizes = [s for s in sizes if s > 0]
        if sizes:
            avg_size = sum(sizes) / len(sizes)
            if avg_size > 1024:
                patterns.append("Large packets")
            else:
                patterns.append("Small packets")
        
        return ", ".join(patterns) if patterns else "Unknown pattern"
    
    def _identify_risk_indicators(self, entries: List[Dict]) -> List[str]:
        """Identify risk indicators in connection patterns"""
        
        indicators = []
        
        # Port analysis
        ports = [e.get('dst_port', 0) for e in entries]
        unique_ports = set(ports)
        
        if len(unique_ports) > 20:
            indicators.append("Port scanning behavior")
        
        c2_port_usage = sum(1 for p in unique_ports if p in self.c2_ports)
        if c2_port_usage > 0:
            indicators.append(f"Known C2 ports used ({c2_port_usage})")
        
        # Destination analysis
        destinations = list(set(e.get('dst_ip', '') for e in entries))
        if len(destinations) > 50:
            indicators.append("Excessive external connections")
        
        # Protocol analysis
        protocols = set(e.get('protocol', '') for e in entries)
        if 'TCP' in protocols and 'UDP' in protocols:
            indicators.append("Mixed protocol usage")
        
        return indicators
    
    def _format_bytes(self, bytes_count: int) -> str:
        """Format bytes count in human-readable format"""
        
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_count < 1024:
                return f"{bytes_count:.2f} {unit}"
            bytes_count /= 1024
        return f"{bytes_count:.2f} PB"
