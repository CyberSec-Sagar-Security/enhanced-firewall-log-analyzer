#!/usr/bin/env python3
"""
Suspicious Port Detector
Detects connections to high-risk ports commonly used by attackers
Author: SOC Team
"""

from typing import List, Dict
from collections import defaultdict


class SuspiciousPortDetector:
    """Detector for suspicious port usage patterns"""
    
    def __init__(self):
        # High-risk ports commonly used by attackers
        self.high_risk_ports = {
            # Remote Access/Control
            22: "SSH - Potential unauthorized remote access",
            23: "Telnet - Insecure remote access protocol", 
            3389: "RDP - Remote Desktop Protocol access",
            5900: "VNC - Virtual Network Computing",
            5901: "VNC - Alternative port",
            
            # Database Services
            1433: "SQL Server - Database access attempt",
            1434: "SQL Server Browser - Database enumeration",
            1521: "Oracle DB - Database access attempt",
            3306: "MySQL - Database access attempt",
            5432: "PostgreSQL - Database access attempt",
            
            # Windows Services
            135: "RPC Endpoint Mapper - Windows service",
            139: "NetBIOS Session - Windows file sharing",
            445: "SMB - Windows file sharing protocol",
            593: "HTTP RPC Endpoint Mapper",
            
            # Backdoor/Malware Ports
            1337: "Elite/Leet - Common backdoor port",
            4444: "Metasploit - Common reverse shell port",
            6666: "IRC/Beast Trojan - Malware communication",
            6667: "IRC - Bot communication channel",
            31337: "Back Orifice - Remote access trojan",
            12345: "NetBus - Remote access trojan",
            54321: "Back Orifice 2000 - Remote access trojan",
            
            # P2P/File Sharing
            6881: "BitTorrent - P2P file sharing",
            6969: "BitTorrent Tracker",
            
            # Web Services (suspicious contexts)
            8080: "HTTP Proxy - Potential tunneling",
            8888: "HTTP Alternative - Potential malware C2",
            9999: "HTTP Alternative - Potential backdoor",
            
            # Other Suspicious
            7547: "TR-069 - CPE WAN Management (IoT exploitation)",
            2323: "Telnet Alternative - IoT device access",
            8291: "MikroTik Winbox - Router management"
        }
        
        # Medium-risk ports (generate medium alerts)
        self.medium_risk_ports = {
            21: "FTP - File transfer protocol",
            25: "SMTP - Email server", 
            53: "DNS - Domain name resolution",
            79: "Finger - User information protocol",
            80: "HTTP - Web traffic (suspicious if excessive)",
            110: "POP3 - Email retrieval",
            143: "IMAP - Email access",
            443: "HTTPS - Secure web traffic",
            465: "SMTPS - Secure email",
            993: "IMAPS - Secure email access",
            995: "POP3S - Secure email retrieval",
            1080: "SOCKS Proxy - Potential tunneling",
            8443: "HTTPS Alternative"
        }
    
    def detect(self, log_entries: List[Dict]) -> List[Dict]:
        """
        Detect suspicious port usage in firewall logs
        
        Args:
            log_entries: List of normalized log entries
            
        Returns:
            List of alert dictionaries
        """
        
        alerts = []
        port_stats = defaultdict(lambda: {'count': 0, 'sources': set(), 'destinations': set()})
        
        # Analyze each log entry
        for entry in log_entries:
            dst_port = entry.get('dst_port', 0)
            src_ip = entry.get('src_ip', '')
            dst_ip = entry.get('dst_ip', '')
            action = entry.get('action', '').upper()
            
            if dst_port and dst_port > 0:
                port_stats[dst_port]['count'] += 1
                port_stats[dst_port]['sources'].add(src_ip)
                port_stats[dst_port]['destinations'].add(dst_ip)
                
                # Check for high-risk ports
                if dst_port in self.high_risk_ports:
                    alert = {
                        'severity': 'HIGH',
                        'type': 'SUSPICIOUS_PORT',
                        'title': f'High-Risk Port Activity Detected',
                        'description': f'Connection to high-risk port {dst_port} ({self.high_risk_ports[dst_port]})',
                        'timestamp': entry.get('timestamp', ''),
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'destination_port': dst_port,
                        'protocol': entry.get('protocol', ''),
                        'action': action,
                        'risk_level': 'HIGH',
                        'port_description': self.high_risk_ports[dst_port],
                        'recommendation': self._get_port_recommendation(dst_port),
                        'raw_log': entry.get('raw_log', ''),
                        'line_number': entry.get('line_number', 0)
                    }
                    alerts.append(alert)
                
                # Check for medium-risk ports (only if blocked or excessive)
                elif dst_port in self.medium_risk_ports:
                    if action == 'BLOCK' or port_stats[dst_port]['count'] > 50:
                        alert = {
                            'severity': 'MEDIUM',
                            'type': 'SUSPICIOUS_PORT',
                            'title': f'Medium-Risk Port Activity',
                            'description': f'{"Blocked access" if action == "BLOCK" else "High volume access"} to port {dst_port} ({self.medium_risk_ports[dst_port]})',
                            'timestamp': entry.get('timestamp', ''),
                            'source_ip': src_ip,
                            'destination_ip': dst_ip,
                            'destination_port': dst_port,
                            'protocol': entry.get('protocol', ''),
                            'action': action,
                            'risk_level': 'MEDIUM',
                            'port_description': self.medium_risk_ports[dst_port],
                            'connection_count': port_stats[dst_port]['count'],
                            'raw_log': entry.get('raw_log', ''),
                            'line_number': entry.get('line_number', 0)
                        }
                        alerts.append(alert)
        
        # Generate summary alerts for high-activity ports
        self._generate_port_summary_alerts(port_stats, alerts)
        
        return alerts
    
    def _generate_port_summary_alerts(self, port_stats: Dict, alerts: List[Dict]):
        """Generate summary alerts for ports with high activity"""
        
        for port, stats in port_stats.items():
            if stats['count'] > 100:  # High activity threshold
                # Check if it's a suspicious port or unusual activity
                if port in self.high_risk_ports or port in self.medium_risk_ports:
                    continue  # Already alerted on individual connections
                
                # Alert on unusual high-port activity
                if port > 1024 and len(stats['sources']) > 10:
                    alert = {
                        'severity': 'MEDIUM',
                        'type': 'PORT_SCANNING',
                        'title': f'High Activity on Port {port}',
                        'description': f'Port {port} accessed {stats["count"]} times from {len(stats["sources"])} different sources',
                        'timestamp': '',  # Summary alert
                        'destination_port': port,
                        'connection_count': stats['count'],
                        'unique_sources': len(stats['sources']),
                        'unique_destinations': len(stats['destinations']),
                        'sources': list(stats['sources'])[:10],  # Limit to first 10
                        'recommendation': 'Investigate if this port should be receiving this level of traffic',
                        'risk_level': 'MEDIUM'
                    }
                    alerts.append(alert)
    
    def _get_port_recommendation(self, port: int) -> str:
        """Get security recommendation for specific ports"""
        
        recommendations = {
            22: "Ensure SSH access is restricted to authorized IPs and uses key-based authentication",
            23: "Disable Telnet - use SSH instead for secure remote access",
            3389: "Restrict RDP access to authorized IPs and enable Network Level Authentication",
            1433: "Ensure SQL Server is not exposed to internet, use VPN for remote access",
            135: "Block RPC ports at firewall, only allow within trusted network segments",
            139: "Disable NetBIOS over TCP/IP if not required",
            445: "Restrict SMB access to trusted networks only, enable SMB signing",
            4444: "Block this port - commonly used by Metasploit reverse shells",
            31337: "Block this port - associated with Back Orifice trojan",
            6667: "Monitor IRC traffic for potential botnet communication"
        }
        
        return recommendations.get(port, f"Investigate why port {port} is being accessed and restrict if not required")
