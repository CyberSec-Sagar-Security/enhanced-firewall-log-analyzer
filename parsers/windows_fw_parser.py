#!/usr/bin/env python3
"""
Windows Firewall Log Parser
Parses Windows Defender Firewall logs (.csv, .evtx formats)
Normalizes Windows firewall events for threat detection
"""

import csv
import re
import json
import io
from datetime import datetime
from typing import List, Dict, Optional

# Try to import evtx parser - it's optional
try:
    from evtx import Evtx
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False
    print("⚠️  Warning: python-evtx not available. .evtx files won't be supported.")


class WindowsFirewallParser:
    """Parser for Windows Defender Firewall logs"""
    
    def __init__(self):
        # Windows Firewall event IDs
        self.firewall_event_ids = {
            5156: "Connection Allowed",
            5157: "Connection Blocked", 
            5158: "Bind Allowed",
            5159: "Bind Blocked",
            5152: "Platform Packet Drop",
            5154: "Platform Listen"
        }
        
        # Common Windows firewall CSV log pattern
        self.csv_pattern = re.compile(
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})'  # timestamp
        )
        
        # High-risk ports for Windows environments
        self.windows_risk_ports = {
            135: "RPC Endpoint Mapper",
            139: "NetBIOS Session",
            445: "SMB",
            1433: "SQL Server",
            1434: "SQL Server Browser",
            3389: "RDP",
            5985: "WinRM HTTP",
            5986: "WinRM HTTPS",
            47001: "WinRM"
        }
    
    def parse_log_file(self, file_path: str) -> List[Dict]:
        """
        Parse Windows firewall log file
        
        Args:
            file_path: Path to the log file (.csv or .evtx)
            
        Returns:
            List of normalized log entries
        """
        
        log_entries = []
        
        try:
            if file_path.lower().endswith('.evtx'):
                if EVTX_AVAILABLE:
                    log_entries = self._parse_evtx_format(file_path)
                else:
                    print("❌ EVTX format not supported. Install python-evtx: pip install python-evtx")
                    
            elif file_path.lower().endswith('.csv'):
                log_entries = self._parse_csv_format(file_path)
                
            else:
                # Try to parse as text log
                log_entries = self._parse_text_format(file_path)
                
        except Exception as e:
            print(f"❌ Error parsing Windows firewall log: {str(e)}")
            
        return log_entries
    
    def _parse_evtx_format(self, file_path: str) -> List[Dict]:
        """Parse Windows Event Log (.evtx) format"""
        
        log_entries = []
        
        try:
            with Evtx(file_path) as log:
                for record in log.records():
                    try:
                        # Parse XML event data
                        event_data = self._extract_event_data(record.xml())
                        
                        if event_data and event_data.get('EventID') in self.firewall_event_ids:
                            entry = self._normalize_windows_event(event_data)
                            if entry:
                                log_entries.append(entry)
                                
                    except Exception as e:
                        print(f"⚠️  Warning: Could not parse EVTX record: {str(e)}")
                        continue
                        
        except Exception as e:
            print(f"❌ Error reading EVTX file: {str(e)}")
            
        print(f"✅ Parsed {len(log_entries)} Windows firewall events from EVTX")
        return log_entries
    
    def _parse_csv_format(self, file_path: str) -> List[Dict]:
        """Parse Windows firewall CSV export"""
        
        log_entries = []
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            # Skip comment lines and find the header
            lines = []
            for line in file:
                line = line.strip()
                if line and not line.startswith('#'):
                    lines.append(line)
            
            if not lines:
                print("⚠️  No data found in CSV file")
                return []
            
            # Recreate the CSV data without comments
            csv_data = '\n'.join(lines)
            
            # Try to detect delimiter
            delimiter = ',' if ',' in csv_data else '\t'
            
            # Parse the CSV data
            csv_reader = csv.DictReader(io.StringIO(csv_data), delimiter=delimiter)
            
            for row_num, row in enumerate(csv_reader, 1):
                try:
                    # Common Windows firewall CSV fields
                    entry = {
                        'timestamp': self._normalize_timestamp(
                            row.get('Date', '') + ' ' + row.get('Time', '')
                        ),
                        'action': self._normalize_action(row.get('Action', row.get('Status', ''))),
                        'protocol': row.get('Protocol', '').upper(),
                        'src_ip': row.get('Source IP', row.get('SourceIP', row.get('src_ip', ''))),
                        'src_port': self._safe_int(row.get('Source Port', row.get('SourcePort', row.get('src_port', '0')))),
                        'dst_ip': row.get('Destination IP', row.get('DestIP', row.get('dst_ip', ''))),
                        'dst_port': self._safe_int(row.get('Destination Port', row.get('DestPort', row.get('dst_port', '0')))),
                        'direction': row.get('Direction', 'unknown'),
                        'process': row.get('Process', row.get('Application', '')),
                        'event_id': self._safe_int(row.get('Event ID', row.get('EventID', '0'))),
                        'line_number': row_num,
                        'raw_log': str(row)
                    }
                    
                    # Only include entries with valid IPs
                    if entry['src_ip'] and entry['dst_ip']:
                        log_entries.append(entry)
                        
                except Exception as e:
                    print(f"⚠️  Warning: Could not parse CSV row {row_num}: {str(e)}")
                    continue
                    
        print(f"✅ Parsed {len(log_entries)} entries from Windows CSV format")
        return log_entries
    
    def _parse_text_format(self, file_path: str) -> List[Dict]:
        """Parse Windows firewall text log format"""
        
        log_entries = []
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line_num, line in enumerate(file, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                    
                # Windows firewall log format: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path
                parts = line.split()
                
                if len(parts) >= 8:
                    try:
                        entry = {
                            'timestamp': self._normalize_timestamp(f"{parts[0]} {parts[1]}"),
                            'action': parts[2].upper(),
                            'protocol': parts[3].upper(),
                            'src_ip': parts[4],
                            'dst_ip': parts[5],
                            'src_port': self._safe_int(parts[6]),
                            'dst_port': self._safe_int(parts[7]),
                            'size': self._safe_int(parts[8]) if len(parts) > 8 else 0,
                            'line_number': line_num,
                            'raw_log': line
                        }
                        
                        log_entries.append(entry)
                        
                    except Exception as e:
                        print(f"⚠️  Warning: Could not parse line {line_num}: {str(e)}")
                        continue
                        
        print(f"✅ Parsed {len(log_entries)} entries from Windows text format")
        return log_entries
    
    def _extract_event_data(self, xml_data: str) -> Dict:
        """Extract relevant data from Windows Event XML"""
        
        # Simple XML parsing - in production you'd use xml.etree.ElementTree
        event_data = {}
        
        try:
            # Extract Event ID
            event_id_match = re.search(r'<EventID>(\d+)</EventID>', xml_data)
            if event_id_match:
                event_data['EventID'] = int(event_id_match.group(1))
            
            # Extract timestamp
            time_match = re.search(r'<TimeCreated SystemTime="([^"]+)"', xml_data)
            if time_match:
                event_data['TimeCreated'] = time_match.group(1)
            
            # Extract network data from EventData
            src_ip_match = re.search(r'<Data Name="SourceAddress">([^<]+)</Data>', xml_data)
            if src_ip_match:
                event_data['SourceAddress'] = src_ip_match.group(1)
                
            dst_ip_match = re.search(r'<Data Name="DestAddress">([^<]+)</Data>', xml_data)
            if dst_ip_match:
                event_data['DestAddress'] = dst_ip_match.group(1)
                
            src_port_match = re.search(r'<Data Name="SourcePort">([^<]+)</Data>', xml_data)
            if src_port_match:
                event_data['SourcePort'] = src_port_match.group(1)
                
            dst_port_match = re.search(r'<Data Name="DestPort">([^<]+)</Data>', xml_data)
            if dst_port_match:
                event_data['DestPort'] = dst_port_match.group(1)
                
            protocol_match = re.search(r'<Data Name="Protocol">([^<]+)</Data>', xml_data)
            if protocol_match:
                event_data['Protocol'] = protocol_match.group(1)
                
        except Exception as e:
            print(f"⚠️  Warning: Error extracting event data: {str(e)}")
            
        return event_data
    
    def _normalize_windows_event(self, event_data: Dict) -> Optional[Dict]:
        """Normalize Windows event to standard format"""
        
        try:
            entry = {
                'timestamp': self._normalize_timestamp(event_data.get('TimeCreated', '')),
                'action': 'ALLOW' if event_data['EventID'] in [5156, 5158] else 'BLOCK',
                'protocol': self._get_protocol_name(event_data.get('Protocol', '')),
                'src_ip': event_data.get('SourceAddress', ''),
                'src_port': self._safe_int(event_data.get('SourcePort', '0')),
                'dst_ip': event_data.get('DestAddress', ''),
                'dst_port': self._safe_int(event_data.get('DestPort', '0')),
                'event_id': event_data['EventID'],
                'event_description': self.firewall_event_ids.get(event_data['EventID'], 'Unknown'),
                'raw_log': str(event_data)
            }
            
            return entry if entry['src_ip'] and entry['dst_ip'] else None
            
        except Exception as e:
            print(f"⚠️  Warning: Error normalizing Windows event: {str(e)}")
            return None
    
    def _normalize_action(self, action: str) -> str:
        """Normalize action field"""
        
        action = action.upper().strip()
        
        if 'ALLOW' in action or 'ACCEPT' in action or 'PERMIT' in action:
            return 'ALLOW'
        elif 'BLOCK' in action or 'DENY' in action or 'DROP' in action:
            return 'BLOCK'
        else:
            return action
    
    def _get_protocol_name(self, protocol: str) -> str:
        """Convert protocol number to name"""
        
        protocol_map = {
            '1': 'ICMP',
            '6': 'TCP', 
            '17': 'UDP',
            '58': 'ICMPv6'
        }
        
        return protocol_map.get(str(protocol), protocol.upper())
    
    def _safe_int(self, value: str) -> int:
        """Safely convert string to int"""
        
        try:
            return int(value) if value and str(value).isdigit() else 0
        except (ValueError, TypeError):
            return 0
    
    def _normalize_timestamp(self, timestamp_str: str) -> str:
        """Normalize timestamp to ISO format"""
        
        try:
            # Handle various Windows timestamp formats
            timestamp_str = timestamp_str.strip()
            
            if not timestamp_str:
                return datetime.now().isoformat()
                
            # Format: "2025-06-15T14:23:45.123456Z" (ISO with microseconds)
            if 'T' in timestamp_str and 'Z' in timestamp_str:
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                return dt.isoformat()
                
            # Format: "2025-06-15 14:23:45"
            elif re.match(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}', timestamp_str):
                dt = datetime.strptime(timestamp_str[:19], "%Y-%m-%d %H:%M:%S")
                return dt.isoformat()
                
            # Format: "06/15/2025 14:23:45"
            elif re.match(r'\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}', timestamp_str):
                dt = datetime.strptime(timestamp_str[:19], "%m/%d/%Y %H:%M:%S")
                return dt.isoformat()
                
            else:
                # If we can't parse it, return current time
                return datetime.now().isoformat()
                
        except Exception as e:
            # If any error occurs, return current time
            return datetime.now().isoformat()
