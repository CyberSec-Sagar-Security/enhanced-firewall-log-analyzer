#!/usr/bin/env python3
"""
pfSense Firewall Log Parser
Parses pfSense firewall logs and normalizes them for threat detection
Supports both CSV export format and raw log format
"""

import csv
import re
from datetime import datetime
from typing import List, Dict, Optional


class PfSenseParser:
    """Parser for pfSense firewall logs"""
    
    def __init__(self):
        # Common pfSense log patterns
        self.raw_log_pattern = re.compile(
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'  # timestamp
            r'[\w-]+\s+filterlog:\s+'                      # hostname and filterlog
            r'(\d+),[\w-]*,(\w+),(\w+),'                  # rule number, interface, reason, action
            r'(\w+),(\d+),'                               # direction, ip version
            r'[\d\w,]*,'                                  # tos, ecn, ttl, id, offset, flags, proto num
            r'(\w+),'                                     # protocol
            r'[\d,]*,'                                    # length
            r'([\d.]+),.*?,'                              # source IP (might have more fields)
            r'([\d.]+),.*?,'                              # dest IP (might have more fields)
            r'(\d+),(\d+)'                                # source port, dest port
        )
        
        # Suspicious ports commonly used by attackers
        self.suspicious_ports = {
            22: "SSH",
            23: "Telnet", 
            135: "RPC",
            139: "NetBIOS",
            445: "SMB",
            1433: "SQL Server",
            1521: "Oracle",
            3389: "RDP",
            4444: "Metasploit",
            5900: "VNC",
            6667: "IRC",
            31337: "Back Orifice"
        }
    
    def parse_log_file(self, file_path: str) -> List[Dict]:
        """
        Parse pfSense log file (supports both CSV and raw format)
        
        Args:
            file_path: Path to the log file
            
        Returns:
            List of normalized log entries
        """
        
        log_entries = []
        
        try:
            # Try to determine file format
            if file_path.lower().endswith('.csv'):
                log_entries = self._parse_csv_format(file_path)
            else:
                log_entries = self._parse_raw_format(file_path)
                
        except Exception as e:
            print(f"❌ Error parsing pfSense log: {str(e)}")
            
        return log_entries
    
    def _parse_csv_format(self, file_path: str) -> List[Dict]:
        """Parse pfSense CSV export format"""
        
        log_entries = []
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            # Skip any header lines that might exist
            content = file.read()
            lines = content.strip().split('\n')
            
            for line_num, line in enumerate(lines, 1):
                if not line.strip() or line.startswith('#'):
                    continue
                    
                try:
                    # CSV format: timestamp,action,interface,protocol,src_ip,src_port,dst_ip,dst_port,length
                    parts = [part.strip().strip('"') for part in line.split(',')]
                    
                    if len(parts) >= 8:
                        entry = {
                            'timestamp': self._normalize_timestamp(parts[0]),
                            'action': parts[1].upper(),
                            'interface': parts[2],
                            'protocol': parts[3].upper(),
                            'src_ip': parts[4],
                            'src_port': int(parts[5]) if parts[5].isdigit() else 0,
                            'dst_ip': parts[6], 
                            'dst_port': int(parts[7]) if parts[7].isdigit() else 0,
                            'length': int(parts[8]) if len(parts) > 8 and parts[8].isdigit() else 0,
                            'line_number': line_num,
                            'raw_log': line
                        }
                        
                        log_entries.append(entry)
                        
                except (ValueError, IndexError) as e:
                    print(f"⚠️  Warning: Could not parse line {line_num}: {str(e)}")
                    continue
                    
        print(f"✅ Parsed {len(log_entries)} entries from CSV format")
        return log_entries
    
    def _parse_raw_format(self, file_path: str) -> List[Dict]:
        """Parse pfSense raw log format"""
        
        log_entries = []
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line_num, line in enumerate(file, 1):
                line = line.strip()
                if not line:
                    continue
                    
                match = self.raw_log_pattern.search(line)
                if match:
                    try:
                        timestamp_str = match.group(1)
                        reason = match.group(3)
                        action = match.group(4)
                        direction = match.group(5)
                        protocol = match.group(7)
                        src_ip = match.group(8)
                        dst_ip = match.group(9)
                        src_port = int(match.group(10)) if match.group(10).isdigit() else 0
                        dst_port = int(match.group(11)) if match.group(11).isdigit() else 0
                        
                        entry = {
                            'timestamp': self._normalize_timestamp(timestamp_str),
                            'action': action.upper(),
                            'reason': reason,
                            'direction': direction,
                            'protocol': protocol.upper(),
                            'src_ip': src_ip,
                            'src_port': src_port,
                            'dst_ip': dst_ip,
                            'dst_port': dst_port,
                            'line_number': line_num,
                            'raw_log': line
                        }
                        
                        log_entries.append(entry)
                        
                    except (ValueError, IndexError) as e:
                        print(f"⚠️  Warning: Could not parse line {line_num}: {str(e)}")
                        continue
                        
        print(f"✅ Parsed {len(log_entries)} entries from raw format")
        return log_entries
    
    def _normalize_timestamp(self, timestamp_str: str) -> str:
        """
        Normalize various timestamp formats to ISO format
        
        Args:
            timestamp_str: Raw timestamp string
            
        Returns:
            ISO formatted timestamp string
        """
        
        try:
            # Handle different timestamp formats
            current_year = datetime.now().year
            
            # Format: "Jun 15 14:23:45" (syslog format)
            if re.match(r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', timestamp_str):
                dt = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
                return dt.isoformat()
                
            # Format: "2025-06-15 14:23:45"
            elif re.match(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}', timestamp_str):
                dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                return dt.isoformat()
                
            # Format: "06/15/2025 14:23:45"
            elif re.match(r'\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}', timestamp_str):
                dt = datetime.strptime(timestamp_str, "%m/%d/%Y %H:%M:%S")
                return dt.isoformat()
                
            else:
                # Fallback - return current time if can't parse
                return datetime.now().isoformat()
                
        except ValueError:
            # If all else fails, return current timestamp
            return datetime.now().isoformat()
    
    def get_suspicious_port_info(self, port: int) -> Optional[str]:
        """
        Get information about suspicious ports
        
        Args:
            port: Port number to check
            
        Returns:
            Service name if port is suspicious, None otherwise
        """
        
        return self.suspicious_ports.get(port)
