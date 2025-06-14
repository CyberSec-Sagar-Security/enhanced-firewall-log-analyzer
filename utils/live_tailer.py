#!/usr/bin/env python3
"""
Live Log Tailing for SOC Firewall Log Analyzer
Watches firewall log files in real-time and processes new entries
Author: SOC Team
"""

import time
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Callable
from loguru import logger
from threading import Thread, Event
import queue

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parsers.windows_fw_parser import WindowsFirewallParser
from parsers.pfsense_parser import PfSenseParser
from detectors.suspicious_ports import SuspiciousPortDetector
from detectors.brute_force_detector import BruteForceDetector
from detectors.exfiltration_detector import ExfiltrationDetector
from detectors.reverse_shell_detector import ReverseShellDetector
from alerts.local_alert import LocalAlert
from utils.log_writer import LogWriter


class LiveLogTailer:
    """Real-time log file monitoring and analysis"""
    
    def __init__(self, log_file_path: str, parser_type: str, 
                 buffer_size: int = 1024, check_interval: float = 1.0):
        """
        Initialize live log tailer
        
        Args:
            log_file_path: Path to log file to monitor
            parser_type: Type of parser ('windows', 'pfsense')
            buffer_size: Buffer size for reading new lines
            check_interval: How often to check for new data (seconds)
        """
        self.log_file_path = Path(log_file_path)
        self.parser_type = parser_type
        self.buffer_size = buffer_size
        self.check_interval = check_interval
        
        # Initialize components
        self.parsers = {
            'windows': WindowsFirewallParser(),
            'pfsense': PfSenseParser()
        }
        
        self.detectors = [
            SuspiciousPortDetector(),
            BruteForceDetector(),
            ExfiltrationDetector(),
            ReverseShellDetector()
        ]
        
        self.alert_system = LocalAlert()
        self.log_writer = LogWriter()
        
        # Threading components
        self.stop_event = Event()
        self.new_lines_queue = queue.Queue()
        self.processing_thread = None
        self.monitoring_thread = None
        
        # File monitoring state
        self.last_position = 0
        self.file_handle = None
        
        # Statistics
        self.stats = {
            'start_time': None,
            'lines_processed': 0,
            'alerts_generated': 0,
            'last_activity': None
        }
        
        logger.add("logs/live_tailer.log", rotation="10 MB")
        logger.info(f"Live tailer initialized for {log_file_path}")
    
    def start_monitoring(self):
        """Start live monitoring of the log file"""
        
        if not self.log_file_path.exists():
            logger.error(f"Log file not found: {self.log_file_path}")
            self.alert_system.show_error(f"Log file not found: {self.log_file_path}")
            return False
        
        self.stats['start_time'] = time.time()
        
        # Initialize file position
        self._initialize_file_position()
        
        # Start monitoring thread
        self.monitoring_thread = Thread(target=self._monitor_file, daemon=True)
        self.monitoring_thread.start()
        
        # Start processing thread
        self.processing_thread = Thread(target=self._process_new_lines, daemon=True)
        self.processing_thread.start()
        
        self.alert_system.show_success("🔴 Live monitoring started!")
        logger.info("Live monitoring started")
        
        return True
    
    def stop_monitoring(self):
        """Stop live monitoring"""
        
        self.stop_event.set()
        
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        
        if self.processing_thread:
            self.processing_thread.join(timeout=5)
        
        if self.file_handle:
            self.file_handle.close()
        
        self.alert_system.show_info("🔴 Live monitoring stopped")
        logger.info("Live monitoring stopped")
    
    def _initialize_file_position(self):
        """Initialize file position (start from end for live monitoring)"""
        
        try:
            self.file_handle = open(self.log_file_path, 'r', encoding='utf-8', errors='ignore')
            # Start from end of file for live monitoring
            self.file_handle.seek(0, 2)  # Seek to end
            self.last_position = self.file_handle.tell()
            logger.info(f"Initialized file position at {self.last_position}")
        except Exception as e:
            logger.error(f"Failed to initialize file position: {e}")
    
    def _monitor_file(self):
        """Monitor file for new lines (runs in separate thread)"""
        
        while not self.stop_event.is_set():
            try:
                if not self.file_handle:
                    self._initialize_file_position()
                    continue
                
                # Check for new data
                current_size = self.log_file_path.stat().st_size
                
                if current_size > self.last_position:
                    # Read new data
                    self.file_handle.seek(self.last_position)
                    new_data = self.file_handle.read(current_size - self.last_position)
                    
                    if new_data:
                        # Split into lines and queue them
                        lines = new_data.split('\n')
                        for line in lines:
                            if line.strip():  # Skip empty lines
                                self.new_lines_queue.put(line.strip())
                        
                        self.last_position = current_size
                        self.stats['last_activity'] = time.time()
                
                elif current_size < self.last_position:
                    # File was truncated/rotated
                    logger.info("Log file rotation detected, reinitializing...")
                    self.file_handle.close()
                    self._initialize_file_position()
                
                time.sleep(self.check_interval)
                
            except Exception as e:
                logger.error(f"Error monitoring file: {e}")
                time.sleep(self.check_interval * 2)  # Back off on error
    
    def _process_new_lines(self):
        """Process new log lines (runs in separate thread)"""
        
        line_buffer = []
        
        while not self.stop_event.is_set():
            try:
                # Collect lines for batch processing
                while not self.new_lines_queue.empty() and len(line_buffer) < 50:
                    line = self.new_lines_queue.get_nowait()
                    line_buffer.append(line)
                
                if line_buffer:
                    self._process_line_batch(line_buffer)
                    line_buffer.clear()
                
                time.sleep(0.5)  # Process every 500ms
                
            except queue.Empty:
                time.sleep(0.1)
            except Exception as e:
                logger.error(f"Error processing lines: {e}")
                time.sleep(1)
    
    def _process_line_batch(self, lines: List[str]):
        """Process a batch of new log lines"""
        
        try:
            # Convert lines to temporary file format for parsing
            temp_content = self._format_lines_for_parsing(lines)
            
            if not temp_content:
                return
            
            # Parse the lines
            parser = self.parsers[self.parser_type]
            log_entries = self._parse_lines_content(parser, temp_content)
            
            if not log_entries:
                return
            
            self.stats['lines_processed'] += len(lines)
            
            # Run detection on new entries
            alerts = self._run_detection(log_entries)
            
            if alerts:
                self.stats['alerts_generated'] += len(alerts)
                self._handle_live_alerts(alerts)
            
        except Exception as e:
            logger.error(f"Error processing line batch: {e}")
    
    def _format_lines_for_parsing(self, lines: List[str]) -> str:
        """Format lines for parser consumption"""
        
        if self.parser_type == 'windows':
            # For Windows CSV format, we need header + data
            header = "Date,Time,Action,Protocol,Source IP,Source Port,Destination IP,Destination Port,Size,Application,Direction"
            formatted_lines = [header] + [line for line in lines if ',' in line]
            return '\n'.join(formatted_lines)
        else:
            # For pfSense, just return the lines
            return '\n'.join(lines)
    
    def _parse_lines_content(self, parser, content: str) -> List[Dict]:
        """Parse content using appropriate parser"""
        
        try:
            # Create temporary file for parsing
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp_file:
                tmp_file.write(content)
                tmp_file.flush()
                
                # Parse using the parser
                entries = parser.parse_log_file(tmp_file.name)
                
                # Clean up
                os.unlink(tmp_file.name)
                
                return entries
                
        except Exception as e:
            logger.error(f"Error parsing lines: {e}")
            return []
    
    def _run_detection(self, log_entries: List[Dict]) -> List[Dict]:
        """Run threat detection on new log entries"""
        
        all_alerts = []
        
        for detector in self.detectors:
            try:
                alerts = detector.detect(log_entries)
                if alerts:
                    for alert in alerts:
                        alert['detection_time'] = time.time()
                        alert['live_detected'] = True
                        all_alerts.append(alert)
            except Exception as e:
                logger.error(f"Error in detector {detector.__class__.__name__}: {e}")
        
        return all_alerts
    
    def _handle_live_alerts(self, alerts: List[Dict]):
        """Handle alerts detected in live mode"""
        
        for alert in alerts:
            # Show immediate alert
            self.alert_system.show_alert(alert)
            
            # Write to JSON log
            self.log_writer.write_alert(alert)
            
            # Log the alert
            logger.warning(f"LIVE ALERT: {alert.get('title', 'Unknown')} - {alert.get('source_ip', 'N/A')}")
    
    def get_statistics(self) -> Dict:
        """Get monitoring statistics"""
        
        runtime = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
        
        return {
            'runtime_seconds': runtime,
            'runtime_formatted': f"{runtime/3600:.1f}h" if runtime > 3600 else f"{runtime/60:.1f}m",
            'lines_processed': self.stats['lines_processed'],
            'alerts_generated': self.stats['alerts_generated'],
            'lines_per_second': self.stats['lines_processed'] / runtime if runtime > 0 else 0,
            'alerts_per_hour': (self.stats['alerts_generated'] / runtime) * 3600 if runtime > 0 else 0,
            'last_activity': self.stats['last_activity'],
            'is_running': not self.stop_event.is_set()
        }
    
    def print_status(self):
        """Print current monitoring status"""
        
        stats = self.get_statistics()
        
        print(f"\n🔴 LIVE MONITORING STATUS")
        print(f"{'='*40}")
        print(f"📁 File: {self.log_file_path.name}")
        print(f"⏱️  Runtime: {stats['runtime_formatted']}")
        print(f"📄 Lines Processed: {stats['lines_processed']}")
        print(f"🚨 Alerts Generated: {stats['alerts_generated']}")
        print(f"📊 Processing Rate: {stats['lines_per_second']:.1f} lines/sec")
        print(f"🔔 Alert Rate: {stats['alerts_per_hour']:.1f} alerts/hour")
        print(f"📡 Status: {'🟢 ACTIVE' if stats['is_running'] else '🔴 STOPPED'}")
        print(f"{'='*40}\n")


def main():
    """Main function for standalone live monitoring"""
    
    import argparse
    
    parser = argparse.ArgumentParser(description="Live Firewall Log Monitor")
    parser.add_argument('--logfile', required=True, help='Log file to monitor')
    parser.add_argument('--parser', choices=['windows', 'pfsense'], required=True, help='Parser type')
    parser.add_argument('--interval', type=float, default=1.0, help='Check interval in seconds')
    
    args = parser.parse_args()
    
    # Create and start tailer
    tailer = LiveLogTailer(args.logfile, args.parser, check_interval=args.interval)
    
    if not tailer.start_monitoring():
        print("❌ Failed to start monitoring")
        return
    
    try:
        print("🔴 Live monitoring active. Press Ctrl+C to stop...")
        while True:
            time.sleep(10)
            tailer.print_status()
    except KeyboardInterrupt:
        print("\n🛑 Stopping live monitoring...")
        tailer.stop_monitoring()
        print("✅ Stopped")


if __name__ == "__main__":
    main()
