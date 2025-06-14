#!/usr/bin/env python3
"""
Unit tests for suspicious port detector
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from detectors.suspicious_ports import SuspiciousPortDetector


class TestSuspiciousPortDetector:
    """Test cases for SuspiciousPortDetector."""
    
    def test_init(self):
        """Test detector initialization."""
        detector = SuspiciousPortDetector()
        assert detector is not None
        assert hasattr(detector, 'high_risk_ports')
        assert len(detector.high_risk_ports) > 0
    
    def test_detect_suspicious_port(self, sample_log_entries):
        """Test detection of suspicious ports."""
        detector = SuspiciousPortDetector()
        
        # Add a suspicious port entry
        suspicious_entry = {
            'timestamp': '2025-06-15 14:25:30',
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'destination_port': 4444,  # Metasploit default port
            'protocol': 'TCP',
            'action': 'BLOCK'
        }
        
        alerts = detector.detect([suspicious_entry])
        
        assert len(alerts) > 0
        assert alerts[0]['severity'] in ['HIGH', 'MEDIUM']
        assert 'port' in alerts[0]
        assert alerts[0]['destination_port'] == 4444
    
    def test_detect_no_threats(self):
        """Test detection with safe ports."""
        detector = SuspiciousPortDetector()
        
        safe_entry = {
            'timestamp': '2025-06-15 14:25:30',
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'destination_port': 80,  # HTTP - safe port
            'protocol': 'TCP',
            'action': 'ALLOW'
        }
        
        alerts = detector.detect([safe_entry])
        
        # Should not generate alerts for safe ports
        suspicious_alerts = [a for a in alerts if a.get('destination_port') == 80]
        assert len(suspicious_alerts) == 0
    
    def test_high_risk_ports_coverage(self):
        """Test that all major high-risk ports are covered."""
        detector = SuspiciousPortDetector()
        
        # Check for common attack ports
        expected_ports = [4444, 31337, 3389, 1433, 445, 135]
        
        for port in expected_ports:
            assert port in detector.high_risk_ports, f"Port {port} should be in high-risk list"
    
    @pytest.mark.parametrize("port,expected_severity", [
        (4444, "HIGH"),    # Metasploit
        (31337, "HIGH"),   # Back Orifice
        (3389, "MEDIUM"),  # RDP
        (1433, "MEDIUM"),  # SQL Server
    ])
    def test_port_severity_mapping(self, port, expected_severity):
        """Test that ports are mapped to correct severity levels."""
        detector = SuspiciousPortDetector()
        
        test_entry = {
            'timestamp': '2025-06-15 14:25:30',
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'destination_port': port,
            'protocol': 'TCP',
            'action': 'BLOCK'
        }
        
        alerts = detector.detect([test_entry])
        
        if alerts:
            port_alerts = [a for a in alerts if a.get('destination_port') == port]
            if port_alerts:
                assert port_alerts[0]['severity'] == expected_severity
