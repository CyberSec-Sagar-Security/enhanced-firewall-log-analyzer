#!/usr/bin/env python3
"""
Integration tests for the main analyzer
"""

import pytest
import sys
import tempfile
import json
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from main import FirewallLogAnalyzer


class TestFirewallLogAnalyzer:
    """Integration tests for FirewallLogAnalyzer."""
    
    def test_analyzer_initialization(self):
        """Test that analyzer initializes correctly."""
        analyzer = FirewallLogAnalyzer()
        assert analyzer is not None
        assert hasattr(analyzer, 'parsers')
        assert hasattr(analyzer, 'detectors')
    
    def test_analyze_sample_windows_log(self, test_config):
        """Test analysis of sample Windows firewall log."""
        analyzer = FirewallLogAnalyzer()
        
        # Use sample log file
        log_file = test_config['test_data_dir'] / 'sample_windows_fw.csv'
        
        if log_file.exists():
            results = analyzer.analyze_log_file(str(log_file), 'windows')
            
            assert results is not None
            assert 'alerts' in results
            assert isinstance(results['alerts'], list)
            assert len(results['alerts']) > 0
    
    def test_analyze_sample_pfsense_log(self, test_config):
        """Test analysis of sample pfSense log."""
        analyzer = FirewallLogAnalyzer()
        
        # Use sample log file
        log_file = test_config['test_data_dir'] / 'sample_pfsense.csv'
        
        if log_file.exists():
            results = analyzer.analyze_log_file(str(log_file), 'pfsense')
            
            assert results is not None
            assert 'alerts' in results
            assert isinstance(results['alerts'], list)
    
    def test_invalid_parser_type(self):
        """Test handling of invalid parser type."""
        analyzer = FirewallLogAnalyzer()
        
        with pytest.raises(ValueError):
            analyzer.analyze_log_file('nonexistent.csv', 'invalid_parser')
    
    def test_nonexistent_file(self):
        """Test handling of nonexistent log file."""
        analyzer = FirewallLogAnalyzer()
        
        with pytest.raises(FileNotFoundError):
            analyzer.analyze_log_file('nonexistent.csv', 'windows')
    
    @pytest.mark.slow
    def test_large_log_performance(self, test_config):
        """Test performance with larger log files."""
        analyzer = FirewallLogAnalyzer()
        
        # Create a temporary large log file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            # Write CSV header
            f.write("Date,Time,Action,Protocol,Source IP,Source Port,Destination IP,Destination Port,Size,Application,Direction\n")
            
            # Generate 1000 log entries
            for i in range(1000):
                f.write(f"2025-06-15,14:25:{i % 60:02d},BLOCK,TCP,192.168.1.{i % 254 + 1},4444,10.0.0.1,135,64,System,Inbound\n")
        
        try:
            results = analyzer.analyze_log_file(f.name, 'windows')
            
            assert results is not None
            assert 'alerts' in results
            assert len(results['alerts']) > 0
            
        finally:
            Path(f.name).unlink()  # Clean up temp file
