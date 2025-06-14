#!/usr/bin/env python3
"""
Test suite for SOC Firewall Log Analyzer
"""

import pytest
import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Test configuration
pytest_plugins = []

def pytest_configure(config):
    """Configure pytest with custom markers and settings."""
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "security: marks tests as security tests"
    )
    config.addinivalue_line(
        "markers", "slow: marks tests as slow running"
    )

@pytest.fixture
def sample_log_entries():
    """Sample log entries for testing."""
    return [
        {
            'timestamp': '2025-06-15 14:25:30',
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'destination_port': 4444,
            'protocol': 'TCP',
            'action': 'BLOCK'
        },
        {
            'timestamp': '2025-06-15 14:25:35',
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'destination_port': 22,
            'protocol': 'TCP',
            'action': 'ALLOW'
        }
    ]

@pytest.fixture
def test_config():
    """Test configuration settings."""
    return {
        'test_data_dir': project_root / 'test_logs',
        'output_dir': project_root / 'test_output',
        'quiet_mode': True
    }
