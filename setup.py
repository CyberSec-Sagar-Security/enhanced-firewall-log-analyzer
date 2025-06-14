#!/usr/bin/env python3
"""
Setup script for SOC Firewall Log Analyzer
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

# Read requirements
requirements = []
try:
    with open('requirements.txt', 'r', encoding='utf-8') as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]
except FileNotFoundError:
    pass

setup(    name="soc-firewall-analyzer",
    version="2.0.0",
    author="SOC Team",
    author_email="",
    description="Advanced SOC Firewall Log Analyzer with MITRE ATT&CK integration",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/CyberSec-Sagar-Security/soc-firewall-analyzer",  # Update this with your GitHub username
    project_urls={
        "Bug Reports": "https://github.com/CyberSec-Sagar-Security/soc-firewall-analyzer/issues",
        "Documentation": "https://github.com/CyberSec-Sagar-Security/soc-firewall-analyzer#readme",
        "Source": "https://github.com/CyberSec-Sagar-Security/soc-firewall-analyzer",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Environment :: Web Environment",
    ],
    python_requires=">=3.8",
    install_requires=[
        "colorama>=0.4.6",
        "loguru>=0.7.2",
        "openpyxl>=3.1.2",
        "pandas>=2.1.3",
    ],
    extras_require={
        "full": requirements,
        "gui": [
            "streamlit>=1.28.1",
            "plotly>=5.17.0",
        ],
        "pdf": [
            "jinja2>=3.1.2",
            "weasyprint>=60.2",
        ],
        "notifications": [
            "win10toast>=0.9",
        ],
        "scheduling": [
            "schedule>=1.2.0",
        ],
        "dev": [
            "pytest>=7.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "soc-analyzer=main:main",
            "soc-analyzer-enhanced=enhanced_main:main",
            "soc-analyzer-launcher=launcher:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.csv", "*.md", "*.txt", "*.json"],
        "test_logs": ["*.csv"],
        "templates": ["*.html", "*.css"],
    },
    project_urls={
        "Bug Reports": "https://github.com/yourusername/soc-firewall-analyzer/issues",
        "Source": "https://github.com/yourusername/soc-firewall-analyzer",
        "Documentation": "https://github.com/yourusername/soc-firewall-analyzer/blob/main/README.md",
    },
    keywords=[
        "security", "firewall", "logs", "soc", "cybersecurity", 
        "threat-detection", "mitre-attack", "incident-response",
        "network-security", "log-analysis", "threat-hunting"
    ],
)
