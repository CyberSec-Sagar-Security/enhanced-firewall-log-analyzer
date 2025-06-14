# 🔥 SOC Firewall Log Analyzer

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](VERSION)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()
[![Status](https://img.shields.io/badge/status-production-brightgreen.svg)]()
[![Security](https://img.shields.io/badge/security-offline-blue.svg)]()

A comprehensive, **100% offline** Python-based Security Operations Center (SOC) tool for analyzing firewall logs and detecting suspicious activity patterns. Built for cybersecurity professionals, SOC analysts, and security researchers.

## 🎯 Core Features

### ✅ WORKING FEATURES (Fully Operational)
- � Log file parsing - Windows Firewall CSV and pfSense formats
- � Detection logic - Known bad ports (135, 3389, 4444, etc.)
- � Frequency-based detection - Rapid connection patterns (5+ connections)
- 🌙 Off-hours anomaly detection - Suspicious activity outside business hours
- 🐚 Reverse shell detection - Backdoor patterns (ports 4444/5555)
- 🔔 Local alerting - Windows toast notifications with win10toast
- 🎨 Color-coded alerts - Professional SOC-style terminal output
- 📄 JSON export - Structured alert data for SIEM integration
- 📊 Excel reports - Automated spreadsheet generation
- 🌐 Fully offline operation - No internet required

### � ADVANCED FEATURES (Enhanced SOC Capabilities)
- 🔗 Correlation Engine - Multi-stage attack detection across IPs
- �️ MITRE ATT&CK Tagging - Automatic technique classification (T1059, T1110, etc.)
- � Live Log Monitoring - Real-time tail functionality
- � PDF Report Generation - Professional incident reports (optional)
- ⏰ Scheduled Analysis - Automated daily/weekly scans
- 🎯 GUI Dashboard - Streamlit web interface with interactive charts

## 🚀 Quick Start

### Installation

```powershell
# Navigate to project directory
cd "Firewall Logs Analyzer"

# Install dependencies
pip install -r requirements.txt
```

### 🎯 Feature Launcher (Recommended)

```powershell
# Launch interactive feature selector
python launcher.py
```

### 📊 Basic Analysis (Original)

```powershell
# Basic threat detection with table output and Excel export
python main.py --logfile test_logs/sample_windows_fw.csv --parser windows
```

### 🔥 Enhanced Analysis (Advanced SOC Features)

```powershell
# All features enabled - correlation, MITRE tagging, PDF reports
python enhanced_main.py --logfile test_logs/sample_windows_fw.csv --parser windows --correlation --mitre --pdf

# Live monitoring mode
python enhanced_main.py --live --logfile firewall.log --parser windows

# Scheduled analysis
python enhanced_main.py --schedule --config scheduler.json
```

### 🎯 GUI Dashboard

```powershell
# Launch interactive web dashboard
streamlit run gui/dashboard.py
```

## 📋 Requirements

### Core Dependencies
```
win10toast==0.9          # Windows notifications
colorama==0.4.6          # Terminal colors
loguru==0.7.2            # Advanced logging
openpyxl==3.1.2          # Excel export
pandas==2.1.3            # Data analysis
```

### Advanced Features (Optional)
```
streamlit==1.28.1        # GUI Dashboard
plotly==5.17.0           # Interactive charts
jinja2==3.1.2            # PDF templates
weasyprint==60.2         # PDF generation (requires system libraries)
schedule==1.2.0          # Task scheduling
```

Note: PDF generation requires additional system libraries on Windows. All other features work without WeasyPrint.

## 🛡️ Detection Capabilities

### 🔴 High-Risk Port Monitoring
```python
4444    # Metasploit reverse shell
31337   # Back Orifice backdoor  
3389    # RDP brute force
1433    # SQL Server attacks
445     # SMB exploitation
6667    # IRC botnet communication
135     # RPC exploitation
```

### 🔥 Multi-Stage Attack Detection
- Brute Force → Lateral Movement - Failed auth followed by successful connections
- Reconnaissance → Exploitation - Port scanning patterns leading to reverse shells
- Data Exfiltration Chains - Large transfers to multiple destinations
- C2 Communication - Regular beaconing patterns

### 🏷️ MITRE ATT&CK Integration
- T1059 - Command and Scripting Interpreter
- T1110.001 - Password Brute Force
- T1110.003 - Password Spraying  
- T1021.001 - Remote Desktop Protocol
- T1041 - Exfiltration Over C2 Channel
- T1105 - Ingress Tool Transfer

## 📊 Sample Output

### 🎨 Terminal Output
```
🔥 [HIGH] Reverse Shell Connection Detected
────────────────────────────────────────────────────────────
Description: Host 192.168.1.150 connected to known reverse shell port 4444
Timestamp: 2025-06-15T13:47:30
Source IP: 192.168.1.150
Destination IP: 94.237.67.81
Port: 4444 (Metasploit default)
MITRE ATT&CK: T1059 (Command and Scripting Interpreter)
Connections: 5
Recommendation: Immediately isolate 192.168.1.150 and investigate
────────────────────────────────────────────────────────────

🔗 [CRITICAL] Multi-Stage Attack Detected  
────────────────────────────────────────────────────────────
Correlation ID: CORR-2025-001
Source IP: 123.45.67.89
Attack Chain: Port Scan → Brute Force → Data Exfiltration
Time Window: 15 minutes
MITRE ATT&CK: T1595.001, T1110.001, T1041
Confidence: 95%
Recommendation: Block source IP and conduct full incident response
────────────────────────────────────────────────────────────
```

### 📊 Executive Summary
```
═══ THREAT DETECTION SUMMARY ═══
📊 Total Alerts: 68
🚨 By Severity:
   HIGH: 54 alerts
   MEDIUM: 14 alerts
🎯 MITRE Coverage: 30.9%
🔗 Correlations: 3 multi-stage attacks
📝 Reports: Excel, JSON, PDF (optional)
```

## 📁 Project Structure

```
📦 SOC Firewall Log Analyzer/
├── 📜 main.py                    # Core analyzer (original functionality)
├── 📜 enhanced_main.py           # Enhanced analyzer with advanced features
├── 📜 launcher.py                # Interactive feature launcher
├── 📜 requirements.txt           # Python dependencies
├── 📜 README.md                  # This comprehensive guide
│
├── 📂 parsers/                   # Log format parsers
│   ├── 📜 pfsense_parser.py      # pfSense log parser
│   └── 📜 windows_fw_parser.py   # Windows Firewall parser
│
├── 📂 detectors/                 # Threat detection modules
│   ├── 📜 suspicious_ports.py    # Port-based threat detection
│   ├── 📜 brute_force_detector.py # Brute force pattern detection
│   ├── 📜 exfiltration_detector.py # Data exfiltration detection
│   └── 📜 reverse_shell_detector.py # Backdoor/shell detection
│
├── 📂 alerts/                    # Alert and notification system
│   └── 📜 local_alert.py         # Color output + toast notifications
│
├── 📂 utils/                     # Utility modules and advanced features
│   ├── 📜 log_writer.py          # JSON log management
│   ├── 📜 time_utils.py          # Time-based analysis
│   ├── 📜 excel_export.py        # Excel report generation
│   ├── 📜 table_formatter.py     # Console table formatting
│   ├── 📜 correlation_engine.py  # Multi-stage attack correlation
│   ├── 📜 mitre_tagger.py        # MITRE ATT&CK technique tagging
│   ├── 📜 live_tailer.py         # Real-time log monitoring
│   ├── 📜 pdf_report.py          # PDF report generation
│   └── 📜 scheduler.py           # Automated task scheduling
│
├── 📂 gui/                       # Web dashboard interface
│   └── 📜 dashboard.py           # Streamlit GUI application
│
├── 📂 logs/                      # Output directory
│   ├── 📜 alert_output.json      # Structured alert data
│   └── 📜 analyzer.log           # Application logs
│
├── 📂 reports/                   # Generated reports
│   ├── 📜 firewall_alerts_*.xlsx # Excel reports
│   ├── 📜 mitre_tagged_*.json    # MITRE ATT&CK tagged alerts
│   └── 📜 incident_*.pdf         # PDF incident reports (optional)
│
└── 📂 test_logs/                 # Sample logs for testing
    ├── 📜 sample_pfsense.csv     # Sample pfSense logs
    └── 📜 sample_windows_fw.csv  # Sample Windows logs
```

## 🎯 Feature Usage Guide

### 1. 📊 Basic Analysis
Perfect for initial threat hunting and daily security monitoring.

```powershell
# Basic analysis with all core features
python main.py --logfile your_firewall.csv --parser windows

# Quiet mode (no notifications)
python main.py --logfile logs.csv --parser pfsense --quiet
```

Outputs:
- Color-coded terminal alerts
- Excel report in `reports/`
- JSON log in `logs/alert_output.json`
- Toast notifications (Windows)

### 2. 🔥 Enhanced Analysis
Full SOC capabilities with correlation and MITRE mapping.

```powershell
# Complete enhanced analysis
python enhanced_main.py --logfile firewall.log --parser windows --correlation --mitre

# Generate PDF report (requires WeasyPrint)
python enhanced_main.py --logfile logs.csv --parser windows --correlation --mitre --pdf
```

Outputs:
- All basic analysis outputs
- Correlated multi-stage attacks
- MITRE ATT&CK technique tags
- Enhanced Excel with correlation data
- PDF incident reports (optional)

### 3. 📡 Live Monitoring
Real-time threat detection for active log files.

```powershell
# Monitor active firewall log
python enhanced_main.py --live --logfile C:\Windows\System32\LogFiles\Firewall\pfirewall.log --parser windows

# Live monitoring with all features
python enhanced_main.py --live --logfile firewall.log --parser windows --correlation --mitre
```

Features:
- Real-time log tail functionality
- Immediate threat alerts
- Continuous correlation analysis
- Live MITRE technique tracking

### 4. ⏰ Scheduled Analysis
Automated daily/weekly security monitoring.

```powershell
# Start scheduler with default configuration
python enhanced_main.py --schedule

# Custom schedule configuration
python enhanced_main.py --schedule --config custom_schedule.json
```

Capabilities:
- Daily/weekly automated scans
- Email report delivery (configurable)
- Historical trend analysis
- Automated threat intelligence updates

### 5. 🎯 GUI Dashboard
Interactive web-based analysis and visualization.

```powershell
# Launch dashboard
streamlit run gui/dashboard.py
```

Features:
- Interactive alert timelines
- Threat trend visualizations
- Real-time monitoring dashboard
- Export capabilities (Excel, PDF, JSON)
- Filter and search functionality

## 🎯 Use Cases & Applications

### 🔍 SOC Analyst Training
- Threat Pattern Recognition - Learn to identify real attack signatures
- Incident Response Workflows - Practice investigation procedures
- MITRE ATT&CK Framework - Understand technique classification
- Alert Triage - Develop severity assessment skills

### 🛡️ Threat Hunting Operations
- Proactive Monitoring - Continuous security posture assessment
- Baseline Establishment - Normal vs. anomalous behavior patterns
- Advanced Persistent Threats - Multi-stage attack detection
- Insider Threat Detection - Off-hours and unusual activity patterns

### 🚨 Incident Response
- Rapid Threat Assessment - Quick identification of active threats
- Attack Timeline Recreation - Sequence of events analysis
- Evidence Collection - Structured data for forensic analysis
- Impact Assessment - Scope and severity determination

### 📋 Compliance & Auditing
- Security Monitoring Evidence - Documented threat detection
- Regulatory Reporting - Structured incident reports
- Risk Assessment - Quantified security posture metrics
- Executive Dashboards - High-level security status reporting

## 🔧 Advanced Configuration

### 📊 Custom Detection Rules
Create custom threat detection modules:

```python
# Example: Custom APT Detection
class APTDetector:
    def detect(self, log_entries):
        # Your custom detection logic
        suspicious_patterns = []
        for entry in log_entries:
            if self._is_apt_behavior(entry):
                suspicious_patterns.append(entry)
        return self._generate_alerts(suspicious_patterns)
```

### 🔗 Correlation Engine Tuning
Adjust correlation sensitivity and time windows:

```json
{
  "correlation_rules": {
    "brute_force_to_lateral": {
      "time_window": 1800,
      "threshold": 3,
      "severity": "HIGH"
    },
    "recon_to_exploitation": {
      "time_window": 3600,
      "threshold": 2,
      "severity": "CRITICAL"
    }
  }
}
```

### 🏷️ MITRE ATT&CK Customization
Add custom technique mappings:

```python
# Custom MITRE mappings
CUSTOM_MITRE_MAPPINGS = {
    "custom_backdoor": ["T1059.001", "T1543.003"],
    "lateral_movement": ["T1021.001", "T1021.002"],
    "data_staging": ["T1074.001", "T1074.002"]
}
```

### 📅 Scheduler Configuration
Setup automated analysis schedules:

```json
{
  "daily_scan": {
    "schedule": "08:00",
    "log_paths": ["/var/log/firewall/*.log"],
    "features": ["correlation", "mitre", "pdf"],
    "email_report": true
  },
  "weekly_summary": {
    "schedule": "monday 09:00", 
    "report_type": "executive",
    "recipients": ["soc@company.com"]
  }
}
```

## 📊 Output Formats & Integration

### 🔄 JSON API Format
```json
{
  "alert_id": "ALT-2025-001",
  "severity": "HIGH",
  "type": "REVERSE_SHELL",
  "timestamp": "2025-06-15T13:47:30Z",
  "source_ip": "192.168.1.150",
  "destination_ip": "94.237.67.81",
  "destination_port": 4444,
  "mitre_techniques": ["T1059"],
  "confidence": 0.95,
  "correlation_id": "CORR-2025-001",
  "recommendation": "Isolate host immediately"
}
```

### 📊 SIEM Integration
- Splunk - JSON logs compatible with Splunk Universal Forwarder  
- ELK Stack - Elasticsearch-ready JSON format
- QRadar - CEF format conversion available
- Sentinel - Azure Sentinel connector compatible

### 📑 Executive Reporting
- PDF Reports - Professional incident documentation
- Excel Dashboards - Pivot tables and charts
- PowerPoint - Executive briefing templates
- CSV Export - Custom analysis and reporting

## 🛠️ Development & Extensibility

### 🔌 Adding New Parsers
```python
class CustomFirewallParser:
    def parse_log_file(self, file_path):
        entries = []
        # Your parsing logic here
        return self._normalize_entries(entries)
    
    def _normalize_entries(self, raw_entries):
        # Convert to standard format
        return normalized_entries
```

### 🎯 Custom Detector Development
```python
class CustomThreatDetector:
    def __init__(self):
        self.name = "Custom Threat Detector"
        self.description = "Detects custom threat patterns"
    
    def detect(self, log_entries):
        alerts = []
        # Your detection algorithm
        return alerts
```

### 📈 Analytics Extensions
- Machine Learning - Anomaly detection models
- Statistical Analysis - Baseline deviation algorithms  
- Behavioral Analytics - User and entity behavior analysis
- Threat Intelligence - IOC enrichment and validation

## 🔒 Security & Privacy

### 🌐 Offline Operation
- Zero Cloud Dependencies - Complete air-gapped capability
- Local Processing Only - Logs never leave your environment
- No External APIs - No internet connectivity required
- Data Sovereignty - Full control over sensitive log data

### � Data Protection
- In-Memory Processing - Minimal disk writes
- Secure Log Handling - No sensitive data exposure
- Configurable Retention - Automated cleanup policies
- Access Control - File permission compliance

## 📞 Support & Community

### 📚 Documentation
- Code Comments - Extensive inline documentation
- Algorithm Details - Detection logic explanations
- Best Practices - SOC operational guidance
- Troubleshooting - Common issues and solutions

### 🤝 Contributing
This tool is designed for the cybersecurity community:
- Detection Algorithms - Contribute new threat patterns
- Parser Support - Add new log format parsers
- MITRE Mappings - Enhance technique classifications
- Performance Optimizations - Improve analysis speed

### 🎓 Educational Use
Perfect for:
- Cybersecurity Training - Hands-on threat detection
- Academic Research - Security analytics studies
- Certification Prep - SOC analyst skill development
- Red Team Exercises - Blue team response training

## ⚖️ License & Usage

Educational and Professional Use
- Built for SOC analysts and cybersecurity professionals
- Suitable for academic and training environments
- Commercial use in security operations centers
- Compliance with organizational security policies

---

🔥 Built for SOC Excellence - Detect, Analyze, Respond

🚀 Next-Generation Threat Detection Platform

Transform your security operations with comprehensive, offline-capable threat detection and analysis.
