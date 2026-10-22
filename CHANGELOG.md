# Changelog

All notable changes to the SOC Firewall Log Analyzer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Full rebuild as 3.0.0. Scope, milestones and boundaries are in `docs/SCOPE.md`; security requirements are in `docs/THREAT_MODEL.md`.

### Removed
- Dead, duplicated or out-of-scope files: `enhanced_main.py`, `launcher.py`, `deploy_to_github.py`, `gui/dashboard.py` (Streamlit), `utils/excel_report.py`, `utils/time_utils.py`, `setup.py`, `MANIFEST.in`, `DEPLOYMENT.md`, `test_logs/clean_windows_fw.csv`.
- Broken CI workflow (Python 3.8, deprecated `upload-artifact@v3`, steps referencing removed scripts). New CI arrives in rebuild milestone M0.
- `streamlit` and `plotly` from `requirements.txt`.

### Changed
- README now describes the rebuild and the known defects in the legacy code, replacing the old feature claims.

## [2.0.0] - 2025-06-15

### 🚀 Major Release - Enhanced SOC Edition

#### Added
- **MITRE ATT&CK Integration**: Automatic mapping of detected threats to MITRE framework
- **Correlation Engine**: Multi-stage attack detection across time windows and IPs
- **Live Log Monitoring**: Real-time log file tailing and analysis
- **PDF Report Generation**: Professional incident reports with charts and visualizations
- **Streamlit GUI Dashboard**: Interactive web-based interface with real-time charts
- **Automated Scheduling**: Task scheduler for daily/weekly automated analysis
- **Enhanced Excel Reports**: Multi-sheet reports with pivot tables and charts
- **Interactive Launcher**: User-friendly feature selection and guided workflows

#### Enhanced Detection Capabilities
- **Advanced Port Analysis**: Extended suspicious port database with 20+ high-risk ports
- **Brute Force Detection**: Multi-vector attack pattern recognition
- **Data Exfiltration Detection**: Large transfer and C2 communication patterns
- **Reverse Shell Detection**: Backdoor and persistent connection identification
- **Off-hours Analysis**: Time-based anomaly detection for after-hours activity

#### Technical Improvements
- **Modular Architecture**: Clean separation of concerns across components
- **Error Handling**: Comprehensive exception handling and graceful degradation
- **Performance Optimization**: Efficient processing for large log files
- **Cross-platform Support**: Windows, Linux, and macOS compatibility
- **Type Hints**: Complete type annotation for better code maintainability

#### Security Enhancements
- **Input Validation**: Robust validation of all log file inputs
- **Safe File Handling**: Secure processing of potentially malicious log data
- **Memory Management**: Optimized memory usage for large datasets
- **Offline Operation**: Complete air-gapped capability with no external dependencies

### Changed
- **Configuration System**: JSON-based configuration for all components
- **Logging Framework**: Migration to loguru for enhanced logging capabilities
- **Output Formats**: Standardized JSON schema for all alert outputs
- **CLI Interface**: Enhanced command-line interface with comprehensive options
- **Documentation**: Complete rewrite with detailed usage examples and tutorials

### Fixed
- **CSV Parser Robustness**: Improved handling of malformed CSV files
- **Windows Compatibility**: Fixed Windows-specific path and notification issues
- **Memory Leaks**: Resolved memory issues in long-running processes
- **Thread Safety**: Fixed race conditions in multi-threaded operations

### Security
- **Dependency Updates**: Updated all dependencies to latest secure versions
- **Code Scanning**: Integrated security scanning in CI/CD pipeline
- **Vulnerability Assessment**: Regular security audits and penetration testing

## [1.0.0] - 2025-06-10

### 🎉 Initial Release

#### Core Features
- **Multi-format Log Parsing**: Support for Windows Firewall and pfSense logs
- **Threat Detection**: Basic suspicious port and connection pattern detection
- **Color-coded Alerts**: Professional SOC-style terminal output
- **Toast Notifications**: Windows desktop notifications for immediate alerts
- **JSON Export**: Structured alert data for SIEM integration
- **Excel Reports**: Automated spreadsheet generation for analysis

#### Detection Modules
- **Suspicious Port Detector**: Identification of connections to high-risk ports
- **Brute Force Detector**: Detection of repeated failed authentication attempts
- **Connection Analyzer**: Statistical analysis of connection patterns

#### Supported Formats
- Windows Defender Firewall CSV exports
- pfSense firewall log exports
- Generic CSV log formats

#### Platform Support
- Windows 10/11 (Primary)
- Python 3.8+ compatibility
- Offline operation capability

---

## Upcoming Features (Roadmap)

### v2.1.0 - Advanced Analytics
- [ ] Machine Learning anomaly detection
- [ ] Behavioral analytics engine
- [ ] Advanced statistical analysis
- [ ] Threat intelligence integration

### v2.2.0 - Enterprise Features
- [ ] SIEM connector APIs
- [ ] Multi-tenant support
- [ ] Role-based access control
- [ ] Audit logging

### v3.0.0 - Cloud & Scale
- [ ] Cloud deployment options
- [ ] Distributed processing
- [ ] Big data integration
- [ ] Advanced visualization

---

## Migration Guides

### From v1.x to v2.x
- **Configuration**: Update configuration files to new JSON format
- **CLI Arguments**: Review command-line options (some have changed)
- **Output Format**: JSON schema has been enhanced with additional fields
- **Dependencies**: Run `pip install -r requirements.txt` to update packages

### Breaking Changes in v2.0
- Removed deprecated `--legacy-output` option
- Changed alert severity levels (LOW/MEDIUM/HIGH/CRITICAL)
- Updated MITRE ATT&CK technique IDs to latest framework
- Restructured project directories

---

## Support

For questions about changes or migration:
- 📖 [Documentation](README.md)
- 🐛 [Issues](https://github.com/yourusername/soc-firewall-analyzer/issues)
- 💬 [Discussions](https://github.com/yourusername/soc-firewall-analyzer/discussions)

## Contributors

Thanks to all contributors who made this release possible! See [CONTRIBUTORS.md](CONTRIBUTORS.md) for the full list.
