# Contributing to SOC Firewall Log Analyzer

Thank you for your interest in contributing to the SOC Firewall Log Analyzer! This document provides guidelines for contributing to this cybersecurity project.

## 🛡️ Code of Conduct

### Security First
- All contributions must prioritize security and responsible disclosure
- Never include real sensitive data in examples or tests
- Follow secure coding practices
- Report security vulnerabilities privately via GitHub Security Advisories

### Professional Standards
- Be respectful and professional in all interactions
- Focus on constructive feedback and improvements
- Maintain high code quality standards
- Document your changes thoroughly

## 🚀 Getting Started

### Prerequisites
- Python 3.8 or higher
- Git
- Basic understanding of cybersecurity concepts
- Familiarity with firewall logs and SIEM systems

### Development Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/soc-firewall-analyzer.git
cd soc-firewall-analyzer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -e .[dev]

# Install pre-commit hooks
pre-commit install
```

## 📝 How to Contribute

### 1. Feature Requests
- Check existing issues first
- Use the feature request template
- Provide clear use cases and security benefits
- Include example firewall log scenarios

### 2. Bug Reports
- Use the bug report template
- Include steps to reproduce
- Provide log files and error messages (sanitized)
- Specify your environment (OS, Python version)

### 3. Code Contributions

#### Branch Naming
- `feature/description` - New features
- `bugfix/description` - Bug fixes
- `security/description` - Security improvements
- `docs/description` - Documentation updates

#### Pull Request Process
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add/update tests
5. Update documentation
6. Ensure all tests pass
7. Submit pull request

### 4. Documentation
- Update README.md for user-facing changes
- Add docstrings for new functions/classes
- Include usage examples
- Update CHANGELOG.md

## 🧪 Testing Guidelines

### Test Categories
```bash
# Unit tests
pytest tests/unit/

# Integration tests
pytest tests/integration/

# Security tests
pytest tests/security/

# End-to-end tests
pytest tests/e2e/
```

### Test Requirements
- All new features must include tests
- Maintain >80% code coverage
- Include both positive and negative test cases
- Test edge cases and error conditions
- Use sanitized test data only

### Sample Test Structure
```python
def test_suspicious_port_detection():
    """Test detection of connections to suspicious ports."""
    # Arrange
    test_logs = create_test_log_entries()
    detector = SuspiciousPortDetector()
    
    # Act
    alerts = detector.detect(test_logs)
    
    # Assert
    assert len(alerts) > 0
    assert alerts[0]['severity'] == 'HIGH'
    assert 'port' in alerts[0]
```

## 🔒 Security Guidelines

### Sensitive Data
- Never commit real IP addresses, hostnames, or user data
- Use anonymized test data (192.168.x.x, example.com)
- Sanitize all log examples
- Use placeholder values in documentation

### Code Security
- Validate all inputs
- Use parameterized queries
- Avoid shell injection vulnerabilities
- Follow OWASP secure coding practices
- Implement proper error handling

### Dependencies
- Regularly update dependencies
- Monitor for security advisories
- Use virtual environments
- Pin dependency versions in requirements.txt

## 📋 Coding Standards

### Python Style
```python
# Use Black formatter
black --line-length 88 .

# Follow PEP 8
flake8 .

# Type hints
mypy --strict .
```

### Documentation Style
```python
def detect_threats(log_entries: List[Dict]) -> List[Alert]:
    """
    Detect security threats in firewall log entries.
    
    Args:
        log_entries: List of normalized log entry dictionaries
        
    Returns:
        List of Alert objects containing threat information
        
    Raises:
        ValueError: If log_entries is empty or malformed
        
    Example:
        >>> detector = ThreatDetector()
        >>> alerts = detector.detect_threats(sample_logs)
        >>> print(f"Found {len(alerts)} threats")
    """
```

### Commit Messages
```
type(scope): description

feat(detection): add new reverse shell detection algorithm
fix(parser): handle malformed CSV headers correctly  
docs(readme): update installation instructions
security(auth): validate user input in API endpoints
test(integration): add MITRE ATT&CK tagging tests
```

## 🎯 Contribution Areas

### High Priority
- **New Detection Algorithms**: Additional threat patterns
- **Parser Support**: New firewall/SIEM log formats  
- **MITRE ATT&CK**: Extended technique mappings
- **Performance**: Optimization for large log files
- **Documentation**: Usage examples and tutorials

### Medium Priority
- **GUI Enhancements**: Dashboard improvements
- **Reporting**: Additional output formats
- **Integration**: SIEM/SOAR connectors
- **Internationalization**: Multi-language support

### Expert Level
- **Machine Learning**: Anomaly detection models
- **Threat Intelligence**: IOC enrichment
- **Real-time Processing**: Stream processing capabilities
- **Cloud Integration**: AWS/Azure/GCP support

## 🏗️ Project Structure

```
soc-firewall-analyzer/
├── alerts/           # Alert handling and notifications
├── detectors/        # Threat detection algorithms  
├── parsers/          # Log format parsers
├── utils/            # Utility modules and helpers
├── gui/              # Streamlit dashboard
├── tests/            # Test suites
├── docs/             # Documentation
├── examples/         # Usage examples
└── scripts/          # Utility scripts
```

## 📚 Resources

### Cybersecurity References
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SANS Reading Room](https://www.sans.org/reading-room/)

### Development Resources
- [Python Security Best Practices](https://python-security.readthedocs.io/)
- [Secure Coding Guidelines](https://wiki.sei.cmu.edu/confluence/display/seccode)
- [Git Security](https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work)

## 🤝 Community

### Communication Channels
- GitHub Issues: Bug reports and feature requests
- GitHub Discussions: General questions and ideas
- Security Issues: Use GitHub Security Advisories

### Recognition
Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation
- Special recognition for security improvements

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

**Remember**: This is a security tool. Always prioritize responsible disclosure and ethical use. Your contributions help make the cybersecurity community stronger! 🛡️
