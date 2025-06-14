#!/usr/bin/env python3
"""
MITRE ATT&CK Tagging System for SOC Firewall Log Analyzer
Maps detected threats to MITRE ATT&CK framework tactics and techniques
Author: SOC Team
"""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, asdict
from loguru import logger


@dataclass
class MitreTag:
    """Represents a MITRE ATT&CK tag"""
    technique_id: str
    technique_name: str
    tactic: str
    sub_technique: Optional[str] = None
    confidence: float = 1.0
    description: str = ""
    url: str = ""


@dataclass
class TaggedAlert:
    """Alert with MITRE ATT&CK tags"""
    original_alert: Dict
    mitre_tags: List[MitreTag]
    primary_tactic: str
    attack_pattern: str
    severity_adjusted: str


class MitreAttackTagger:
    """MITRE ATT&CK framework tagger for security alerts"""
    
    def __init__(self, custom_mappings_file: Optional[str] = None):
        """
        Initialize MITRE ATT&CK tagger
        
        Args:
            custom_mappings_file: Path to custom technique mappings
        """
        self.technique_mappings = self._load_technique_mappings()
        self.custom_mappings = self._load_custom_mappings(custom_mappings_file)
        
        # Combine mappings
        self.all_mappings = {**self.technique_mappings, **self.custom_mappings}
        
        logger.add("logs/mitre_tagger.log", rotation="10 MB")
        logger.info(f"MITRE ATT&CK tagger initialized with {len(self.all_mappings)} mappings")
    
    def tag_alerts(self, alerts: List[Dict]) -> List[TaggedAlert]:
        """
        Tag alerts with MITRE ATT&CK techniques
        
        Args:
            alerts: List of alert dictionaries
            
        Returns:
            List of tagged alerts
        """
        
        if not alerts:
            return []
        
        logger.info(f"Tagging {len(alerts)} alerts with MITRE ATT&CK techniques")
        
        tagged_alerts = []
        
        for alert in alerts:
            tags = self._identify_techniques(alert)
            
            if tags:
                # Determine primary tactic and attack pattern
                primary_tactic = self._get_primary_tactic(tags)
                attack_pattern = self._classify_attack_pattern(tags, alert)
                
                # Adjust severity based on MITRE classification
                adjusted_severity = self._adjust_severity(alert, tags)
                
                tagged_alert = TaggedAlert(
                    original_alert=alert,
                    mitre_tags=tags,
                    primary_tactic=primary_tactic,
                    attack_pattern=attack_pattern,
                    severity_adjusted=adjusted_severity
                )
                
                tagged_alerts.append(tagged_alert)
                
                logger.debug(f"Tagged alert {alert.get('title', 'Unknown')} with {len(tags)} techniques")
            else:
                # Create tagged alert with no MITRE tags
                tagged_alert = TaggedAlert(
                    original_alert=alert,
                    mitre_tags=[],
                    primary_tactic="Unknown",
                    attack_pattern="Unclassified",
                    severity_adjusted=alert.get('severity', 'Medium')
                )
                
                tagged_alerts.append(tagged_alert)
        
        logger.info(f"Successfully tagged {len(tagged_alerts)} alerts")
        
        return tagged_alerts
    
    def _load_technique_mappings(self) -> Dict[str, List[MitreTag]]:
        """Load default MITRE ATT&CK technique mappings"""
        
        # Comprehensive mapping of common security alerts to MITRE techniques
        mappings = {
            # Reconnaissance (TA0043)
            'port_scan': [
                MitreTag(
                    technique_id='T1595.001',
                    technique_name='Scanning IP Blocks',
                    tactic='Reconnaissance',
                    description='Adversaries may scan victim IP blocks to gather information',
                    url='https://attack.mitre.org/techniques/T1595/001/'
                )
            ],
            'service_scan': [
                MitreTag(
                    technique_id='T1595.002',
                    technique_name='Vulnerability Scanning',
                    tactic='Reconnaissance',
                    description='Adversaries may scan victims for vulnerabilities',
                    url='https://attack.mitre.org/techniques/T1595/002/'
                )
            ],
            'network_scan': [
                MitreTag(
                    technique_id='T1595',
                    technique_name='Active Scanning',
                    tactic='Reconnaissance',
                    description='Adversaries may execute active reconnaissance scans',
                    url='https://attack.mitre.org/techniques/T1595/'
                )
            ],
            
            # Initial Access (TA0001)
            'brute_force': [
                MitreTag(
                    technique_id='T1110.001',
                    technique_name='Password Guessing',
                    tactic='Credential Access',
                    description='Adversaries may use password guessing to obtain credentials',
                    url='https://attack.mitre.org/techniques/T1110/001/'
                ),
                MitreTag(
                    technique_id='T1110.003',
                    technique_name='Password Spraying',
                    tactic='Credential Access',
                    description='Adversaries may use password spraying attacks',
                    url='https://attack.mitre.org/techniques/T1110/003/'
                )
            ],
            'rdp_brute_force': [
                MitreTag(
                    technique_id='T1021.001',
                    technique_name='Remote Desktop Protocol',
                    tactic='Lateral Movement',
                    description='Adversaries may use RDP to laterally move',
                    url='https://attack.mitre.org/techniques/T1021/001/'
                ),
                MitreTag(
                    technique_id='T1110',
                    technique_name='Brute Force',
                    tactic='Credential Access',
                    description='Adversaries may use brute force techniques',
                    url='https://attack.mitre.org/techniques/T1110/'
                )
            ],
            'ssh_brute_force': [
                MitreTag(
                    technique_id='T1021.004',
                    technique_name='SSH',
                    tactic='Lateral Movement',
                    description='Adversaries may use SSH for lateral movement',
                    url='https://attack.mitre.org/techniques/T1021/004/'
                ),
                MitreTag(
                    technique_id='T1110',
                    technique_name='Brute Force',
                    tactic='Credential Access',
                    description='Adversaries may use brute force techniques',
                    url='https://attack.mitre.org/techniques/T1110/'
                )
            ],
            
            # Execution (TA0002)
            'reverse_shell': [
                MitreTag(
                    technique_id='T1059',
                    technique_name='Command and Scripting Interpreter',
                    tactic='Execution',
                    description='Adversaries may abuse command interpreters',
                    url='https://attack.mitre.org/techniques/T1059/'
                )
            ],
            'powershell': [
                MitreTag(
                    technique_id='T1059.001',
                    technique_name='PowerShell',
                    tactic='Execution',  
                    description='Adversaries may abuse PowerShell commands',
                    url='https://attack.mitre.org/techniques/T1059/001/'
                )
            ],
            'cmd_execution': [
                MitreTag(
                    technique_id='T1059.003',
                    technique_name='Windows Command Shell',
                    tactic='Execution',
                    description='Adversaries may abuse Windows command shell',
                    url='https://attack.mitre.org/techniques/T1059/003/'
                )
            ],
            
            # Persistence (TA0003)
            'backdoor': [
                MitreTag(
                    technique_id='T1543',
                    technique_name='Create or Modify System Process',
                    tactic='Persistence',
                    description='Adversaries may create or modify system processes',
                    url='https://attack.mitre.org/techniques/T1543/'
                )
            ],
            
            # Defense Evasion (TA0005)
            'obfuscation': [
                MitreTag(
                    technique_id='T1027',
                    technique_name='Obfuscated Files or Information',
                    tactic='Defense Evasion',
                    description='Adversaries may attempt to make files undetectable',
                    url='https://attack.mitre.org/techniques/T1027/'
                )
            ],
            'encoding': [
                MitreTag(
                    technique_id='T1027.010',
                    technique_name='Command Obfuscation',
                    tactic='Defense Evasion',
                    description='Adversaries may obfuscate commands to avoid detection',
                    url='https://attack.mitre.org/techniques/T1027/010/'
                )
            ],
            
            # Credential Access (TA0006)
            'credential_dump': [
                MitreTag(
                    technique_id='T1003',
                    technique_name='OS Credential Dumping',
                    tactic='Credential Access',
                    description='Adversaries may dump credentials from OS credential stores',
                    url='https://attack.mitre.org/techniques/T1003/'
                )
            ],
            
            # Collection (TA0009)
            'data_collection': [
                MitreTag(
                    technique_id='T1005',
                    technique_name='Data from Local System',
                    tactic='Collection',
                    description='Adversaries may search local system for data',
                    url='https://attack.mitre.org/techniques/T1005/'
                )
            ],
            
            # Exfiltration (TA0010)
            'data_exfiltration': [
                MitreTag(
                    technique_id='T1041',
                    technique_name='Exfiltration Over C2 Channel',
                    tactic='Exfiltration',
                    description='Adversaries may steal data over C2 channel',
                    url='https://attack.mitre.org/techniques/T1041/'
                )
            ],
            'dns_exfiltration': [
                MitreTag(
                    technique_id='T1048.003',
                    technique_name='Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol',
                    tactic='Exfiltration',
                    sub_technique='DNS',
                    description='Adversaries may steal data over DNS',
                    url='https://attack.mitre.org/techniques/T1048/003/'
                )
            ],
            'http_exfiltration': [
                MitreTag(
                    technique_id='T1048.003',
                    technique_name='Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol',
                    tactic='Exfiltration',
                    sub_technique='HTTP/HTTPS',
                    description='Adversaries may steal data over HTTP/HTTPS',
                    url='https://attack.mitre.org/techniques/T1048/003/'
                )
            ],
            
            # Command and Control (TA0011)
            'c2_communication': [
                MitreTag(
                    technique_id='T1071',
                    technique_name='Application Layer Protocol',
                    tactic='Command and Control',
                    description='Adversaries may communicate using application layer protocols',
                    url='https://attack.mitre.org/techniques/T1071/'
                )
            ],
            'encrypted_channel': [
                MitreTag(
                    technique_id='T1573',
                    technique_name='Encrypted Channel',
                    tactic='Command and Control',
                    description='Adversaries may employ encrypted channels',
                    url='https://attack.mitre.org/techniques/T1573/'
                )
            ],
            
            # Impact (TA0040)
            'dos_attack': [
                MitreTag(
                    technique_id='T1499',
                    technique_name='Endpoint Denial of Service',
                    tactic='Impact',
                    description='Adversaries may perform DoS attacks',
                    url='https://attack.mitre.org/techniques/T1499/'
                )
            ],
            'resource_hijacking': [
                MitreTag(
                    technique_id='T1496',
                    technique_name='Resource Hijacking',
                    tactic='Impact',
                    description='Adversaries may leverage resources for cryptocurrency mining',
                    url='https://attack.mitre.org/techniques/T1496/'
                )
            ]
        }
        
        return mappings
    
    def _load_custom_mappings(self, custom_file: Optional[str]) -> Dict[str, List[MitreTag]]:
        """Load custom MITRE technique mappings from file"""
        
        if not custom_file or not Path(custom_file).exists():
            return {}
        
        try:
            with open(custom_file, 'r') as f:
                custom_data = json.load(f)
            
            custom_mappings = {}
            
            for pattern, techniques in custom_data.items():
                tags = []
                for tech_data in techniques:
                    tag = MitreTag(**tech_data)
                    tags.append(tag)
                
                custom_mappings[pattern] = tags
            
            logger.info(f"Loaded {len(custom_mappings)} custom MITRE mappings")
            return custom_mappings
            
        except Exception as e:
            logger.error(f"Error loading custom MITRE mappings: {e}")
            return {}
    
    def _identify_techniques(self, alert: Dict) -> List[MitreTag]:
        """Identify MITRE techniques for an alert"""
        
        techniques = []
        
        # Get alert properties for analysis
        title = alert.get('title', '').lower()
        description = alert.get('description', '').lower()
        alert_type = alert.get('alert_type', '').lower()
        
        # Combine text for pattern matching
        full_text = f"{title} {description} {alert_type}"
        
        # Check each mapping pattern
        for pattern, tags in self.all_mappings.items():
            if self._matches_pattern(pattern, full_text, alert):
                # Calculate confidence based on match quality
                confidence = self._calculate_confidence(pattern, full_text, alert)
                
                # Add tags with adjusted confidence
                for tag in tags:
                    adjusted_tag = MitreTag(
                        technique_id=tag.technique_id,
                        technique_name=tag.technique_name,
                        tactic=tag.tactic,
                        sub_technique=tag.sub_technique,
                        confidence=confidence,
                        description=tag.description,
                        url=tag.url
                    )
                    techniques.append(adjusted_tag)
        
        # Remove duplicates and sort by confidence
        unique_techniques = self._deduplicate_techniques(techniques)
        
        return sorted(unique_techniques, key=lambda t: t.confidence, reverse=True)
    
    def _matches_pattern(self, pattern: str, text: str, alert: Dict) -> bool:
        """Check if alert matches a MITRE technique pattern"""
        
        # Direct keyword matching
        if pattern.replace('_', ' ') in text:
            return True
        
        # Specific pattern matching based on alert context
        if pattern == 'port_scan':
            return any(keyword in text for keyword in ['port scan', 'scanning', 'probe', 'reconnaissance'])
        
        elif pattern == 'brute_force':
            return any(keyword in text for keyword in ['brute force', 'brute-force', 'password attack', 'multiple attempts'])
        
        elif pattern == 'rdp_brute_force':
            return ('rdp' in text or '3389' in str(alert.get('destination_port', ''))) and \
                   any(keyword in text for keyword in ['brute', 'force', 'attempt'])
        
        elif pattern == 'ssh_brute_force':
            return ('ssh' in text or '22' in str(alert.get('destination_port', ''))) and \
                   any(keyword in text for keyword in ['brute', 'force', 'attempt'])
        
        elif pattern == 'reverse_shell':
            return any(keyword in text for keyword in ['reverse shell', 'shell', 'backdoor', 'remote access'])
        
        elif pattern == 'data_exfiltration':
            return any(keyword in text for keyword in ['exfiltration', 'data transfer', 'large upload', 'suspicious traffic'])
        
        elif pattern == 'dns_exfiltration':
            return ('dns' in text or '53' in str(alert.get('destination_port', ''))) and \
                   any(keyword in text for keyword in ['exfiltration', 'suspicious', 'large'])
        
        elif pattern == 'c2_communication':
            return any(keyword in text for keyword in ['command control', 'c2', 'beacon', 'callback'])
        
        # Default fuzzy matching
        pattern_words = pattern.replace('_', ' ').split()
        return all(word in text for word in pattern_words)
    
    def _calculate_confidence(self, pattern: str, text: str, alert: Dict) -> float:
        """Calculate confidence score for technique match"""
        
        base_confidence = 0.7
        
        # Increase confidence for exact matches
        if pattern.replace('_', ' ') in text:
            base_confidence += 0.2
        
        # Adjust based on alert severity
        severity = alert.get('severity', 'Medium')
        if severity == 'Critical':
            base_confidence += 0.1
        elif severity == 'High':
            base_confidence += 0.05
        
        # Adjust based on additional context
        if alert.get('source_ip') and alert.get('destination_port'):
            base_confidence += 0.05
        
        # Specific adjustments for certain patterns
        if pattern == 'rdp_brute_force' and '3389' in str(alert.get('destination_port', '')):
            base_confidence += 0.15
        
        elif pattern == 'ssh_brute_force' and '22' in str(alert.get('destination_port', '')):
            base_confidence += 0.15
        
        return min(1.0, base_confidence)
    
    def _deduplicate_techniques(self, techniques: List[MitreTag]) -> List[MitreTag]:
        """Remove duplicate techniques, keeping highest confidence"""
        
        seen = {}
        
        for technique in techniques:
            key = technique.technique_id
            
            if key not in seen or technique.confidence > seen[key].confidence:
                seen[key] = technique
        
        return list(seen.values())
    
    def _get_primary_tactic(self, tags: List[MitreTag]) -> str:
        """Determine primary tactic from MITRE tags"""
        
        if not tags:
            return "Unknown"
        
        # Count tactics weighted by confidence
        tactic_scores = {}
        
        for tag in tags:
            score = tactic_scores.get(tag.tactic, 0)
            tactic_scores[tag.tactic] = score + tag.confidence
        
        # Return tactic with highest score
        return max(tactic_scores.items(), key=lambda x: x[1])[0]
    
    def _classify_attack_pattern(self, tags: List[MitreTag], alert: Dict) -> str:
        """Classify overall attack pattern"""
        
        if not tags:
            return "Unclassified"
        
        # Extract primary techniques
        primary_techniques = [tag.technique_id for tag in tags[:3]]  # Top 3 techniques
        
        # Pattern classification based on technique combinations
        if 'T1595' in primary_techniques:  # Active Scanning
            return "Reconnaissance Campaign"
        
        elif 'T1110' in primary_techniques:  # Brute Force
            if any(t.startswith('T1021') for t in primary_techniques):  # Lateral Movement
                return "Credential-based Lateral Movement"
            else:
                return "Brute Force Attack"
        
        elif 'T1041' in primary_techniques or 'T1048' in primary_techniques:  # Exfiltration
            return "Data Exfiltration"
        
        elif 'T1059' in primary_techniques:  # Command Execution
            return "Remote Code Execution"
        
        elif 'T1071' in primary_techniques or 'T1573' in primary_techniques:  # C2
            return "Command and Control"
        
        else:
            # Use primary tactic as pattern
            primary_tactic = self._get_primary_tactic(tags)
            return f"{primary_tactic} Activity"
    
    def _adjust_severity(self, alert: Dict, tags: List[MitreTag]) -> str:
        """Adjust alert severity based on MITRE classification"""
        
        original_severity = alert.get('severity', 'Medium')
        
        if not tags:
            return original_severity
        
        # Severity escalation rules based on MITRE techniques
        high_impact_techniques = [
            'T1003',  # Credential Dumping
            'T1041',  # Exfiltration Over C2 Channel
            'T1059',  # Command and Scripting Interpreter
            'T1543',  # Create or Modify System Process
            'T1499'   # Endpoint Denial of Service
        ]
        
        critical_techniques = [
            'T1110.001',  # Password Guessing (if combined with other techniques)
            'T1021.001'   # RDP (if combined with credential access)
        ]
        
        # Check for high impact techniques
        for tag in tags:
            if tag.technique_id in critical_techniques and tag.confidence > 0.8:
                if original_severity in ['Low', 'Medium']:
                    return 'High'
                elif original_severity == 'High':
                    return 'Critical'
            
            elif tag.technique_id in high_impact_techniques and tag.confidence > 0.7:
                if original_severity == 'Low':
                    return 'Medium'
                elif original_severity == 'Medium':
                    return 'High'
        
        # Check for technique combinations that increase severity
        technique_ids = [tag.technique_id for tag in tags]
        
        # Credential access + lateral movement = escalate
        if ('T1110' in technique_ids and any(t.startswith('T1021') for t in technique_ids)):
            if original_severity in ['Low', 'Medium']:
                return 'High'
        
        # Multiple tactics = escalate
        tactics = set(tag.tactic for tag in tags)
        if len(tactics) >= 3:
            if original_severity == 'Low':
                return 'Medium'
            elif original_severity == 'Medium':
                return 'High'
        
        return original_severity
    
    def export_tagged_alerts(self, tagged_alerts: List[TaggedAlert], output_file: str):
        """Export tagged alerts to JSON file"""
        
        try:
            export_data = {
                'timestamp': datetime.now().isoformat(),
                'total_alerts': len(tagged_alerts),
                'tagged_alerts': []
            }
            
            for tagged_alert in tagged_alerts:
                alert_data = {
                    'original_alert': tagged_alert.original_alert,
                    'mitre_tags': [asdict(tag) for tag in tagged_alert.mitre_tags],
                    'primary_tactic': tagged_alert.primary_tactic,
                    'attack_pattern': tagged_alert.attack_pattern,
                    'severity_adjusted': tagged_alert.severity_adjusted
                }
                export_data['tagged_alerts'].append(alert_data)
            
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            logger.info(f"Exported {len(tagged_alerts)} tagged alerts to {output_file}")
            
        except Exception as e:
            logger.error(f"Error exporting tagged alerts: {e}")
    
    def get_mitre_statistics(self, tagged_alerts: List[TaggedAlert]) -> Dict:
        """Get statistics on MITRE technique usage"""
        
        if not tagged_alerts:
            return {}
        
        # Technique frequency
        technique_counts = {}
        tactic_counts = {}
        pattern_counts = {}
        
        for tagged_alert in tagged_alerts:
            # Count techniques
            for tag in tagged_alert.mitre_tags:
                technique_counts[tag.technique_id] = technique_counts.get(tag.technique_id, 0) + 1
                tactic_counts[tag.tactic] = tactic_counts.get(tag.tactic, 0) + 1
            
            # Count attack patterns
            pattern = tagged_alert.attack_pattern
            pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
        
        return {
            'total_tagged_alerts': len(tagged_alerts),
            'unique_techniques': len(technique_counts),
            'unique_tactics': len(tactic_counts),
            'top_techniques': dict(sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            'tactic_distribution': tactic_counts,
            'attack_patterns': pattern_counts,
            'coverage_percentage': (len([ta for ta in tagged_alerts if ta.mitre_tags]) / len(tagged_alerts)) * 100
        }
    
    def save_custom_mappings(self, output_file: str):
        """Save current mappings to custom file for modification"""
        
        try:
            mappings_data = {}
            
            for pattern, tags in self.technique_mappings.items():
                mappings_data[pattern] = [asdict(tag) for tag in tags]
            
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w') as f:
                json.dump(mappings_data, f, indent=2)
            
            logger.info(f"Saved MITRE mappings template to {output_file}")
            
        except Exception as e:
            logger.error(f"Error saving MITRE mappings: {e}")


def main():
    """Main function for testing MITRE ATT&CK tagging"""
    
    # Create test alerts
    test_alerts = [
        {
            'title': 'Suspicious Port Scanning Activity',
            'description': 'Multiple port scan attempts detected from external IP',
            'source_ip': '192.168.1.100',
            'destination_port': '80,443,22,3389',
            'severity': 'High',
            'timestamp': 1640995200
        },
        {
            'title': 'RDP Brute Force Attack',
            'description': 'Multiple failed RDP authentication attempts',
            'source_ip': '10.0.0.50',
            'destination_port': '3389',
            'severity': 'Critical',
            'timestamp': 1640995800
        },
        {
            'title': 'Suspicious Data Exfiltration',
            'description': 'Large data transfer to external server detected',
            'source_ip': '192.168.1.25',
            'destination_ip': '8.8.8.8',
            'severity': 'High',
            'timestamp': 1640996400
        },
        {
            'title': 'Reverse Shell Connection Detected',
            'description': 'Outbound shell connection to suspicious IP',
            'source_ip': '192.168.1.10',
            'destination_ip': '203.0.113.1',
            'severity': 'Critical',
            'timestamp': 1640996800
        }
    ]
    
    # Create MITRE tagger
    tagger = MitreAttackTagger()
    
    # Tag alerts
    tagged_alerts = tagger.tag_alerts(test_alerts)
    
    # Display results
    print(f"\n🏷️  Tagged {len(tagged_alerts)} alerts with MITRE ATT&CK techniques:")
    print("=" * 80)
    
    for tagged_alert in tagged_alerts:
        alert = tagged_alert.original_alert
        print(f"\n📊 Alert: {alert['title']}")
        print(f"   Original Severity: {alert['severity']} → Adjusted: {tagged_alert.severity_adjusted}")
        print(f"   Primary Tactic: {tagged_alert.primary_tactic}")
        print(f"   Attack Pattern: {tagged_alert.attack_pattern}")
        
        if tagged_alert.mitre_tags:
            print(f"   MITRE Techniques:")
            for tag in tagged_alert.mitre_tags:
                print(f"     • {tag.technique_id}: {tag.technique_name}")
                print(f"       Tactic: {tag.tactic} | Confidence: {tag.confidence:.2f}")
                if tag.url:
                    print(f"       Reference: {tag.url}")
        else:
            print("   No MITRE techniques identified")
    
    # Show statistics
    stats = tagger.get_mitre_statistics(tagged_alerts)
    print(f"\n📈 MITRE ATT&CK Statistics:")
    print(f"   Total Tagged Alerts: {stats['total_tagged_alerts']}")  
    print(f"   Unique Techniques: {stats['unique_techniques']}")
    print(f"   Coverage: {stats['coverage_percentage']:.1f}%")
    print(f"   Top Techniques: {list(stats['top_techniques'].keys())[:3]}")
    print(f"   Tactic Distribution: {stats['tactic_distribution']}")
    
    # Export results
    tagger.export_tagged_alerts(tagged_alerts, "reports/mitre_tagged_alerts.json")
    tagger.save_custom_mappings("config/mitre_mappings_template.json")
    
    print(f"\n✅ Results exported to:")
    print(f"   • reports/mitre_tagged_alerts.json")
    print(f"   • config/mitre_mappings_template.json")


if __name__ == "__main__":
    main()
