#!/usr/bin/env python3
"""
Correlation Engine for SOC Firewall Log Analyzer
Correlates alerts across different detection modules to identify complex attack patterns
Author: SOC Team
"""

import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict
from pathlib import Path
import uuid
from loguru import logger


@dataclass
class CorrelationRule:
    """Represents a correlation rule"""
    name: str
    description: str
    conditions: List[str]  # List of alert types to correlate
    time_window: int  # Time window in seconds
    threshold: int  # Minimum number of alerts to trigger
    severity: str  # Resulting correlation severity
    mitre_tags: List[str]  # MITRE ATT&CK tags


@dataclass
class CorrelatedAlert:
    """Represents a correlated alert"""
    correlation_id: str
    rule_name: str
    source_ip: str
    alert_count: int
    first_seen: float
    last_seen: float
    severity: str
    confidence: float
    related_alerts: List[Dict]
    mitre_tags: List[str]
    description: str
    recommendation: str


class CorrelationEngine:
    """Engine for correlating security alerts across detection modules"""
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize correlation engine
        
        Args:
            config_file: Path to correlation rules configuration file
        """
        self.correlation_rules = self._load_correlation_rules(config_file)
        self.active_correlations = defaultdict(list)  # IP -> list of alerts
        self.correlation_history = []
        self.correlation_window = 3600  # 1 hour default window
        
        # Setup logging
        logger.add("logs/correlation_engine.log", rotation="10 MB")
        logger.info("Correlation engine initialized")
    
    def _load_correlation_rules(self, config_file: Optional[str]) -> List[CorrelationRule]:
        """Load correlation rules from configuration"""
        
        # Default correlation rules
        default_rules = [
            CorrelationRule(
                name="Multi-Vector Attack",
                description="Multiple attack types from same IP within time window",
                conditions=["suspicious_port", "brute_force", "data_exfiltration", "reverse_shell"],
                time_window=1800,  # 30 minutes
                threshold=3,
                severity="Critical",
                mitre_tags=["T1595", "T1110", "T1041", "T1043"]
            ),
            CorrelationRule(
                name="Brute Force Campaign",
                description="Multiple brute force attempts from same IP",
                conditions=["brute_force"],
                time_window=3600,  # 1 hour
                threshold=5,
                severity="High",
                mitre_tags=["T1110.001", "T1110.003"]
            ),
            CorrelationRule(
                name="Port Scanning Campaign",
                description="Extensive port scanning activity from same IP",
                conditions=["suspicious_port"],
                time_window=1800,  # 30 minutes
                threshold=10,
                severity="High",
                mitre_tags=["T1595.001"]
            ),
            CorrelationRule(
                name="Data Exfiltration Pattern",
                description="Multiple data exfiltration attempts following reconnaissance",
                conditions=["suspicious_port", "data_exfiltration"],
                time_window=2400,  # 40 minutes
                threshold=2,
                severity="High",
                mitre_tags=["T1595", "T1041"]
            ),
            CorrelationRule(
                name="Persistent Access Attempt",
                description="Reverse shell attempts after successful brute force",
                conditions=["brute_force", "reverse_shell"],
                time_window=1200,  # 20 minutes
                threshold=2,
                severity="Critical",
                mitre_tags=["T1110", "T1059"]
            ),
            CorrelationRule(
                name="Lateral Movement Indicators",
                description="Multiple internal connections suggesting lateral movement",
                conditions=["suspicious_port", "brute_force"],
                time_window=900,  # 15 minutes
                threshold=3,
                severity="High",
                mitre_tags=["T1021", "T1110"]
            )
        ]
        
        # Load custom rules if config file provided
        if config_file and Path(config_file).exists():
            try:
                with open(config_file, 'r') as f:
                    custom_config = json.load(f)
                    
                # Parse custom rules
                custom_rules = []
                for rule_data in custom_config.get('rules', []):
                    rule = CorrelationRule(**rule_data)
                    custom_rules.append(rule)
                
                logger.info(f"Loaded {len(custom_rules)} custom correlation rules")
                return custom_rules
                
            except Exception as e:
                logger.error(f"Error loading custom correlation rules: {e}")
                logger.info("Using default correlation rules")
        
        logger.info(f"Using {len(default_rules)} default correlation rules")
        return default_rules
    
    def process_alerts(self, alerts: List[Dict]) -> List[CorrelatedAlert]:
        """
        Process new alerts and generate correlations
        
        Args:
            alerts: List of alert dictionaries
            
        Returns:
            List of correlated alerts
        """
        
        if not alerts:
            return []
        
        logger.info(f"Processing {len(alerts)} alerts for correlation")
        
        # Add alerts to active correlations
        self._add_alerts_to_correlations(alerts)
        
        # Clean up old correlations
        self._cleanup_old_correlations()
        
        # Generate correlations
        correlated_alerts = self._generate_correlations()
        
        # Store correlation history
        self.correlation_history.extend(correlated_alerts)
        
        logger.info(f"Generated {len(correlated_alerts)} correlated alerts")
        
        return correlated_alerts
    
    def _add_alerts_to_correlations(self, alerts: List[Dict]):
        """Add new alerts to active correlations by IP"""
        
        for alert in alerts:
            source_ip = alert.get('source_ip', 'unknown')
            
            # Normalize alert type for correlation
            alert_type = self._normalize_alert_type(alert.get('title', ''))
            alert['normalized_type'] = alert_type
            alert['correlation_timestamp'] = alert.get('timestamp', time.time())
            
            # Add to active correlations
            self.active_correlations[source_ip].append(alert)
            
        logger.debug(f"Active correlations for {len(self.active_correlations)} IPs")
    
    def _normalize_alert_type(self, alert_title: str) -> str:
        """Normalize alert title to correlation type"""
        
        title_lower = alert_title.lower()
        
        if 'port' in title_lower or 'scan' in title_lower:
            return 'suspicious_port'
        elif 'brute' in title_lower or 'force' in title_lower:
            return 'brute_force'
        elif 'exfiltration' in title_lower or 'data' in title_lower:
            return 'data_exfiltration'
        elif 'shell' in title_lower or 'reverse' in title_lower:
            return 'reverse_shell'
        else:
            return 'other'
    
    def _cleanup_old_correlations(self):
        """Remove old correlations outside time window"""
        
        current_time = time.time()
        cleanup_threshold = current_time - self.correlation_window
        
        for source_ip in list(self.active_correlations.keys()):
            # Filter alerts within time window
            active_alerts = [
                alert for alert in self.active_correlations[source_ip]
                if alert.get('correlation_timestamp', 0) > cleanup_threshold
            ]
            
            if active_alerts:
                self.active_correlations[source_ip] = active_alerts
            else:
                del self.active_correlations[source_ip]
    
    def _generate_correlations(self) -> List[CorrelatedAlert]:
        """Generate correlated alerts based on rules"""
        
        correlated_alerts = []
        current_time = time.time()
        
        for source_ip, alerts in self.active_correlations.items():
            if len(alerts) < 2:  # Need at least 2 alerts to correlate
                continue
            
            # Check each correlation rule
            for rule in self.correlation_rules:
                correlation = self._check_rule_against_alerts(rule, source_ip, alerts, current_time)
                if correlation:
                    correlated_alerts.append(correlation)
        
        return correlated_alerts
    
    def _check_rule_against_alerts(self, rule: CorrelationRule, source_ip: str, 
                                 alerts: List[Dict], current_time: float) -> Optional[CorrelatedAlert]:
        """Check if alerts match a correlation rule"""
        
        # Filter alerts within rule time window
        window_start = current_time - rule.time_window
        relevant_alerts = [
            alert for alert in alerts
            if alert.get('correlation_timestamp', 0) >= window_start
        ]
        
        if len(relevant_alerts) < rule.threshold:
            return None
        
        # Check if rule conditions are met
        alert_types = [alert.get('normalized_type', '') for alert in relevant_alerts]
        alert_type_counts = Counter(alert_types)
        
        # For rules with multiple conditions, check if all are present
        if len(rule.conditions) > 1:
            conditions_met = all(
                alert_type_counts.get(condition, 0) > 0 
                for condition in rule.conditions
            )
            if not conditions_met:
                return None
        else:
            # For single condition rules, check threshold
            condition_count = alert_type_counts.get(rule.conditions[0], 0)
            if condition_count < rule.threshold:
                return None
        
        # Calculate correlation metrics
        first_seen = min(alert.get('correlation_timestamp', current_time) for alert in relevant_alerts)
        last_seen = max(alert.get('correlation_timestamp', current_time) for alert in relevant_alerts)
        
        # Calculate confidence based on rule matching
        confidence = self._calculate_confidence(rule, relevant_alerts, alert_type_counts)
        
        # Generate correlation description
        description = self._generate_correlation_description(rule, source_ip, relevant_alerts, alert_type_counts)
        
        # Generate recommendation
        recommendation = self._generate_recommendation(rule, source_ip, relevant_alerts)
        
        # Create correlated alert
        correlation = CorrelatedAlert(
            correlation_id=str(uuid.uuid4()),
            rule_name=rule.name,
            source_ip=source_ip,
            alert_count=len(relevant_alerts),
            first_seen=first_seen,
            last_seen=last_seen,
            severity=rule.severity,
            confidence=confidence,
            related_alerts=relevant_alerts,
            mitre_tags=rule.mitre_tags,
            description=description,
            recommendation=recommendation
        )
        
        logger.info(f"Generated correlation: {rule.name} for IP {source_ip}")
        
        return correlation
    
    def _calculate_confidence(self, rule: CorrelationRule, alerts: List[Dict], 
                            alert_type_counts: Counter) -> float:
        """Calculate confidence score for correlation"""
        
        base_confidence = 0.7  # Base confidence
        
        # Increase confidence based on alert count
        alert_bonus = min(0.2, (len(alerts) - rule.threshold) * 0.05)
        
        # Increase confidence for diverse alert types
        diversity_bonus = min(0.1, (len(alert_type_counts) - 1) * 0.05)
        
        # Time clustering bonus (alerts close in time)
        time_clustering_bonus = self._calculate_time_clustering_bonus(alerts)
        
        confidence = base_confidence + alert_bonus + diversity_bonus + time_clustering_bonus
        
        return min(1.0, confidence)  # Cap at 1.0
    
    def _calculate_time_clustering_bonus(self, alerts: List[Dict]) -> float:
        """Calculate bonus for time clustering of alerts"""
        
        if len(alerts) < 2:
            return 0.0
        
        timestamps = [alert.get('correlation_timestamp', 0) for alert in alerts]
        timestamps.sort()
        
        # Calculate average time gap
        gaps = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        avg_gap = sum(gaps) / len(gaps)
        
        # Bonus for smaller gaps (more clustered)
        if avg_gap < 300:  # 5 minutes
            return 0.1
        elif avg_gap < 900:  # 15 minutes
            return 0.05
        else:
            return 0.0
    
    def _generate_correlation_description(self, rule: CorrelationRule, source_ip: str, 
                                        alerts: List[Dict], alert_type_counts: Counter) -> str:
        """Generate human-readable correlation description"""
        
        attack_types = []
        for alert_type, count in alert_type_counts.items():
            if count > 0:
                type_name = alert_type.replace('_', ' ').title()
                attack_types.append(f"{type_name} ({count})")
        
        description = f"Correlated attack pattern detected from IP {source_ip}. "
        description += f"Activities observed: {', '.join(attack_types)}. "
        description += f"Total events: {len(alerts)} over {rule.time_window//60} minutes. "
        description += f"Pattern matches: {rule.description}"
        
        return description
    
    def _generate_recommendation(self, rule: CorrelationRule, source_ip: str, 
                               alerts: List[Dict]) -> str:
        """Generate security recommendations for correlation"""
        
        recommendations = []
        
        # IP-based recommendations
        recommendations.append(f"• Block IP address {source_ip} at firewall/perimeter")
        recommendations.append(f"• Monitor all connections from {source_ip} subnet")
        
        # Rule-specific recommendations
        if rule.name == "Multi-Vector Attack":
            recommendations.append("• Activate incident response procedures")
            recommendations.append("• Check for compromise indicators on affected systems")
            recommendations.append("• Review authentication logs for successful logins")
            
        elif rule.name == "Brute Force Campaign":
            recommendations.append("• Implement account lockout policies")
            recommendations.append("• Enable multi-factor authentication")
            recommendations.append("• Review password policies")
            
        elif rule.name == "Port Scanning Campaign":
            recommendations.append("• Hide or disable unused services")
            recommendations.append("• Implement port knocking or VPN access")
            recommendations.append("• Check system vulnerabilities")
            
        elif rule.name == "Data Exfiltration Pattern":
            recommendations.append("• Check for data loss on affected systems")
            recommendations.append("• Review outbound network traffic")
            recommendations.append("• Activate data breach response procedures")
            
        elif rule.name == "Persistent Access Attempt":
            recommendations.append("• Check for unauthorized access or backdoors")
            recommendations.append("• Review system integrity")
            recommendations.append("• Monitor for privilege escalation attempts")
        
        # MITRE-based recommendations
        if "T1110" in rule.mitre_tags:
            recommendations.append("• Implement credential access monitoring")
        if "T1041" in rule.mitre_tags:
            recommendations.append("• Monitor data exfiltration channels")
        if "T1595" in rule.mitre_tags:
            recommendations.append("• Implement network reconnaissance detection")
        
        return "\n".join(recommendations)
    
    def get_correlation_summary(self) -> Dict:
        """Get summary of correlation activity"""
        
        total_correlations = len(self.correlation_history)
        
        if not self.correlation_history:
            return {
                'total_correlations': 0,
                'active_ips': 0,
                'rule_breakdown': {},
                'severity_breakdown': {},
                'top_ips': {},
                'recent_activity': []
            }
        
        # Rule breakdown
        rule_counts = Counter(corr.rule_name for corr in self.correlation_history)
        
        # Severity breakdown
        severity_counts = Counter(corr.severity for corr in self.correlation_history)
        
        # Top IPs
        ip_counts = Counter(corr.source_ip for corr in self.correlation_history)
        
        # Recent activity (last 24 hours)
        recent_threshold = time.time() - 86400
        recent_correlations = [
            corr for corr in self.correlation_history
            if corr.last_seen > recent_threshold
        ]
        
        return {
            'total_correlations': total_correlations,
            'active_ips': len(self.active_correlations),
            'rule_breakdown': dict(rule_counts),
            'severity_breakdown': dict(severity_counts),
            'top_ips': dict(ip_counts.most_common(10)),
            'recent_activity': [asdict(corr) for corr in recent_correlations[-10:]]
        }
    
    def export_correlations(self, output_file: str):
        """Export correlations to JSON file"""
        
        try:
            correlations_data = {
                'timestamp': datetime.now().isoformat(),
                'summary': self.get_correlation_summary(),
                'correlations': [asdict(corr) for corr in self.correlation_history]
            }
            
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w') as f:
                json.dump(correlations_data, f, indent=2, default=str)
            
            logger.info(f"Exported {len(self.correlation_history)} correlations to {output_file}")
            
        except Exception as e:
            logger.error(f"Error exporting correlations: {e}")
    
    def save_correlation_rules(self, config_file: str):
        """Save current correlation rules to configuration file"""
        
        try:
            rules_data = {
                'rules': [asdict(rule) for rule in self.correlation_rules],
                'timestamp': datetime.now().isoformat()
            }
            
            Path(config_file).parent.mkdir(parents=True, exist_ok=True)
            
            with open(config_file, 'w') as f:
                json.dump(rules_data, f, indent=2)
            
            logger.info(f"Saved {len(self.correlation_rules)} correlation rules to {config_file}")
            
        except Exception as e:
            logger.error(f"Error saving correlation rules: {e}")


def main():
    """Main function for testing correlation engine"""
    
    # Create test correlation engine
    engine = CorrelationEngine()
    
    # Test alerts
    test_alerts = [
        {
            'title': 'Suspicious Port Access',
            'source_ip': '192.168.1.100',
            'timestamp': time.time() - 1500,
            'severity': 'Medium'
        },
        {
            'title': 'Brute Force Attack Detected',
            'source_ip': '192.168.1.100',
            'timestamp': time.time() - 1200,
            'severity': 'High'
        },
        {
            'title': 'Data Exfiltration Attempt',
            'source_ip': '192.168.1.100',
            'timestamp': time.time() - 900,
            'severity': 'High'
        },
        {
            'title': 'Reverse Shell Connection',
            'source_ip': '192.168.1.100',
            'timestamp': time.time() - 600,
            'severity': 'Critical'
        }
    ]
    
    # Process alerts
    correlations = engine.process_alerts(test_alerts)
    
    # Display results
    print(f"\n🔗 Generated {len(correlations)} correlations:")
    
    for correlation in correlations:
        print(f"\n📊 Correlation: {correlation.rule_name}")
        print(f"   Source IP: {correlation.source_ip}")
        print(f"   Severity: {correlation.severity}")
        print(f"   Confidence: {correlation.confidence:.2f}")
        print(f"   Alert Count: {correlation.alert_count}")
        print(f"   MITRE Tags: {', '.join(correlation.mitre_tags)}")
        print(f"   Description: {correlation.description}")
    
    # Show summary
    summary = engine.get_correlation_summary()
    print(f"\n📈 Correlation Summary:")
    print(f"   Total Correlations: {summary['total_correlations']}")
    print(f"   Active IPs: {summary['active_ips']}")
    print(f"   Rule Breakdown: {summary['rule_breakdown']}")
    
    # Export results
    engine.export_correlations("reports/correlations.json")
    print(f"\n✅ Results exported to reports/correlations.json")


if __name__ == "__main__":
    main()
