#!/usr/bin/env python3
"""
Enhanced SOC Firewall Log Analyzer - Main Entry Point
Comprehensive SOC-style analyzer with all advanced features
Author: SOC Team
Date: June 2025
"""

import argparse
import os
import sys
from datetime import datetime
from loguru import logger
from colorama import Fore, Style, init
import threading
import time

# Initialize colorama
init()

# Import our custom modules
try:
    from parsers.pfsense_parser import PfSenseParser
    from parsers.windows_fw_parser import WindowsFirewallParser
    from detectors.suspicious_ports import SuspiciousPortDetector
    from detectors.brute_force_detector import BruteForceDetector
    from detectors.exfiltration_detector import ExfiltrationDetector
    from detectors.reverse_shell_detector import ReverseShellDetector
    from alerts.local_alert import LocalAlert
    from utils.log_writer import LogWriter
    from utils.table_formatter import print_alerts_summary
    from utils.excel_export import export_alerts_to_excel
    from utils.correlation_engine import CorrelationEngine
    from utils.mitre_tagger import MitreAttackTagger
    from utils.live_tailer import LiveLogTailer
    from utils.scheduler import TaskScheduler
    try:
        from utils.pdf_report import PDFReportGenerator
        PDF_AVAILABLE = True
    except ImportError:
        PDFReportGenerator = None
        PDF_AVAILABLE = False
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure all modules are in the correct directories")
    sys.exit(1)


class EnhancedFirewallLogAnalyzer:
    """Enhanced analyzer class with all SOC features"""
    
    def __init__(self):
        self.parsers = {
            'pfsense': PfSenseParser(),
            'windows': WindowsFirewallParser()
        }
        
        self.detectors = [
            SuspiciousPortDetector(),
            BruteForceDetector(),
            ExfiltrationDetector(),
            ReverseShellDetector()
        ]
        
        self.alert_system = LocalAlert()
        self.log_writer = LogWriter()
        
        # Enhanced components
        self.correlation_engine = CorrelationEngine()
        self.mitre_tagger = MitreAttackTagger()
        self.live_tailer = None
        self.scheduler = None
        
        # Optional components (may not be available)
        self.pdf_generator = None
        try:
            self.pdf_generator = PDFReportGenerator() if PDF_AVAILABLE else None
        except ImportError:
            logger.warning("PDF generation not available - install jinja2 and weasyprint")
        
        # Initialize logging
        logger.add("logs/analyzer.log", rotation="10 MB")
        logger.info("Enhanced Firewall Log Analyzer initialized")
    
    def analyze_log_file(self, log_file_path, parser_type, enable_correlation=True, 
                        enable_mitre_tagging=True, generate_pdf=False):
        """
        Enhanced analysis function with all SOC features
        
        Args:
            log_file_path (str): Path to the log file
            parser_type (str): Type of parser to use (pfsense/windows)
            enable_correlation (bool): Enable correlation engine
            enable_mitre_tagging (bool): Enable MITRE ATT&CK tagging
            generate_pdf (bool): Generate PDF report
        """
        
        if not os.path.exists(log_file_path):
            logger.error(f"Log file not found: {log_file_path}")
            self.alert_system.show_error(f"Log file not found: {log_file_path}")
            return
        
        if parser_type not in self.parsers:
            logger.error(f"Unknown parser type: {parser_type}")
            self.alert_system.show_error(f"Unknown parser type: {parser_type}")
            return
        
        try:
            # Parse the log file
            self.alert_system.show_info(f"🔍 Starting enhanced analysis of {log_file_path}")
            logger.info(f"Parsing log file: {log_file_path} with parser: {parser_type}")
            
            parser = self.parsers[parser_type]
            log_entries = parser.parse_log_file(log_file_path)
            
            if not log_entries:
                self.alert_system.show_warning("No log entries found or parsed")
                return
            
            self.alert_system.show_success(f"Parsed {len(log_entries)} log entries")
            logger.info(f"Successfully parsed {len(log_entries)} entries")
            
            # Run threat detection
            all_alerts = self._run_threat_detection(log_entries, log_file_path)
            
            # Enhanced processing
            if all_alerts:
                # Apply MITRE ATT&CK tagging
                if enable_mitre_tagging:
                    all_alerts = self._apply_mitre_tagging(all_alerts)
                
                # Run correlation engine
                if enable_correlation:
                    correlated_alerts = self._run_correlation(all_alerts)
                    if correlated_alerts:
                        print(f"\n{Fore.RED + Style.BRIGHT}🔗 CORRELATION ENGINE RESULTS{Style.RESET_ALL}")
                        print(f"Found {len(correlated_alerts)} correlated attack patterns")
                        for correlation in correlated_alerts:
                            print(f"  • {correlation['rule_name']}: {correlation['description']}")
                
                # Generate enhanced reports
                self._generate_enhanced_reports(all_alerts, log_file_path, generate_pdf)
            
        except Exception as e:
            logger.error(f"Error analyzing log file: {str(e)}")
            self.alert_system.show_error(f"Analysis failed: {str(e)}")
    
    def start_live_monitoring(self, log_file_path, parser_type):
        """
        Start live log file monitoring
        
        Args:
            log_file_path (str): Path to log file to monitor
            parser_type (str): Type of parser to use
        """
        
        self.alert_system.show_info(f"🔴 Starting live monitoring of {log_file_path}")
        
        try:
            self.live_tailer = LiveLogTailer(log_file_path, parser_type)
            
            # Start monitoring in background thread
            monitor_thread = threading.Thread(
                target=self.live_tailer.start_monitoring,
                daemon=True
            )
            monitor_thread.start()
            
            print(f"{Fore.GREEN}📡 Live monitoring started - Press Ctrl+C to stop{Style.RESET_ALL}")
            
            # Keep main thread alive
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}🛑 Stopping live monitoring...{Style.RESET_ALL}")
                self.live_tailer.stop_monitoring()
                
        except Exception as e:
            logger.error(f"Live monitoring error: {str(e)}")
            self.alert_system.show_error(f"Live monitoring failed: {str(e)}")
    
    def setup_scheduled_analysis(self, config_file=None):
        """
        Setup scheduled analysis tasks
        
        Args:
            config_file (str): Path to scheduler configuration file
        """
        
        try:
            self.scheduler = TaskScheduler(config_file)
            
            # Add default tasks if no config provided
            if not config_file:
                self._setup_default_scheduled_tasks()
            
            self.scheduler.start()
            self.alert_system.show_success("📅 Scheduled analysis started")
            
        except Exception as e:
            logger.error(f"Scheduler setup error: {str(e)}")
            self.alert_system.show_error(f"Scheduler setup failed: {str(e)}")
    
    def _run_threat_detection(self, log_entries, source_file):
        """Run all threat detectors with enhanced logging"""
        
        all_alerts = []
        
        self.alert_system.show_info("🚨 Running threat detection algorithms...")
        
        for detector in self.detectors:
            try:
                logger.info(f"Running detector: {detector.__class__.__name__}")
                print(f"  • {detector.__class__.__name__}...", end=" ")
                
                alerts = detector.detect(log_entries)
                
                if alerts:
                    print(f"{Fore.RED}{len(alerts)} threats{Style.RESET_ALL}")
                    for alert in alerts:
                        alert['source_file'] = source_file
                        alert['detection_time'] = datetime.now().isoformat()
                        all_alerts.append(alert)
                        self.log_writer.write_alert(alert)
                else:
                    print(f"{Fore.GREEN}✓ Clean{Style.RESET_ALL}")
                
            except Exception as e:
                print(f"{Fore.RED}✗ Error{Style.RESET_ALL}")
                logger.error(f"Error in detector {detector.__class__.__name__}: {str(e)}")
        
        # Display results
        if all_alerts:
            print_alerts_summary(all_alerts)
            
            # Export to Excel
            try:
                excel_file = export_alerts_to_excel(all_alerts, "reports")
                if excel_file:
                    logger.info(f"Excel export completed: {excel_file}")
                    print(f"\n📊 Excel report created: {excel_file}")
                    self.alert_system.show_success(f"Excel report saved: {os.path.basename(excel_file)}")
            except Exception as e:
                logger.error(f"Excel export failed: {e}")
                print(f"⚠️  Excel export failed: {e}")
        else:
            self.alert_system.show_info("No threats detected - all clear! ✅")
            print(f"\n{Fore.GREEN + Style.BRIGHT}✅ ANALYSIS COMPLETE - NO THREATS DETECTED{Style.RESET_ALL}")
        
        # Enhanced summary
        total_alerts = len(all_alerts)
        high_severity_alerts = len([a for a in all_alerts if a.get('severity', '').upper() in ['CRITICAL', 'HIGH']])
        
        logger.info(f"Analysis complete. Total alerts: {total_alerts}, High severity: {high_severity_alerts}")
        
        # Print enhanced summary banner
        print(f"\n{'='*60}")
        print(f"📋 ENHANCED SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"🔍 Total Events Analyzed: {len(log_entries)}")
        print(f"🚨 Threats Detected: {total_alerts}")
        print(f"⚠️  High/Critical Severity: {high_severity_alerts}")
        print(f"📊 Excel Report: reports/{os.path.basename(excel_file) if 'excel_file' in locals() and excel_file else 'N/A'}")
        print(f"📝 JSON Log: logs/alert_output.json")
        print(f"{'='*60}")
        
        return all_alerts
    
    def _apply_mitre_tagging(self, alerts):
        """Apply MITRE ATT&CK tagging to alerts"""
        
        print(f"\n{Fore.BLUE + Style.BRIGHT}🏷️  APPLYING MITRE ATT&CK TAGS{Style.RESET_ALL}")
        
        tagged_alerts = []
        for alert in alerts:
            try:
                tagged_alert = self.mitre_tagger.tag_alert(alert)
                tagged_alerts.append(tagged_alert.original_alert)
                
                if tagged_alert.mitre_tags:
                    technique_ids = [tag.technique_id for tag in tagged_alert.mitre_tags]
                    print(f"  • {alert.get('type', 'Unknown')}: {', '.join(technique_ids)}")
                    
            except Exception as e:
                logger.warning(f"MITRE tagging failed for alert: {e}")
                tagged_alerts.append(alert)
        
        return tagged_alerts
    
    def _run_correlation(self, alerts):
        """Run correlation engine on alerts"""
        
        print(f"\n{Fore.MAGENTA + Style.BRIGHT}🔗 RUNNING CORRELATION ANALYSIS{Style.RESET_ALL}")
        
        try:
            correlations = self.correlation_engine.correlate_alerts(alerts)
            
            if correlations:
                print(f"Found {len(correlations)} correlated attack patterns:")
                for correlation in correlations:
                    severity_color = Fore.RED if correlation['severity'] == 'HIGH' else Fore.YELLOW
                    print(f"  {severity_color}• {correlation['rule_name']}{Style.RESET_ALL}")
                    print(f"    {correlation['description']}")
                    
            return correlations
            
        except Exception as e:
            logger.error(f"Correlation analysis failed: {e}")
            return []
    
    def _generate_enhanced_reports(self, alerts, source_file, generate_pdf=False):
        """Generate enhanced reports including PDF if available"""
        
        if generate_pdf and self.pdf_generator:
            try:
                print(f"\n{Fore.CYAN + Style.BRIGHT}📄 GENERATING PDF REPORT{Style.RESET_ALL}")
                
                pdf_file = self.pdf_generator.generate_report(
                    alerts, 
                    output_dir="reports",
                    title=f"SOC Analysis Report - {os.path.basename(source_file)}"
                )
                
                if pdf_file:
                    print(f"📄 PDF report created: {pdf_file}")
                    self.alert_system.show_success(f"PDF report saved: {os.path.basename(pdf_file)}")
                    
            except Exception as e:
                logger.error(f"PDF generation failed: {e}")
                print(f"⚠️  PDF generation failed: {e}")
    
    def _setup_default_scheduled_tasks(self):
        """Setup default scheduled analysis tasks"""
        
        # Daily comprehensive analysis
        self.scheduler.add_task(
            name="daily_analysis",
            description="Daily comprehensive log analysis",
            schedule_type="daily",
            schedule_time="02:00",
            task_function="analyze_daily_logs",
            parameters={"generate_reports": True}
        )
        
        # Weekly correlation analysis
        self.scheduler.add_task(
            name="weekly_correlation",
            description="Weekly correlation and trend analysis",
            schedule_type="weekly",
            schedule_time="Sunday 03:00",
            task_function="weekly_correlation_analysis",
            parameters={"lookback_days": 7}
        )


def main():
    """Enhanced main function with all SOC features"""
    
    parser = argparse.ArgumentParser(
        description="Enhanced SOC Firewall Log Analyzer - Full-featured security analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🔥 SOC FEATURES:
  Basic Analysis:    python enhanced_main.py --logfile sample.log --parser windows
  Live Monitoring:   python enhanced_main.py --live --logfile firewall.log --parser windows  
  Correlation:       python enhanced_main.py --logfile sample.log --parser windows --correlation
  MITRE Tagging:     python enhanced_main.py --logfile sample.log --parser windows --mitre
  PDF Reports:       python enhanced_main.py --logfile sample.log --parser windows --pdf
  Scheduled Tasks:   python enhanced_main.py --schedule --config scheduler.json
  GUI Dashboard:     streamlit run gui/dashboard.py
        """
    )
    
    parser.add_argument('--logfile', help='Path to the firewall log file')
    parser.add_argument('--parser', choices=['pfsense', 'windows'], 
                       help='Type of firewall parser to use')
    parser.add_argument('--live', action='store_true', 
                       help='Enable live log monitoring')
    parser.add_argument('--correlation', action='store_true', 
                       help='Enable correlation analysis')
    parser.add_argument('--mitre', action='store_true', 
                       help='Enable MITRE ATT&CK tagging')
    parser.add_argument('--pdf', action='store_true', 
                       help='Generate PDF report')
    parser.add_argument('--schedule', action='store_true', 
                       help='Start scheduled analysis')
    parser.add_argument('--config', help='Configuration file for scheduler')
    parser.add_argument('--quiet', action='store_true', 
                       help='Suppress toast notifications')
    
    args = parser.parse_args()
    
    # Create enhanced analyzer instance
    analyzer = EnhancedFirewallLogAnalyzer()
    
    # Set quiet mode if requested
    if args.quiet:
        analyzer.alert_system.quiet_mode = True
    
    # Print enhanced header
    print("=" * 70)
    print("🔥 ENHANCED SOC FIREWALL LOG ANALYZER")
    print("=" * 70)
    print(f"🚀 Advanced Features: Correlation | MITRE ATT&CK | Live Monitoring | PDF Reports")
    print(f"📅 Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    # Handle different modes
    if args.schedule:
        print("📅 Starting scheduled analysis mode...")
        analyzer.setup_scheduled_analysis(args.config)
        try:
            while True:
                time.sleep(60)  # Keep alive
        except KeyboardInterrupt:
            print("\n🛑 Stopping scheduler...")
            
    elif args.live:
        if not args.logfile or not args.parser:
            print("❌ Live monitoring requires --logfile and --parser arguments")
            sys.exit(1)
        analyzer.start_live_monitoring(args.logfile, args.parser)
        
    elif args.logfile and args.parser:
        print(f"📁 Log File: {args.logfile}")
        print(f"⚙️  Parser: {args.parser}")
        
        # Enhanced analysis
        analyzer.analyze_log_file(
            args.logfile, 
            args.parser,
            enable_correlation=args.correlation,
            enable_mitre_tagging=args.mitre,
            generate_pdf=args.pdf
        )
        
    else:
        print("❌ Please specify analysis mode:")
        print("   --logfile & --parser for file analysis")
        print("   --live for live monitoring") 
        print("   --schedule for scheduled analysis")
        print("   Use --help for full options")
        sys.exit(1)
    
    print("=" * 70)
    print("✅ Enhanced SOC Analysis Complete!")
    print("📋 Check reports/ directory for all generated files")
    print("=" * 70)


if __name__ == "__main__":
    main()
