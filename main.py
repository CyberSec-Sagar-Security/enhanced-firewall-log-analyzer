#!/usr/bin/env python3
"""
SOC Firewall Log Analyzer - Enhanced Main Entry Point
Analyzes firewall logs for suspicious activity patterns with advanced features
Author: SOC Team
Date: June 2025
"""

import argparse
import os
import sys
from datetime import datetime
from loguru import logger
from colorama import Fore, Style, init
from pathlib import Path
from typing import List, Dict, Optional

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
    
    # Optional advanced features
    try:
        from utils.pdf_report import PDFReportGenerator
        PDF_AVAILABLE = True
    except ImportError:
        PDF_AVAILABLE = False
        
    try:
        import schedule
        SCHEDULE_AVAILABLE = True
    except ImportError:
        SCHEDULE_AVAILABLE = False
        
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure all modules are in the correct directories")
    sys.exit(1)


class FirewallLogAnalyzer:
    """Enhanced analyzer class with advanced threat detection and reporting"""
    
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
        
        # Advanced features
        self.correlation_engine = CorrelationEngine()
        self.mitre_tagger = MitreAttackTagger()
        
        if PDF_AVAILABLE:
            try:
                self.pdf_generator = PDFReportGenerator()
            except ImportError:
                self.pdf_generator = None
        else:
            self.pdf_generator = None
        
        if SCHEDULE_AVAILABLE:
            try:
                self.scheduler = TaskScheduler()
            except ImportError:
                self.scheduler = None
        else:
            self.scheduler = None
        
        # Initialize logging
        logger.add("logs/analyzer.log", rotation="10 MB")
        logger.info("Enhanced Firewall Log Analyzer initialized")
    
    def analyze_logs(self, log_files: List[str], parser_type: str, 
                    output_format: str = "both", enable_correlation: bool = True,
                    enable_mitre: bool = True, generate_pdf: bool = False) -> Dict:
        """
        Enhanced analysis function with advanced features
        
        Args:
            log_files: List of log file paths
            parser_type: Type of parser to use (pfsense/windows/auto)
            output_format: Output format (json/excel/both)
            enable_correlation: Enable correlation analysis
            enable_mitre: Enable MITRE ATT&CK tagging
            generate_pdf: Generate PDF report
            
        Returns:
            Analysis results dictionary
        """
        
        if not log_files:
            logger.error("No log files provided")
            return {"status": "error", "message": "No log files provided"}
        
        all_alerts = []
        processed_files = 0
        
        # Process each log file
        for log_file_path in log_files:
            if not os.path.exists(log_file_path):
                logger.error(f"Log file not found: {log_file_path}")
                continue
            
            # Auto-detect parser type
            if parser_type == "auto":
                detected_type = self._detect_parser_type(log_file_path)
                logger.info(f"Auto-detected parser type: {detected_type}")
            else:
                detected_type = parser_type
            
            if detected_type not in self.parsers:
                logger.error(f"Unknown parser type: {detected_type}")
                continue
            
            try:
                # Parse the log file
                logger.info(f"Parsing log file: {log_file_path} with parser: {detected_type}")
                
                parser = self.parsers[detected_type]
                log_entries = parser.parse_log_file(log_file_path)
                
                if not log_entries:
                    logger.warning(f"No entries found in {log_file_path}")
                    continue
                
                logger.info(f"Successfully parsed {len(log_entries)} entries from {log_file_path}")
                
                # Run threat detection
                file_alerts = self._run_threat_detection(log_entries, log_file_path)
                all_alerts.extend(file_alerts)
                processed_files += 1
                
            except Exception as e:
                logger.error(f"Error analyzing {log_file_path}: {str(e)}")
                continue
        
        if not all_alerts:
            result = {
                "status": "success",
                "alert_count": 0,
                "files_processed": processed_files,
                "message": "No threats detected"
            }
            
            if processed_files > 0:
                self.alert_system.show_success("Analysis complete - No threats detected! ✅")
            
            return result
        
        # Apply advanced features
        enhanced_results = self._apply_advanced_features(
            all_alerts, enable_correlation, enable_mitre, generate_pdf
        )
        
        # Generate outputs
        output_files = self._generate_outputs(all_alerts, output_format, enhanced_results)
        
        # Display results
        self._display_results(all_alerts, enhanced_results)
        
        return {
            "status": "success",
            "alert_count": len(all_alerts),
            "files_processed": processed_files,
            "alerts": all_alerts,
            "correlations": enhanced_results.get("correlations", []),
            "mitre_tagged": enhanced_results.get("mitre_tagged", []),
            "output_files": output_files,
            "reports": output_files.get("reports", [])
        }
    
    def analyze_log_file(self, log_file_path: str, parser_type: str):
        """
        Legacy single-file analysis function for backward compatibility
        """
        
        return self.analyze_logs([log_file_path], parser_type, "both")
    
    def start_live_monitoring(self, log_file_path: str, parser_type: str, 
                            check_interval: float = 1.0) -> Optional[LiveLogTailer]:
        """
        Start live log monitoring
        
        Args:
            log_file_path: Path to log file to monitor
            parser_type: Parser type to use
            check_interval: Check interval in seconds
            
        Returns:
            LiveLogTailer instance if successful
        """
        
        try:
            tailer = LiveLogTailer(log_file_path, parser_type, check_interval=check_interval)
            
            if tailer.start_monitoring():
                logger.info(f"Live monitoring started for {log_file_path}")
                return tailer
            else:
                logger.error("Failed to start live monitoring")
                return None
                
        except Exception as e:
            logger.error(f"Error starting live monitoring: {e}")
            return None
    
    def start_scheduler(self) -> bool:
        """
        Start the task scheduler
        
        Returns:
            True if successful, False otherwise
        """
        
        if not self.scheduler:
            logger.error("Scheduler not available")
            return False
        
        try:
            self.scheduler.start_scheduler()
            logger.info("Task scheduler started")
            return True
        except Exception as e:
            logger.error(f"Error starting scheduler: {e}")
            return False
    
    def _detect_parser_type(self, log_file_path: str) -> str:
        """Auto-detect parser type based on file content and name"""
        
        file_name = os.path.basename(log_file_path).lower()
        
        # Check file name patterns
        if 'pfsense' in file_name:
            return 'pfsense'
        elif 'windows' in file_name or 'fw' in file_name:
            return 'windows'
        
        # Check file extension
        if log_file_path.endswith('.evtx'):
            return 'windows'
        
        # Check content (read first few lines)
        try:
            with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                first_lines = ''.join(f.readlines()[:5]).lower()
                
                if 'filterlog' in first_lines or 'pfsense' in first_lines:
                    return 'pfsense'
                elif any(keyword in first_lines for keyword in ['date,time,action', 'src-ip', 'dst-ip']):
                    return 'windows'
        except Exception:
            pass
        
        # Default to Windows parser
        return 'windows'
    
    def _run_threat_detection(self, log_entries: List[Dict], source_file: str) -> List[Dict]:
        """
        Run all threat detectors on the parsed log entries
        """
        
        all_alerts = []
        
        for detector in self.detectors:
            try:
                logger.info(f"Running detector: {detector.__class__.__name__}")
                alerts = detector.detect(log_entries)
                
                if alerts:
                    for alert in alerts:
                        alert['source_file'] = source_file
                        alert['detection_time'] = datetime.now().isoformat()
                        all_alerts.append(alert)
                        
                        # Log to JSON file
                        self.log_writer.write_alert(alert)
                
            except Exception as e:
                logger.error(f"Error in detector {detector.__class__.__name__}: {str(e)}")
        
        return all_alerts
    
    def _apply_advanced_features(self, alerts: List[Dict], enable_correlation: bool,
                               enable_mitre: bool, generate_pdf: bool) -> Dict:
        """Apply advanced analysis features"""
        
        results = {}
        
        # Apply correlation analysis
        if enable_correlation:
            try:
                logger.info("Running correlation analysis")
                correlations = self.correlation_engine.process_alerts(alerts)
                results["correlations"] = correlations
                
                if correlations:
                    logger.info(f"Generated {len(correlations)} correlations")
                    
                    # Export correlations
                    correlation_file = f"reports/correlations_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    self.correlation_engine.export_correlations(correlation_file)
                    results["correlation_file"] = correlation_file
                    
            except Exception as e:
                logger.error(f"Error in correlation analysis: {e}")
                results["correlations"] = []
        
        # Apply MITRE ATT&CK tagging
        if enable_mitre:
            try:
                logger.info("Applying MITRE ATT&CK tagging")
                tagged_alerts = self.mitre_tagger.tag_alerts(alerts)
                results["mitre_tagged"] = tagged_alerts
                
                if tagged_alerts:
                    logger.info(f"Tagged {len(tagged_alerts)} alerts with MITRE techniques")
                    
                    # Get statistics
                    mitre_stats = self.mitre_tagger.get_mitre_statistics(tagged_alerts)
                    results["mitre_stats"] = mitre_stats
                    
                    # Export tagged alerts
                    mitre_file = f"reports/mitre_tagged_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    self.mitre_tagger.export_tagged_alerts(tagged_alerts, mitre_file)
                    results["mitre_file"] = mitre_file
                    
            except Exception as e:
                logger.error(f"Error in MITRE tagging: {e}")
                results["mitre_tagged"] = []
        
        # Generate PDF report
        if generate_pdf and self.pdf_generator:
            try:
                logger.info("Generating PDF report")
                pdf_file = f"reports/security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                
                correlations_data = [c.__dict__ if hasattr(c, '__dict__') else c 
                                   for c in results.get("correlations", [])]
                
                success = self.pdf_generator.generate_security_report(
                    alerts=alerts,
                    output_path=pdf_file,
                    correlations=correlations_data
                )
                
                if success:
                    results["pdf_report"] = pdf_file
                    logger.info(f"PDF report generated: {pdf_file}")
                    
            except Exception as e:
                logger.error(f"Error generating PDF report: {e}")
        
        return results
    
    def _generate_outputs(self, alerts: List[Dict], output_format: str, 
                         enhanced_results: Dict) -> Dict:
        """Generate output files"""
        
        output_files = {"reports": []}
        
        try:
            if output_format in ["excel", "both"]:
                excel_file = export_alerts_to_excel(alerts, "reports")
                if excel_file:
                    output_files["excel"] = excel_file
                    output_files["reports"].append(excel_file)
                    logger.info(f"Excel report created: {excel_file}")
            
            if output_format in ["json", "both"]:
                # JSON output is automatically handled by log_writer
                json_file = "logs/alert_output.json"
                output_files["json"] = json_file
                output_files["reports"].append(json_file)
            
            # Add enhanced results files
            if "correlation_file" in enhanced_results:
                output_files["reports"].append(enhanced_results["correlation_file"])
            
            if "mitre_file" in enhanced_results:
                output_files["reports"].append(enhanced_results["mitre_file"])
            
            if "pdf_report" in enhanced_results:
                output_files["reports"].append(enhanced_results["pdf_report"])
                
        except Exception as e:
            logger.error(f"Error generating outputs: {e}")
        
        return output_files
    
    def _display_results(self, alerts: List[Dict], enhanced_results: Dict):
        """Display analysis results"""
        
        # Display alerts table
        if alerts:
            print_alerts_summary(alerts)
        
        # Show correlation results
        correlations = enhanced_results.get("correlations", [])
        if correlations:
            print(f"\n🔗 CORRELATION ANALYSIS")
            print("=" * 50)
            
            for correlation in correlations[:5]:  # Show top 5
                if hasattr(correlation, 'rule_name'):
                    print(f"📊 {correlation.rule_name}")
                    print(f"   Source IP: {correlation.source_ip}")
                    print(f"   Severity: {correlation.severity}")
                    print(f"   Alert Count: {correlation.alert_count}")
                elif isinstance(correlation, dict):
                    print(f"📊 {correlation.get('rule_name', 'Unknown')}")
                    print(f"   Source IP: {correlation.get('source_ip', 'N/A')}")
                    print(f"   Severity: {correlation.get('severity', 'Unknown')}")
                    print(f"   Alert Count: {correlation.get('alert_count', 0)}")
                print()
        
        # Show MITRE statistics
        mitre_stats = enhanced_results.get("mitre_stats", {})
        if mitre_stats:
            print(f"🏷️  MITRE ATT&CK ANALYSIS")
            print("=" * 50)
            print(f"📊 Coverage: {mitre_stats.get('coverage_percentage', 0):.1f}%")
            print(f"🎯 Unique Techniques: {mitre_stats.get('unique_techniques', 0)}")
            print(f"📋 Top Techniques: {list(mitre_stats.get('top_techniques', {}).keys())[:3]}")
            print()
        
        # Final summary
        total_alerts = len(alerts)
        high_severity_alerts = len([a for a in alerts if a.get('severity', '').upper() in ['CRITICAL', 'HIGH']])
        
        print(f"\n{'='*60}")
        print(f"📋 ENHANCED SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"🚨 Threats Detected: {total_alerts}")
        print(f"⚠️  High/Critical Severity: {high_severity_alerts}")
        print(f"🔗 Correlations: {len(correlations)}")
        print(f"🏷️  MITRE Coverage: {mitre_stats.get('coverage_percentage', 0):.1f}%")
        
        # Show generated reports
        reports = enhanced_results.get("reports", [])
        if "pdf_report" in enhanced_results:
            print(f"📑 PDF Report: {enhanced_results['pdf_report']}")
        if "correlation_file" in enhanced_results:
            print(f"🔗 Correlations: {enhanced_results['correlation_file']}")
        if "mitre_file" in enhanced_results:
            print(f"🏷️  MITRE Tags: {enhanced_results['mitre_file']}")
        
        print(f"📝 JSON Log: logs/alert_output.json")
        print(f"{'='*60}")


def main():
    """Enhanced main function with advanced options"""
    
    parser = argparse.ArgumentParser(
        description="Enhanced SOC Firewall Log Analyzer - Advanced threat detection and reporting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic analysis
  python main.py --logfile sample.log --parser pfsense
  
  # Multiple files with auto-detection
  python main.py --logfile file1.csv file2.log --parser auto
  
  # Full analysis with all features
  python main.py --logfile logs/*.csv --parser auto --correlation --mitre --pdf
  
  # Live monitoring
  python main.py --live --logfile /path/to/live.log --parser windows
  
  # Start GUI dashboard
  python main.py --gui
  
  # Start scheduler
  python main.py --scheduler
        """
    )
    
    # File input options
    parser.add_argument(
        '--logfile', 
        nargs='+',
        help='Path(s) to firewall log file(s) (.log, .csv, .evtx)'
    )
    
    parser.add_argument(
        '--parser',
        choices=['pfsense', 'windows', 'auto'],
        default='auto',
        help='Type of firewall parser to use (default: auto)'
    )
    
    # Output options
    parser.add_argument(
        '--output',
        choices=['json', 'excel', 'both'],
        default='both',
        help='Output format (default: both)'
    )
    
    # Advanced features
    parser.add_argument(
        '--correlation',
        action='store_true',
        help='Enable correlation analysis'
    )
    
    parser.add_argument(
        '--mitre',
        action='store_true',
        help='Enable MITRE ATT&CK tagging'
    )
    
    parser.add_argument(
        '--pdf',
        action='store_true',
        help='Generate PDF report (requires additional dependencies)'
    )
    
    # Operation modes
    parser.add_argument(
        '--live',
        action='store_true',
        help='Start live log monitoring'
    )
    
    parser.add_argument(
        '--gui',
        action='store_true',
        help='Start Streamlit GUI dashboard'
    )
    
    parser.add_argument(
        '--scheduler',
        action='store_true',
        help='Start task scheduler'
    )
    
    # Other options
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress toast notifications'
    )
    
    parser.add_argument(
        '--interval',
        type=float,
        default=1.0,
        help='Live monitoring check interval in seconds (default: 1.0)'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not any([args.logfile, args.live, args.gui, args.scheduler]):
        parser.error("Must specify --logfile, --live, --gui, or --scheduler")
    
    if args.live and not args.logfile:
        parser.error("--live requires --logfile")
    
    if args.pdf and not PDF_AVAILABLE:
        print("⚠️  PDF generation not available. Install: pip install jinja2 weasyprint plotly")
        args.pdf = False
    
    # Create analyzer instance
    analyzer = FirewallLogAnalyzer()
    
    # Set quiet mode
    if args.quiet:
        analyzer.alert_system.quiet_mode = True
    
    # Handle different operation modes
    if args.gui:
        # Start GUI dashboard
        try:
            import subprocess
            print("🌐 Starting Streamlit GUI Dashboard...")
            subprocess.run([sys.executable, "-m", "streamlit", "run", "gui/dashboard.py"])
        except Exception as e:
            print(f"❌ Error starting GUI: {e}")
            print("Install Streamlit: pip install streamlit")
    
    elif args.scheduler:
        # Start scheduler
        if analyzer.start_scheduler():
            print("📅 Task Scheduler started")
            print("Press Ctrl+C to stop...")
            try:
                while True:
                    import time
                    time.sleep(60)
            except KeyboardInterrupt:
                print("\n🛑 Stopping scheduler...")
                analyzer.scheduler.stop_scheduler()
        else:
            print("❌ Failed to start scheduler")
    
    elif args.live:
        # Start live monitoring
        print("🔴 Starting live log monitoring...")
        
        tailer = analyzer.start_live_monitoring(
            args.logfile[0], args.parser, args.interval
        )
        
        if tailer:
            print("Press Ctrl+C to stop monitoring...")
            try:
                while True:
                    import time
                    time.sleep(10)
                    tailer.print_status()
            except KeyboardInterrupt:
                print("\n🛑 Stopping live monitoring...")
                tailer.stop_monitoring()
        else:
            print("❌ Failed to start live monitoring")
    
    else:
        # Standard analysis mode
        print("=" * 60)
        print("🔥 ENHANCED SOC FIREWALL LOG ANALYZER")
        print("=" * 60)
        print(f"📁 Log Files: {args.logfile}")
        print(f"⚙️  Parser: {args.parser}")
        print(f"📊 Output: {args.output}")
        print(f"🔗 Correlation: {'✅' if args.correlation else '❌'}")
        print(f"🏷️  MITRE Tagging: {'✅' if args.mitre else '❌'}")
        print(f"📑 PDF Report: {'✅' if args.pdf else '❌'}")
        print(f"📅 Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # Run analysis
        results = analyzer.analyze_logs(
            log_files=args.logfile,
            parser_type=args.parser,
            output_format=args.output,
            enable_correlation=args.correlation,
            enable_mitre=args.mitre,
            generate_pdf=args.pdf
        )
        
        print("=" * 60)
        print("✅ Enhanced Analysis Complete!")
        print(f"📋 Results: {results['status']} - {results['alert_count']} alerts")
        print("=" * 60)


if __name__ == "__main__":
    main()
    
    def analyze_log_file(self, log_file_path, parser_type):
        """
        Main analysis function that processes log file and detects threats
        
        Args:
            log_file_path (str): Path to the log file
            parser_type (str): Type of parser to use (pfsense/windows)
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
            self.alert_system.show_info(f"Starting analysis of {log_file_path}")
            logger.info(f"Parsing log file: {log_file_path} with parser: {parser_type}")
            
            parser = self.parsers[parser_type]
            log_entries = parser.parse_log_file(log_file_path)
            
            if not log_entries:
                self.alert_system.show_warning("No log entries found or parsed")
                return
            
            self.alert_system.show_success(f"Parsed {len(log_entries)} log entries")
            logger.info(f"Successfully parsed {len(log_entries)} entries")
            
            # Run threat detection
            self._run_threat_detection(log_entries, log_file_path)
            
        except Exception as e:
            logger.error(f"Error analyzing log file: {str(e)}")
            self.alert_system.show_error(f"Analysis failed: {str(e)}")
    
    def _run_threat_detection(self, log_entries, source_file):
        """
        Run all threat detectors on the parsed log entries
        
        Args:
            log_entries (list): List of normalized log entries
            source_file (str): Original log file path
        """
        
        all_alerts = []
        
        self.alert_system.show_info("Running threat detection algorithms...")
        
        for detector in self.detectors:
            try:
                logger.info(f"Running detector: {detector.__class__.__name__}")
                alerts = detector.detect(log_entries)
                
                if alerts:
                    for alert in alerts:
                        alert['source_file'] = source_file
                        alert['detection_time'] = datetime.now().isoformat()
                        
                        # Add to our collection
                        all_alerts.append(alert)
                        
                        # Log to JSON file (individual alerts)
                        self.log_writer.write_alert(alert)
                
            except Exception as e:
                logger.error(f"Error in detector {detector.__class__.__name__}: {str(e)}")
        
        # Display results in table format
        if all_alerts:
            print_alerts_summary(all_alerts)
            
            # Export to Excel in reports directory
            try:
                excel_file = export_alerts_to_excel(all_alerts, "reports")
                if excel_file:
                    logger.info(f"Excel export completed: {excel_file}")
                    print(f"\n📊 Excel report created: {excel_file}")
                    
                    # Show toast notification for Excel creation
                    self.alert_system.show_success(f"Excel report saved: {os.path.basename(excel_file)}")
            except Exception as e:
                logger.error(f"Excel export failed: {e}")
                print(f"⚠️  Excel export failed: {e}")
        else:
            self.alert_system.show_info("No threats detected - all clear! ✅")
            print(f"\n{Fore.GREEN + Style.BRIGHT}✅ ANALYSIS COMPLETE - NO THREATS DETECTED{Style.RESET_ALL}")
        
        # Final summary
        total_alerts = len(all_alerts)
        high_severity_alerts = len([a for a in all_alerts if a.get('severity', '').upper() in ['CRITICAL', 'HIGH']])
        
        logger.info(f"Analysis complete. Total alerts: {total_alerts}, High severity: {high_severity_alerts}")
        
        # Print final summary banner
        print(f"\n{'='*60}")
        print(f"📋 SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"🔍 Total Events Analyzed: {len(log_entries)}")
        print(f"🚨 Threats Detected: {total_alerts}")
        print(f"⚠️  High/Critical Severity: {high_severity_alerts}")
        if all_alerts:
            print(f"📊 Excel Report: reports/{os.path.basename(excel_file) if 'excel_file' in locals() and excel_file else 'N/A'}")
        print(f"📝 JSON Log: logs/alert_output.json")
        print(f"{'='*60}")
        
        return all_alerts


def main():
    """Main function with argument parsing"""
    
    parser = argparse.ArgumentParser(
        description="SOC Firewall Log Analyzer - Detect suspicious activity in firewall logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --logfile sample.log --parser pfsense
  python main.py --logfile windows_fw.csv --parser windows
  python main.py --logfile /path/to/logs/firewall.evtx --parser windows
        """
    )
    
    parser.add_argument(
        '--logfile', 
        required=True,
        help='Path to the firewall log file (.log, .csv, .evtx)'
    )
    
    parser.add_argument(
        '--parser',
        choices=['pfsense', 'windows'],
        required=True,
        help='Type of firewall parser to use'
    )
    
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress toast notifications (console output only)'
    )
    
    args = parser.parse_args()
    
    # Create analyzer instance
    analyzer = FirewallLogAnalyzer()
    
    # Set quiet mode if requested
    if args.quiet:
        analyzer.alert_system.quiet_mode = True
    
    # Run analysis
    print("=" * 60)
    print("🔥 SOC FIREWALL LOG ANALYZER")
    print("=" * 60)
    print(f"📁 Log File: {args.logfile}")
    print(f"⚙️  Parser: {args.parser}")
    print(f"📅 Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    analyzer.analyze_log_file(args.logfile, args.parser)
    
    print("=" * 60)
    print("✅ Analysis Complete!")
    print(f"📋 Check logs/alert_output.json for detailed results")
    print("=" * 60)


if __name__ == "__main__":
    main()
