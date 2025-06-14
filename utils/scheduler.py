#!/usr/bin/env python3
"""
Automated Scheduling System for SOC Firewall Log Analyzer
Provides scheduled analysis, reporting, and maintenance tasks
Author: SOC Team
"""

import os
import sys
import time
import json
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, asdict
import threading
from loguru import logger

# Scheduler dependencies
try:
    import schedule
    SCHEDULE_AVAILABLE = True
except ImportError:
    SCHEDULE_AVAILABLE = False

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@dataclass
class ScheduledTask:
    """Represents a scheduled task"""
    name: str
    description: str
    schedule_type: str  # 'daily', 'weekly', 'hourly', 'interval'
    schedule_time: str  # Time specification
    task_function: str  # Function name to call
    parameters: Dict  # Parameters to pass to function
    enabled: bool = True
    last_run: Optional[float] = None
    next_run: Optional[float] = None
    run_count: int = 0
    last_success: bool = True
    last_error: Optional[str] = None


class TaskScheduler:
    """Automated task scheduler for SOC operations"""
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize task scheduler
        
        Args:
            config_file: Path to scheduler configuration file
        """
        if not SCHEDULE_AVAILABLE:
            raise ImportError("Schedule library not available. Install: pip install schedule")
        
        self.config_file = config_file or "config/scheduler_config.json"
        self.tasks = []
        self.is_running = False
        self.scheduler_thread = None        
        # Initialize components
        # Initialize analyzer when needed to avoid circular imports
        self.analyzer = None
        
        # Initialize other components
        try:
            from utils.correlation_engine import CorrelationEngine
            self.correlation_engine = CorrelationEngine()
        except ImportError:
            self.correlation_engine = None
            
        try:
            from utils.mitre_tagger import MitreAttackTagger
            self.mitre_tagger = MitreAttackTagger()
        except ImportError:
            self.mitre_tagger = None
        
    def _get_analyzer(self):
        """Get analyzer instance, creating it if needed to avoid circular imports"""
        if self.analyzer is None:
            # Import here to avoid circular imports
            from main import FirewallLogAnalyzer
            self.analyzer = FirewallLogAnalyzer()
        return self.analyzer
          # PDF generator (optional)
        try:
            from utils.pdf_report import PDFReportGenerator
            self.pdf_generator = PDFReportGenerator()
            self.pdf_available = True
        except ImportError:
            self.pdf_generator = None
            self.pdf_available = False
        
        # Task registry
        self.task_registry = {
            'analyze_logs': self._task_analyze_logs,
            'generate_daily_report': self._task_generate_daily_report,
            'generate_weekly_report': self._task_generate_weekly_report,
            'clean_old_logs': self._task_clean_old_logs,
            'backup_reports': self._task_backup_reports,
            'update_threat_intel': self._task_update_threat_intel,
            'system_health_check': self._task_system_health_check,
            'correlation_analysis': self._task_correlation_analysis,
            'mitre_tagging': self._task_mitre_tagging,
            'export_alerts': self._task_export_alerts
        }
        
        # Load configuration
        self._load_configuration()
        
        # Setup logging
        logger.add("logs/scheduler.log", rotation="10 MB")
        logger.info("Task scheduler initialized")
    
    def _load_configuration(self):
        """Load scheduler configuration"""
        
        if Path(self.config_file).exists():
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                
                self.tasks = []
                for task_data in config.get('tasks', []):
                    task = ScheduledTask(**task_data)
                    self.tasks.append(task)
                
                logger.info(f"Loaded {len(self.tasks)} scheduled tasks")
                
            except Exception as e:
                logger.error(f"Error loading scheduler configuration: {e}")
                self._create_default_configuration()
        else:
            self._create_default_configuration()
    
    def _create_default_configuration(self):
        """Create default scheduler configuration"""
        
        default_tasks = [
            ScheduledTask(
                name="Daily Log Analysis",
                description="Analyze firewall logs from the last 24 hours",
                schedule_type="daily",
                schedule_time="08:00",
                task_function="analyze_logs",
                parameters={
                    "log_directory": "logs/daily",
                    "parser_type": "auto",
                    "output_format": "both"
                }
            ),
            ScheduledTask(
                name="Daily Security Report",
                description="Generate daily security summary report",
                schedule_type="daily",
                schedule_time="09:00",
                task_function="generate_daily_report",
                parameters={
                    "report_type": "security",
                    "include_correlations": True,
                    "include_mitre": True
                }
            ),
            ScheduledTask(
                name="Weekly Executive Summary",
                description="Generate weekly executive summary",
                schedule_type="weekly",
                schedule_time="monday:10:00",
                task_function="generate_weekly_report",
                parameters={
                    "report_type": "executive",
                    "time_period": "7 days"
                }
            ),
            ScheduledTask(
                name="Log Cleanup",
                description="Clean up old log files to free disk space",
                schedule_type="weekly",
                schedule_time="sunday:02:00",
                task_function="clean_old_logs",
                parameters={
                    "retention_days": 30,
                    "directories": ["logs", "reports"]
                }
            ),
            ScheduledTask(
                name="Correlation Analysis",
                description="Run correlation analysis on recent alerts",
                schedule_type="hourly",
                schedule_time="every_2_hours",
                task_function="correlation_analysis",
                parameters={
                    "time_window": 7200  # 2 hours
                }
            ),
            ScheduledTask(
                name="System Health Check",
                description="Check system health and resource usage",
                schedule_type="daily",
                schedule_time="06:00",
                task_function="system_health_check",
                parameters={
                    "check_disk_space": True,
                    "check_log_rotation": True,
                    "send_alerts": True
                }
            )
        ]
        
        self.tasks = default_tasks
        self._save_configuration()
        logger.info("Created default scheduler configuration")
    
    def _save_configuration(self):
        """Save scheduler configuration"""
        
        try:
            config = {
                'timestamp': datetime.now().isoformat(),
                'tasks': [asdict(task) for task in self.tasks]
            }
            
            Path(self.config_file).parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2, default=str)
            
            logger.info(f"Saved scheduler configuration to {self.config_file}")
            
        except Exception as e:
            logger.error(f"Error saving scheduler configuration: {e}")
    
    def start_scheduler(self):
        """Start the task scheduler"""
        
        if self.is_running:
            logger.warning("Scheduler is already running")
            return
        
        logger.info("Starting task scheduler")
        
        # Clear existing schedule
        schedule.clear()
        
        # Schedule all enabled tasks
        for task in self.tasks:
            if task.enabled:
                self._schedule_task(task)
        
        # Start scheduler thread
        self.is_running = True
        self.scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.scheduler_thread.start()
        
        logger.info(f"Task scheduler started with {len([t for t in self.tasks if t.enabled])} active tasks")
    
    def stop_scheduler(self):
        """Stop the task scheduler"""
        
        if not self.is_running:
            logger.warning("Scheduler is not running")
            return
        
        logger.info("Stopping task scheduler")
        
        self.is_running = False
        
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        
        schedule.clear()
        logger.info("Task scheduler stopped")
    
    def _schedule_task(self, task: ScheduledTask):
        """Schedule a single task"""
        
        try:
            if task.schedule_type == 'daily':
                schedule.every().day.at(task.schedule_time).do(self._execute_task, task)
            
            elif task.schedule_type == 'weekly':
                if ':' in task.schedule_time:
                    day, time_str = task.schedule_time.split(':')
                    getattr(schedule.every(), day.lower()).at(time_str).do(self._execute_task, task)
                else:
                    schedule.every().week.do(self._execute_task, task)
            
            elif task.schedule_type == 'hourly':
                if task.schedule_time == 'every_hour':
                    schedule.every().hour.do(self._execute_task, task)
                elif task.schedule_time.startswith('every_'):
                    # Parse "every_X_hours"
                    hours = int(task.schedule_time.split('_')[1])
                    schedule.every(hours).hours.do(self._execute_task, task)
                else:
                    # Specific minute
                    schedule.every().hour.at(f":{task.schedule_time}").do(self._execute_task, task)
            
            elif task.schedule_type == 'interval':
                # Interval in seconds
                interval = int(task.schedule_time)
                schedule.every(interval).seconds.do(self._execute_task, task)
            
            logger.info(f"Scheduled task: {task.name} ({task.schedule_type} at {task.schedule_time})")
            
        except Exception as e:
            logger.error(f"Error scheduling task {task.name}: {e}")
    
    def _run_scheduler(self):
        """Main scheduler loop"""
        
        while self.is_running:
            try:
                schedule.run_pending()
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in scheduler loop: {e}")
                time.sleep(60)  # Wait longer on error
    
    def _execute_task(self, task: ScheduledTask):
        """Execute a scheduled task"""
        
        logger.info(f"Executing task: {task.name}")
        
        start_time = time.time()
        task.last_run = start_time
        
        try:
            # Get task function
            task_func = self.task_registry.get(task.task_function)
            
            if not task_func:
                raise ValueError(f"Unknown task function: {task.task_function}")
            
            # Execute task with parameters
            result = task_func(**task.parameters)
            
            # Update task status
            task.last_success = True
            task.last_error = None
            task.run_count += 1
            
            execution_time = time.time() - start_time
            logger.info(f"Task {task.name} completed successfully in {execution_time:.2f}s")
            
            return result
            
        except Exception as e:
            task.last_success = False
            task.last_error = str(e)
            
            execution_time = time.time() - start_time
            logger.error(f"Task {task.name} failed after {execution_time:.2f}s: {e}")
            
            return None
        
        finally:
            # Save configuration to persist task status
            self._save_configuration()
    
    def _task_analyze_logs(self, log_directory: str, parser_type: str = "auto", 
                          output_format: str = "both") -> Dict:
        """Task: Analyze firewall logs"""
        
        logger.info(f"Starting log analysis: {log_directory}")
        
        # Find log files
        log_dir = Path(log_directory)
        if not log_dir.exists():
            # Try common log directories
            for common_dir in ["logs", "test_logs", "."]:
                if Path(common_dir).exists():
                    log_dir = Path(common_dir)
                    break
        
        log_files = []
        for pattern in ["*.csv", "*.log", "*.txt"]:
            log_files.extend(log_dir.glob(pattern))
        
        if not log_files:
            logger.warning(f"No log files found in {log_directory}")
            return {"status": "no_files", "files_processed": 0}
        
        # Analyze logs
        results = {
            "status": "success",
            "files_processed": len(log_files),
            "alerts_generated": 0,
            "reports_created": []
        }
        
        for log_file in log_files:
            try:
                # Determine parser type
                if parser_type == "auto":
                    if "pfsense" in log_file.name.lower():
                        file_parser_type = "pfsense"
                    else:
                        file_parser_type = "windows"
                else:
                    file_parser_type = parser_type
                  # Analyze file
                analyzer = self._get_analyzer()
                file_results = analyzer.analyze_logs([str(log_file)], file_parser_type, output_format)
                results["alerts_generated"] += file_results.get("alert_count", 0)
                
                if file_results.get("reports"):
                    results["reports_created"].extend(file_results["reports"])
                
            except Exception as e:
                logger.error(f"Error analyzing {log_file}: {e}")
        
        logger.info(f"Log analysis completed: {results['alerts_generated']} alerts generated")
        return results
    
    def _task_generate_daily_report(self, report_type: str = "security", 
                                  include_correlations: bool = True,
                                  include_mitre: bool = True) -> Dict:
        """Task: Generate daily security report"""
        
        logger.info("Generating daily security report")
        
        # Load recent alerts (last 24 hours)
        alerts = self._load_recent_alerts(hours=24)
        
        if not alerts:
            logger.info("No alerts found for daily report")
            return {"status": "no_data", "alerts_count": 0}
        
        # Generate correlations if requested
        correlations = []
        if include_correlations:
            try:
                correlations = self.correlation_engine.process_alerts(alerts)
            except Exception as e:
                logger.error(f"Error generating correlations: {e}")
        
        # Apply MITRE tagging if requested
        tagged_alerts = []
        if include_mitre:
            try:
                tagged_alerts = self.mitre_tagger.tag_alerts(alerts)
            except Exception as e:
                logger.error(f"Error applying MITRE tags: {e}")
        
        # Generate report
        report_data = {
            "report_type": "Daily Security Report",
            "date": datetime.now().strftime("%Y-%m-%d"),
            "alerts": alerts,
            "correlations": [asdict(c) for c in correlations] if correlations else [],
            "tagged_alerts": [asdict(ta) for ta in tagged_alerts] if tagged_alerts else [],
            "summary": {
                "total_alerts": len(alerts),
                "correlations": len(correlations),
                "tagged_alerts": len(tagged_alerts)
            }
        }
        
        # Save JSON report
        json_file = f"reports/daily_report_{datetime.now().strftime('%Y%m%d')}.json"
        Path(json_file).parent.mkdir(parents=True, exist_ok=True)
        
        with open(json_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        # Generate PDF report if available
        pdf_file = None
        if self.pdf_available and self.pdf_generator:
            try:
                pdf_file = f"reports/daily_report_{datetime.now().strftime('%Y%m%d')}.pdf"
                success = self.pdf_generator.generate_security_report(
                    alerts=alerts,
                    output_path=pdf_file,
                    correlations=[asdict(c) for c in correlations] if correlations else None
                )
                
                if not success:
                    pdf_file = None
                    
            except Exception as e:
                logger.error(f"Error generating PDF report: {e}")
                pdf_file = None
        
        result = {
            "status": "success",
            "alerts_count": len(alerts),
            "correlations_count": len(correlations),
            "json_report": json_file,
            "pdf_report": pdf_file
        }
        
        logger.info(f"Daily report generated: {result}")
        return result
    
    def _task_generate_weekly_report(self, report_type: str = "executive", 
                                   time_period: str = "7 days") -> Dict:
        """Task: Generate weekly executive report"""
        
        logger.info("Generating weekly executive report")
        
        # Load recent alerts (last 7 days)
        alerts = self._load_recent_alerts(hours=24*7)
        
        if not alerts:
            logger.info("No alerts found for weekly report")
            return {"status": "no_data", "alerts_count": 0}
        
        # Generate executive summary
        report_file = None
        if self.pdf_available and self.pdf_generator:
            try:
                report_file = f"reports/executive_summary_{datetime.now().strftime('%Y%m%d')}.pdf"
                success = self.pdf_generator.generate_executive_summary(
                    alerts=alerts,
                    output_path=report_file,
                    time_period=time_period
                )
                
                if not success:
                    report_file = None
                    
            except Exception as e:
                logger.error(f"Error generating executive report: {e}")
                report_file = None
        
        result = {
            "status": "success" if report_file else "partial",
            "alerts_count": len(alerts),
            "report_file": report_file,
            "time_period": time_period
        }
        
        logger.info(f"Weekly report generated: {result}")
        return result
    
    def _task_clean_old_logs(self, retention_days: int = 30, 
                           directories: List[str] = None) -> Dict:
        """Task: Clean up old log files"""
        
        if directories is None:
            directories = ["logs", "reports"]
        
        logger.info(f"Cleaning old files (older than {retention_days} days)")
        
        cutoff_time = time.time() - (retention_days * 24 * 3600)
        cleaned_files = 0
        freed_space = 0
        
        for directory in directories:
            dir_path = Path(directory)
            
            if not dir_path.exists():
                continue
            
            for file_path in dir_path.rglob("*"):
                if file_path.is_file():
                    try:
                        file_time = file_path.stat().st_mtime
                        
                        if file_time < cutoff_time:
                            file_size = file_path.stat().st_size
                            file_path.unlink()
                            
                            cleaned_files += 1
                            freed_space += file_size
                            
                    except Exception as e:
                        logger.error(f"Error cleaning {file_path}: {e}")
        
        result = {
            "status": "success",
            "cleaned_files": cleaned_files,
            "freed_space_mb": freed_space / (1024 * 1024),
            "retention_days": retention_days
        }
        
        logger.info(f"Cleanup completed: {result}")
        return result
    
    def _task_backup_reports(self, backup_directory: str = "backups") -> Dict:
        """Task: Backup important reports"""
        
        logger.info("Backing up reports")
        
        backup_dir = Path(backup_directory)
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Create timestamped backup directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_subdir = backup_dir / f"backup_{timestamp}"
        backup_subdir.mkdir(exist_ok=True)
        
        # Copy reports
        reports_dir = Path("reports")
        copied_files = 0
        
        if reports_dir.exists():
            for report_file in reports_dir.glob("*.pdf"):
                try:
                    import shutil
                    shutil.copy2(report_file, backup_subdir)
                    copied_files += 1
                except Exception as e:
                    logger.error(f"Error backing up {report_file}: {e}")
        
        result = {
            "status": "success",
            "backup_directory": str(backup_subdir),
            "files_backed_up": copied_files
        }
        
        logger.info(f"Backup completed: {result}")
        return result
    
    def _task_update_threat_intel(self) -> Dict:
        """Task: Update threat intelligence data"""
        
        logger.info("Updating threat intelligence")
        
        # Placeholder for threat intelligence updates
        # This could fetch IOCs, update rules, etc.
        
        result = {
            "status": "success",
            "updated_at": datetime.now().isoformat(),
            "sources_updated": ["internal"]
        }
        
        logger.info("Threat intelligence update completed")
        return result
    
    def _task_system_health_check(self, check_disk_space: bool = True,
                                check_log_rotation: bool = True,
                                send_alerts: bool = True) -> Dict:
        """Task: Perform system health check"""
        
        logger.info("Performing system health check")
        
        health_status = {
            "timestamp": datetime.now().isoformat(),
            "overall_status": "healthy",
            "checks": {}
        }
        
        # Check disk space
        if check_disk_space:
            try:
                import shutil
                total, used, free = shutil.disk_usage(".")
                free_percentage = (free / total) * 100
                
                health_status["checks"]["disk_space"] = {
                    "status": "healthy" if free_percentage > 10 else "warning",
                    "free_percentage": free_percentage,
                    "free_gb": free / (1024**3)
                }
                
                if free_percentage <= 10:
                    health_status["overall_status"] = "warning"
                    
            except Exception as e:
                health_status["checks"]["disk_space"] = {
                    "status": "error",
                    "error": str(e)
                }
        
        # Check log file sizes
        if check_log_rotation:
            large_logs = []
            log_dir = Path("logs")
            
            if log_dir.exists():
                for log_file in log_dir.glob("*.log"):
                    try:
                        size_mb = log_file.stat().st_size / (1024*1024)
                        if size_mb > 100:  # Files larger than 100MB
                            large_logs.append({
                                "file": str(log_file),
                                "size_mb": size_mb
                            })
                    except Exception as e:
                        logger.error(f"Error checking {log_file}: {e}")
            
            health_status["checks"]["log_rotation"] = {
                "status": "healthy" if not large_logs else "warning",
                "large_logs": large_logs
            }
            
            if large_logs:
                health_status["overall_status"] = "warning"
        
        # Check recent alert activity
        try:
            recent_alerts = self._load_recent_alerts(hours=24)
            health_status["checks"]["alert_activity"] = {
                "status": "healthy",
                "recent_alerts": len(recent_alerts),
                "last_24h": len(recent_alerts)
            }
        except Exception as e:
            health_status["checks"]["alert_activity"] = {
                "status": "error",
                "error": str(e)
            }
        
        # Save health report
        health_file = f"reports/health_check_{datetime.now().strftime('%Y%m%d')}.json"
        Path(health_file).parent.mkdir(parents=True, exist_ok=True)
        
        with open(health_file, 'w') as f:
            json.dump(health_status, f, indent=2)
        
        logger.info(f"System health check completed: {health_status['overall_status']}")
        return health_status
    
    def _task_correlation_analysis(self, time_window: int = 3600) -> Dict:
        """Task: Run correlation analysis"""
        
        logger.info("Running correlation analysis")
        
        # Load recent alerts
        hours = time_window / 3600
        alerts = self._load_recent_alerts(hours=hours)
        
        if not alerts:
            return {"status": "no_data", "alerts_count": 0}
        
        # Run correlation
        correlations = self.correlation_engine.process_alerts(alerts)
        
        # Export results
        if correlations:
            export_file = f"reports/correlations_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
            self.correlation_engine.export_correlations(export_file)
        
        result = {
            "status": "success",
            "alerts_analyzed": len(alerts),
            "correlations_found": len(correlations),
            "export_file": export_file if correlations else None
        }
        
        logger.info(f"Correlation analysis completed: {result}")
        return result
    
    def _task_mitre_tagging(self) -> Dict:
        """Task: Apply MITRE ATT&CK tagging to recent alerts"""
        
        logger.info("Applying MITRE ATT&CK tagging")
        
        # Load recent alerts
        alerts = self._load_recent_alerts(hours=24)
        
        if not alerts:
            return {"status": "no_data", "alerts_count": 0}
        
        # Apply MITRE tagging
        tagged_alerts = self.mitre_tagger.tag_alerts(alerts)
        
        # Export results
        export_file = f"reports/mitre_tagged_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
        self.mitre_tagger.export_tagged_alerts(tagged_alerts, export_file)
        
        # Get statistics
        stats = self.mitre_tagger.get_mitre_statistics(tagged_alerts)
        
        result = {
            "status": "success",
            "alerts_processed": len(alerts),
            "alerts_tagged": len([ta for ta in tagged_alerts if ta.mitre_tags]),
            "coverage_percentage": stats.get("coverage_percentage", 0),
            "export_file": export_file
        }
        
        logger.info(f"MITRE tagging completed: {result}")
        return result
    
    def _task_export_alerts(self, format: str = "excel", time_period: int = 24) -> Dict:
        """Task: Export recent alerts"""
        
        logger.info(f"Exporting alerts to {format}")
        
        # Load recent alerts
        alerts = self._load_recent_alerts(hours=time_period)
        
        if not alerts:
            return {"status": "no_data", "alerts_count": 0}
        
        # Export based on format
        export_file = None
        
        if format.lower() == "excel":
            try:
                from utils.excel_export import export_alerts_to_excel
                export_file = f"reports/alerts_export_{datetime.now().strftime('%Y%m%d_%H%M')}.xlsx"
                export_alerts_to_excel(alerts, export_file)
            except Exception as e:
                logger.error(f"Error exporting to Excel: {e}")
        
        elif format.lower() == "json":
            export_file = f"reports/alerts_export_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
            Path(export_file).parent.mkdir(parents=True, exist_ok=True)
            
            with open(export_file, 'w') as f:
                json.dump(alerts, f, indent=2, default=str)
        
        result = {
            "status": "success" if export_file else "error",
            "alerts_exported": len(alerts),
            "export_file": export_file,
            "format": format
        }
        
        logger.info(f"Alert export completed: {result}")
        return result
    
    def _load_recent_alerts(self, hours: float = 24) -> List[Dict]:
        """Load alerts from the last N hours"""
        
        alerts = []
        alert_file = Path("logs/alert_output.json")
        
        if not alert_file.exists():
            return alerts
        
        cutoff_time = time.time() - (hours * 3600)
        
        try:
            with open(alert_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        alert = json.loads(line)
                        alert_time = alert.get('timestamp', 0)
                        
                        if alert_time >= cutoff_time:
                            alerts.append(alert)
                            
        except Exception as e:
            logger.error(f"Error loading alerts: {e}")
        
        return alerts
    
    def add_task(self, task: ScheduledTask):
        """Add a new scheduled task"""
        
        self.tasks.append(task)
        self._save_configuration()
        
        if self.is_running:
            self._schedule_task(task)
        
        logger.info(f"Added scheduled task: {task.name}")
    
    def remove_task(self, task_name: str) -> bool:
        """Remove a scheduled task"""
        
        for i, task in enumerate(self.tasks):
            if task.name == task_name:
                del self.tasks[i]
                self._save_configuration()
                logger.info(f"Removed scheduled task: {task_name}")
                return True
        
        return False
    
    def enable_task(self, task_name: str) -> bool:
        """Enable a scheduled task"""
        
        for task in self.tasks:
            if task.name == task_name:
                task.enabled = True
                self._save_configuration()
                logger.info(f"Enabled task: {task_name}")
                return True
        
        return False
    
    def disable_task(self, task_name: str) -> bool:
        """Disable a scheduled task"""
        
        for task in self.tasks:
            if task.name == task_name:
                task.enabled = False
                self._save_configuration()
                logger.info(f"Disabled task: {task_name}")
                return True
        
        return False
    
    def get_task_status(self) -> List[Dict]:
        """Get status of all scheduled tasks"""
        
        status_list = []
        
        for task in self.tasks:
            status = {
                "name": task.name,
                "description": task.description,
                "enabled": task.enabled,
                "schedule": f"{task.schedule_type} at {task.schedule_time}",
                "last_run": datetime.fromtimestamp(task.last_run).isoformat() if task.last_run else "Never",
                "run_count": task.run_count,
                "last_success": task.last_success,
                "last_error": task.last_error
            }
            status_list.append(status)
        
        return status_list
    
    def run_task_now(self, task_name: str) -> Dict:
        """Run a task immediately"""
        
        for task in self.tasks:
            if task.name == task_name:
                logger.info(f"Running task immediately: {task_name}")
                return self._execute_task(task)
        
        return {"status": "error", "message": f"Task not found: {task_name}"}


def main():
    """Main function for testing task scheduler"""
    
    if not SCHEDULE_AVAILABLE:
        print("❌ Schedule library not available")
        print("Install required package: pip install schedule")
        return
    
    # Create scheduler
    scheduler = TaskScheduler()
    
    # Show current tasks
    print(f"\n📋 Scheduled Tasks:")
    print("=" * 60)
    
    for task in scheduler.tasks:
        status = "✅ Enabled" if task.enabled else "❌ Disabled"
        print(f"{status} {task.name}")
        print(f"   Description: {task.description}")
        print(f"   Schedule: {task.schedule_type} at {task.schedule_time}")
        print(f"   Function: {task.task_function}")
        print(f"   Last Run: {datetime.fromtimestamp(task.last_run).strftime('%Y-%m-%d %H:%M:%S') if task.last_run else 'Never'}")
        print()
    
    # Test running a task
    print("🧪 Testing log analysis task...")
    result = scheduler.run_task_now("Daily Log Analysis")
    print(f"Result: {result}")
    
    # Test system health check
    print("\n🏥 Testing system health check...")
    result = scheduler.run_task_now("System Health Check")
    print(f"Health Status: {result.get('overall_status', 'Unknown')}")
    
    print(f"\n✅ Scheduler test completed")
    print(f"📁 Configuration saved to: {scheduler.config_file}")


if __name__ == "__main__":
    main()
