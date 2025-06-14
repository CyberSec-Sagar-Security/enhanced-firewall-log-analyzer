#!/usr/bin/env python3
"""
SOC Firewall Log Analyzer - Feature Launcher
Easy launcher for all SOC features and capabilities
Author: SOC Team
"""

import os
import sys
import subprocess
from colorama import Fore, Style, init

# Initialize colorama
init()


def print_banner():
    """Print the main banner"""
    print(f"""
{Fore.RED + Style.BRIGHT}
  ╔══════════════════════════════════════════════════════════════╗
  ║                   🔥 SOC FIREWALL ANALYZER 🔥                ║
  ║              Advanced Security Operations Center              ║
  ║                     Feature Launcher                         ║
  ╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")


def print_features():
    """Print available features"""
    features = {
        "✅ CORE FEATURES (Working)": [
            "🔍 Log file parsing (Windows Firewall CSV)",
            "🚨 Detection logic for known bad ports (135, 3389, etc.)",
            "📊 Frequency-based detection (e.g., 5 rapid connections)", 
            "🌙 Off-hours anomaly detection",
            "🐚 Reverse shell pattern (port 4444/5555)",
            "🔔 Local alerting with win10toast",
            "🎨 Color-coded terminal alerts with colorama",
            "📄 Export alerts to structured JSON",
            "📊 Summary report generation (Excel)",
            "🌐 Fully offline operation"
        ],
        "🚀 ADVANCED FEATURES (Available)": [
            "📡 Live log tailing (Watch firewall.log file in real-time)",
            "🎯 Streamlit GUI Dashboard (Show alert graphs, filters, timeline)",
            "🔗 Correlation Engine (Combine alerts by IP → Flag multi-stage attacks)",
            "📑 Auto report generation (PDF) (Use jinja2 to turn JSON alerts into reports)",
            "🏷️  MITRE ATT&CK Tagging (Add tags like T1021.001 for RDP)",
            "⏰ Scheduling (Use schedule or Task Scheduler to run daily on logs)"
        ]
    }
    
    for category, items in features.items():
        print(f"\n{Fore.CYAN + Style.BRIGHT}{category}{Style.RESET_ALL}")
        for item in items:
            print(f"  {item}")


def print_menu():
    """Print the main menu"""
    print(f"""
{Fore.YELLOW + Style.BRIGHT}🚀 CHOOSE YOUR MISSION:{Style.RESET_ALL}

{Fore.GREEN}1.{Style.RESET_ALL} 📊 {Fore.WHITE + Style.BRIGHT}Basic Analysis{Style.RESET_ALL} - Analyze a log file (current working version)
{Fore.GREEN}2.{Style.RESET_ALL} 🔥 {Fore.WHITE + Style.BRIGHT}Enhanced Analysis{Style.RESET_ALL} - Full SOC analysis with all features
{Fore.GREEN}3.{Style.RESET_ALL} 📡 {Fore.WHITE + Style.BRIGHT}Live Monitoring{Style.RESET_ALL} - Real-time log file monitoring
{Fore.GREEN}4.{Style.RESET_ALL} 🎯 {Fore.WHITE + Style.BRIGHT}GUI Dashboard{Style.RESET_ALL} - Launch web-based dashboard
{Fore.GREEN}5.{Style.RESET_ALL} 📅 {Fore.WHITE + Style.BRIGHT}Schedule Analysis{Style.RESET_ALL} - Setup automated daily/weekly scans
{Fore.GREEN}6.{Style.RESET_ALL} 🛠️  {Fore.WHITE + Style.BRIGHT}Install Dependencies{Style.RESET_ALL} - Install all required packages
{Fore.GREEN}7.{Style.RESET_ALL} 📋 {Fore.WHITE + Style.BRIGHT}View Sample Commands{Style.RESET_ALL} - See example usage
{Fore.GREEN}8.{Style.RESET_ALL} ❌ {Fore.WHITE + Style.BRIGHT}Exit{Style.RESET_ALL}

{Fore.CYAN}Enter your choice (1-8):{Style.RESET_ALL} """)


def run_basic_analysis():
    """Run basic analysis (current working version)"""
    print(f"\n{Fore.GREEN}📊 BASIC ANALYSIS MODE{Style.RESET_ALL}")
    print("This is the current working version with table output and Excel reports.")
    
    log_file = input(f"\n{Fore.CYAN}Enter log file path (or press Enter for test file):{Style.RESET_ALL} ").strip()
    if not log_file:
        log_file = "test_logs/sample_windows_fw.csv"
    
    parser_type = input(f"{Fore.CYAN}Enter parser type (windows/pfsense) [windows]:{Style.RESET_ALL} ").strip()
    if not parser_type:
        parser_type = "windows"
    
    print(f"\n{Fore.YELLOW}🚀 Running analysis...{Style.RESET_ALL}")
    
    cmd = f'python main.py --logfile "{log_file}" --parser {parser_type}'
    os.system(cmd)


def run_enhanced_analysis():
    """Run enhanced analysis with all features"""
    print(f"\n{Fore.RED}🔥 ENHANCED ANALYSIS MODE{Style.RESET_ALL}")
    print("Full SOC analysis with correlation, MITRE tagging, and PDF reports.")
    
    log_file = input(f"\n{Fore.CYAN}Enter log file path (or press Enter for test file):{Style.RESET_ALL} ").strip()
    if not log_file:
        log_file = "test_logs/sample_windows_fw.csv"
    
    parser_type = input(f"{Fore.CYAN}Enter parser type (windows/pfsense) [windows]:{Style.RESET_ALL} ").strip()
    if not parser_type:
        parser_type = "windows"
    
    # Options
    print(f"\n{Fore.CYAN}🛠️  Enhanced Features:{Style.RESET_ALL}")
    correlation = input("Enable correlation analysis? (y/n) [y]: ").strip().lower()
    correlation = "--correlation" if correlation != 'n' else ""
    
    mitre = input("Enable MITRE ATT&CK tagging? (y/n) [y]: ").strip().lower()
    mitre = "--mitre" if mitre != 'n' else ""
    
    pdf = input("Generate PDF report? (y/n) [n]: ").strip().lower()
    pdf = "--pdf" if pdf == 'y' else ""
    
    print(f"\n{Fore.YELLOW}🚀 Running enhanced analysis...{Style.RESET_ALL}")
    
    cmd = f'python enhanced_main.py --logfile "{log_file}" --parser {parser_type} {correlation} {mitre} {pdf}'
    os.system(cmd)


def run_live_monitoring():
    """Run live monitoring"""
    print(f"\n{Fore.BLUE}📡 LIVE MONITORING MODE{Style.RESET_ALL}")
    print("Monitor log files in real-time and detect threats as they happen.")
    
    log_file = input(f"\n{Fore.CYAN}Enter log file path to monitor:{Style.RESET_ALL} ").strip()
    if not log_file:
        print(f"{Fore.RED}❌ Log file path is required for live monitoring{Style.RESET_ALL}")
        return
    
    parser_type = input(f"{Fore.CYAN}Enter parser type (windows/pfsense) [windows]:{Style.RESET_ALL} ").strip()
    if not parser_type:
        parser_type = "windows"
    
    print(f"\n{Fore.YELLOW}📡 Starting live monitoring... Press Ctrl+C to stop{Style.RESET_ALL}")
    
    cmd = f'python enhanced_main.py --live --logfile "{log_file}" --parser {parser_type}'
    os.system(cmd)


def launch_gui_dashboard():
    """Launch the GUI dashboard"""
    print(f"\n{Fore.MAGENTA}🎯 LAUNCHING GUI DASHBOARD{Style.RESET_ALL}")
    print("Starting Streamlit web dashboard...")
    
    try:
        cmd = "streamlit run gui/dashboard.py"
        os.system(cmd)
    except Exception as e:
        print(f"{Fore.RED}❌ Error launching dashboard: {e}{Style.RESET_ALL}")
        print("Make sure Streamlit is installed: pip install streamlit")


def setup_scheduling():
    """Setup scheduled analysis"""
    print(f"\n{Fore.CYAN}📅 SCHEDULING SETUP{Style.RESET_ALL}")
    print("Setup automated analysis to run daily/weekly.")
    
    print("Starting scheduler with default configuration...")
    cmd = "python enhanced_main.py --schedule"
    os.system(cmd)


def install_dependencies():
    """Install all dependencies"""
    print(f"\n{Fore.GREEN}🛠️  INSTALLING DEPENDENCIES{Style.RESET_ALL}")
    
    print("Installing core dependencies...")
    os.system("pip install -r requirements.txt")
    
    print(f"\n{Fore.GREEN}✅ Installation complete!{Style.RESET_ALL}")


def show_sample_commands():
    """Show sample commands"""
    print(f"\n{Fore.YELLOW + Style.BRIGHT}📋 SAMPLE COMMANDS{Style.RESET_ALL}")
    
    commands = [
        ("Basic Analysis", "python main.py --logfile test_logs/sample_windows_fw.csv --parser windows"),
        ("Enhanced with All Features", "python enhanced_main.py --logfile test_logs/sample_windows_fw.csv --parser windows --correlation --mitre --pdf"),
        ("Live Monitoring", "python enhanced_main.py --live --logfile firewall.log --parser windows"),
        ("GUI Dashboard", "streamlit run gui/dashboard.py"),
        ("Scheduled Analysis", "python enhanced_main.py --schedule"),
        ("Quiet Mode", "python main.py --logfile sample.csv --parser windows --quiet")
    ]
    
    for name, cmd in commands:
        print(f"\n{Fore.CYAN}{name}:{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}{cmd}{Style.RESET_ALL}")


def main():
    """Main launcher function"""
    
    while True:
        print_banner()
        print_features()
        print_menu()
        
        try:
            choice = input().strip()
            
            if choice == '1':
                run_basic_analysis()
            elif choice == '2':
                run_enhanced_analysis()
            elif choice == '3':
                run_live_monitoring()
            elif choice == '4':
                launch_gui_dashboard()
            elif choice == '5':
                setup_scheduling()
            elif choice == '6':
                install_dependencies()
            elif choice == '7':
                show_sample_commands()
            elif choice == '8':
                print(f"\n{Fore.GREEN}👋 Thanks for using SOC Firewall Analyzer!{Style.RESET_ALL}")
                break
            else:
                print(f"\n{Fore.RED}❌ Invalid choice. Please enter 1-8.{Style.RESET_ALL}")
            
            input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
            
        except KeyboardInterrupt:
            print(f"\n\n{Fore.GREEN}👋 Thanks for using SOC Firewall Analyzer!{Style.RESET_ALL}")
            break
        except Exception as e:
            print(f"\n{Fore.RED}❌ Error: {e}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
