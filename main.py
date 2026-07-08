#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cyber-Defense-Shield v1.4
Multi-Layered Security Tool for Linux Systems
Main Application Controller
"""

import os
import sys
import argparse
import signal
import time
import logging
import logging.handlers
from datetime import datetime
from defense_modules import (
    SecurityScanner,
    NetworkMonitor,
    DDosProtector,
    FirewallManager,
    SystemHardener,
    LogAnalyzer,
    RealtimeThreatDetector,
    ReportGenerator,
    VulnerabilityScanner,
    IntrusionDetectionSystem,
    MalwareDetector,
    UserActivityAuditor,
    AdvancedReporter,
    AlertNotifier,
    WebAttackScanner
)


class CyberDefenseShield:
    """Main Application Class - Cyber-Defense-Shield v1.4"""
    
    def __init__(self):
        """Initialize the application"""
        self.security_scanner = SecurityScanner()
        self.network_monitor = NetworkMonitor()
        self.ddos_protector = DDosProtector()
        self.firewall_manager = FirewallManager()
        self.system_hardener = SystemHardener()
        self.log_analyzer = LogAnalyzer()
        self.realtime_detector = RealtimeThreatDetector()
        self.report_generator = ReportGenerator()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.ids = IntrusionDetectionSystem()
        self.malware_detector = MalwareDetector()
        self.user_auditor = UserActivityAuditor()
        self.advanced_reporter = AdvancedReporter()
        self.notifier = AlertNotifier()
        self.web_attack_scanner = WebAttackScanner()
    
    def print_banner(self):
        """Display application banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║             🛡️  CYBER-DEFENSE-SHIELD v1.4 - Linux Security Tool 🛡️        ║
║                                                                           ║
║              Multi-Layered Cybersecurity Defense System                   ║
║                   Kali Linux / Debian-Based Linux                         ║
║                                                                           ║
║  ✓ Security Scanning          ✓ Network Monitoring                       ║
║  ✓ DDoS Protection             ✓ Firewall Management                      ║
║  ✓ System Hardening            ✓ Log Analysis                             ║
║  ✓ Threat Detection            ✓ Real-time Monitoring                     ║
║  ✓ Vulnerability Scanning      ✓ Intrusion Detection                      ║
║  ✓ Malware Detection           ✓ User Activity Auditing                   ║
║  ✓ Advanced Reporting          ✓ Comprehensive Assessment                 ║
║                                                                           ║
║              Cyber-Rage Security Team © 2026                             ║
║              MIT License | Open Source | Community Driven                ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def print_menu(self):
        """Display main menu"""
        menu = """
┌─────────────────────────────────────────────────────────────────────────┐
│                      MAIN MENU - SELECT AN OPTION                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1.  🔍 Full System Security Scan                                       │
│  2.  🌐 Network Monitoring & Analysis                                   │
│  3.  🚨 DDoS/DoS Protection & Mitigation                                │
│  4.  🔥 Firewall Management & Configuration                             │
│  5.  🔐 System Hardening & Security Enhancement                         │
│  6.  📊 Log Analysis & Threat Detection                                 │
│  7.  ⚡ Real-time Threat Detection & Prevention                         │
│  8.  📋 Generate Security Report (Basic)                                │
│  9.  🔎 Vulnerability Scanner                                           │
│  10. 🛡️ Intrusion Detection System (IDS)                               │
│  11. 🦠 Malware Detection & Analysis                                    │
│  12. 👤 User Activity Auditing & Monitoring                             │
│  13. 📈 Advanced Comprehensive Report                                   │
│  14. 🔄 Run All Security Checks (Full Assessment)                       │
│  15. 🌐 Web Attack Scan (SQLi / XSS / Path Traversal)                   │
│  16. ❌ Exit Program                                                     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
        """
        print(menu)
    
    def check_root(self):
        """Check if running with root privileges"""
        try:
            is_root = os.geteuid() == 0
        except AttributeError:
            # os.geteuid() doesn't exist on non-POSIX platforms (e.g. Windows).
            # This tool relies on Linux-only utilities (ufw, iptables, ss,
            # auditctl, dpkg, ...) regardless, but we fail gracefully here
            # instead of crashing with an unhandled AttributeError.
            print("\n[!] WARNING: Root check is unavailable on this platform.")
            print("[!] Cyber-Defense-Shield requires a Linux system (Kali/Debian-based) to function.\n")
            return False

        if not is_root:
            print("\n[!] WARNING: This tool requires root/sudo privileges!")
            print("[!] Some features may not work without root access.")
            print("[*] Run with: sudo python3 main.py\n")
            return False
        return True
    
    def run_option_1(self):
        """Full System Security Scan"""
        print("\n" + "="*70)
        print("[*] FULL SYSTEM SECURITY SCAN")
        print("="*70)
        
        print("\n[*] Step 1: Scanning open ports...")
        self.security_scanner.scan_open_ports()
        
        print("\n[*] Step 2: Checking suspicious processes...")
        self.security_scanner.check_suspicious_processes()
        
        print("\n[*] Step 3: Analyzing firewall status...")
        self.security_scanner.check_firewall()
        
        print("\n[*] Step 4: Verifying SSH security...")
        self.security_scanner.check_ssh_security()
        
        print("\n[*] Step 5: Scanning installed packages...")
        self.security_scanner.check_suspicious_packages()
        
        print("\n[*] Step 6: Checking running services...")
        self.security_scanner.check_running_services()
        
        print("\n[+] Full System Security Scan COMPLETE!\n")
    
    def run_option_2(self):
        """Network Monitoring & Analysis"""
        print("\n" + "="*70)
        print("[*] NETWORK MONITORING & ANALYSIS")
        print("="*70)
        
        print("\n[*] Monitoring active connections...")
        self.network_monitor.monitor_connections()
        
        print("\n[*] Analyzing network traffic...")
        self.network_monitor.analyze_traffic()
        
        print("\n[*] Detecting suspicious IP addresses...")
        self.network_monitor.detect_suspicious_ips()
        
        print("\n[+] Network Analysis COMPLETE!\n")
    
    def run_option_3(self):
        """DDoS/DoS Protection"""
        print("\n" + "="*70)
        print("[*] DDOS/DOS PROTECTION & MITIGATION")
        print("="*70)
        
        print("\n[*] Enabling rate limiting...")
        self.ddos_protector.enable_rate_limiting()
        
        print("\n[*] Enabling SYN flood protection...")
        self.ddos_protector.enable_syn_flood_protection()
        
        print("\n[*] Enabling UDP flood protection...")
        self.ddos_protector.enable_udp_flood_protection()
        
        print("\n[*] Enabling ICMP flood protection...")
        self.ddos_protector.enable_icmp_flood_protection()
        
        print("\n[*] Enabling anti-spoofing protection...")
        self.ddos_protector.enable_anti_spoofing_protection()
        
        print("\n[*] Monitoring traffic anomalies...")
        self.ddos_protector.monitor_traffic_anomalies()
        
        print("\n[+] DDoS/DoS Protection ENABLED!\n")
    
    def run_option_4(self):
        """Firewall Management"""
        print("\n" + "="*70)
        print("[*] FIREWALL MANAGEMENT & CONFIGURATION")
        print("="*70)
        
        print("\n[*] Enabling firewall...")
        self.firewall_manager.enable_firewall()
        
        print("\n[*] Adding security rules...")
        self.firewall_manager.add_security_rules()
        
        print("\n[*] Closing dangerous ports...")
        self.firewall_manager.close_dangerous_ports()
        
        print("\n[*] Enabling incoming traffic monitoring...")
        self.firewall_manager.enable_incoming_monitoring()
        
        print("\n[+] Firewall Configuration COMPLETE!\n")
    
    def run_option_5(self):
        """System Hardening"""
        print("\n" + "="*70)
        print("[*] SYSTEM HARDENING & SECURITY ENHANCEMENT")
        print("="*70)
        
        print("\n[*] Hardening SSH configuration...")
        self.system_hardener.harden_ssh()
        
        print("\n[*] Updating system packages...")
        self.system_hardener.update_system()
        
        print("\n[*] Disabling unnecessary services...")
        self.system_hardener.disable_unnecessary_services()
        
        print("\n[*] Hardening sudo configuration...")
        self.system_hardener.harden_sudo()
        
        print("\n[*] Enabling audit logging...")
        self.system_hardener.enable_audit_logging()
        
        print("\n[+] System Hardening COMPLETE!\n")
    
    def run_option_6(self):
        """Log Analysis & Threat Detection"""
        print("\n" + "="*70)
        print("[*] LOG ANALYSIS & THREAT DETECTION")
        print("="*70)
        
        print("\n[*] Analyzing authentication logs...")
        self.log_analyzer.analyze_auth_log()
        
        print("\n[*] Analyzing system logs...")
        self.log_analyzer.analyze_syslog()
        
        print("\n[*] Detecting attack patterns...")
        self.log_analyzer.detect_attack_patterns()
        
        print("\n[*] Checking syscall audit events...")
        self.log_analyzer.check_syscall_audit_events()
        
        print("\n[+] Log Analysis COMPLETE!\n")
    
    def run_option_7(self):
        """Real-time Threat Detection"""
        print("\n" + "="*70)
        print("[*] REAL-TIME THREAT DETECTION & PREVENTION")
        print("="*70)
        print("\n[*] Starting real-time monitoring (Press Ctrl+C to stop)...\n")
        
        self.realtime_detector.start_realtime_monitoring()
        
        print("\n[+] Real-time Monitoring STOPPED!\n")
    
    def run_option_8(self):
        """Generate Basic Report"""
        print("\n" + "="*70)
        print("[*] GENERATING SECURITY REPORT")
        print("="*70)
        
        report_file = self.report_generator.generate_html_report()
        
        if report_file:
            print(f"\n[+] Report generated successfully!")
            print(f"[+] Location: {report_file}\n")
        else:
            print("\n[!] Error generating report!\n")
    
    def run_option_9(self):
        """Vulnerability Scanner"""
        print("\n" + "="*70)
        print("[*] VULNERABILITY SCANNER")
        print("="*70)
        
        print("\n[*] Scanning system for vulnerabilities...")
        vulnerabilities = self.vulnerability_scanner.scan_system_vulnerabilities()
        
        print("\n[*] Checking for CVE security updates...")
        self.vulnerability_scanner.check_cve_updates()
        
        if vulnerabilities:
            print("\n[!] VULNERABILITIES FOUND:")
            for vuln in vulnerabilities:
                print(f"    - {vuln}")
        else:
            print("\n[+] No critical vulnerabilities detected!")
        
        print("\n[+] Vulnerability Scan COMPLETE!\n")
    
    def run_option_10(self):
        """Intrusion Detection System"""
        print("\n" + "="*70)
        print("[*] INTRUSION DETECTION SYSTEM (IDS)")
        print("="*70)
        
        print("\n[*] Analyzing network behavior for intrusions...")
        threats = self.ids.analyze_network_behavior()
        
        print("\n[*] Monitoring suspicious connections...")
        suspicious = self.ids.monitor_suspicious_connections()
        
        print("\n[*] Checking for ARP spoofing (MITM indicators)...")
        arp_findings = self.ids.detect_arp_spoofing()
        threats.extend(arp_findings)
        
        if threats:
            print("\n[!] THREATS DETECTED:")
            for threat in threats:
                print(f"    - {threat}")
        else:
            print("\n[+] No active threats detected!")
        
        print("\n[+] IDS Analysis COMPLETE!\n")
    
    def run_option_11(self):
        """Malware Detection"""
        print("\n" + "="*70)
        print("[*] MALWARE DETECTION & ANALYSIS")
        print("="*70)
        
        print("\n[*] Scanning for suspicious files...")
        suspicious_files = self.malware_detector.scan_for_suspicious_files()
        
        print("\n[*] Checking file integrity...")
        hashes = self.malware_detector.check_file_hashes()
        
        print("\n[*] Analyzing executable behavior...")
        suspicious_processes = self.malware_detector.scan_executable_behavior()
        
        print("\n[*] Analyzing kernel modules...")
        flagged_modules = self.malware_detector.analyze_kernel_modules()
        
        print("\n[*] Checking basic rootkit indicators...")
        rootkit_findings = self.malware_detector.check_rootkit_indicators()
        
        if suspicious_files:
            print("\n[!] SUSPICIOUS FILES FOUND:")
            for file in suspicious_files:
                print(f"    - {file}")
        else:
            print("\n[+] No suspicious files detected!")
        
        if flagged_modules or rootkit_findings:
            print("\n[!] ROOTKIT/KERNEL INDICATORS FOUND:")
            for item in flagged_modules + rootkit_findings:
                print(f"    - {item}")
        
        print("\n[+] Malware Detection COMPLETE!\n")
    
    def run_option_12(self):
        """User Activity Auditing"""
        print("\n" + "="*70)
        print("[*] USER ACTIVITY AUDITING & MONITORING")
        print("="*70)
        
        print("\n[*] Auditing user login history...")
        self.user_auditor.audit_user_logins()
        
        print("\n[*] Checking privilege escalation...")
        self.user_auditor.audit_privilege_escalation()
        
        print("\n[*] Monitoring critical file access...")
        self.user_auditor.monitor_file_access()
        
        print("\n[*] Retrieving system users...")
        users = self.user_auditor.get_system_users()
        
        print("\n[+] User Activity Audit COMPLETE!\n")
    
    def run_option_13(self):
        """Advanced Comprehensive Report"""
        print("\n" + "="*70)
        print("[*] ADVANCED COMPREHENSIVE REPORT GENERATION")
        print("="*70)
        
        report_file = self.advanced_reporter.generate_comprehensive_report()
        
        if report_file:
            print(f"\n[+] Comprehensive report generated successfully!")
            print(f"[+] Location: {report_file}\n")
        else:
            print("\n[!] Error generating report!\n")
    
    def run_option_14(self):
        """Run All Security Checks"""
        print("\n" + "="*70)
        print("[*] RUNNING FULL SECURITY ASSESSMENT")
        print("="*70)
        
        print("\n[*] This will run all security checks...")
        print("[*] This may take several minutes...\n")
        
        # Run all checks
        self.run_option_1()
        self.run_option_2()
        self.run_option_6()
        self.run_option_9()
        self.run_option_10()
        self.run_option_11()
        self.run_option_12()
        self.run_option_15()
        
        # Generate comprehensive report
        print("\n[*] Generating comprehensive report...")
        self.run_option_13()
        
        print("\n" + "="*70)
        print("[+] FULL SECURITY ASSESSMENT COMPLETE!")
        print("="*70 + "\n")
    
    def run_option_15(self):
        """Web Attack Scan (SQLi / XSS / Path Traversal)"""
        print("\n" + "="*70)
        print("[*] WEB ATTACK SCAN (SQLi / XSS / PATH TRAVERSAL)")
        print("="*70)
        
        findings = self.web_attack_scanner.scan_web_logs()
        
        if findings:
            print("\n[!] SIGNATURE MATCHES FOUND:")
            for item in findings:
                print(f"    - {item}")
        
        print("\n[+] Web Attack Scan COMPLETE!\n")
    
    def run_daemon(self, interval=300):
        """Run continuously in the background, without the interactive menu.

        Intended for systemd (see cyber-defense-shield.service). Each
        cycle runs detection-only checks (IDS, suspicious IPs, suspicious
        processes/files) and sends an alert via AlertNotifier if anything
        actionable is found. Deliberately does NOT re-run firewall/SSH/
        sudo hardening or `apt-get upgrade` automatically each cycle -
        those are mutating operations that stay under manual control via
        the interactive menu, since silently re-applying system changes
        on a timer is a materially riskier feature than monitoring.

        Handles SIGTERM/SIGINT so `systemctl stop` shuts it down cleanly
        instead of being killed mid-check.
        """
        log_file = None
        try:
            import config as _cfg_mod
            log_file = getattr(_cfg_mod, 'LOG_FILE', None)
        except Exception:
            pass

        # Uses the standard logging module with a size-based rotating file
        # handler, instead of a manual open()/write() per line. The manual
        # version had no rotation, so a daemon left running for weeks would
        # grow the log file without bound. 5MB x 3 backups keeps a bounded
        # history on disk regardless of how long the daemon has been up.
        logger = logging.getLogger('cyber_defense_shield')
        logger.setLevel(logging.INFO)
        logger.handlers.clear()

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(console_handler)

        if log_file:
            try:
                os.makedirs(os.path.dirname(log_file) or '.', exist_ok=True)
                file_handler = logging.handlers.RotatingFileHandler(
                    log_file, maxBytes=5 * 1024 * 1024, backupCount=3
                )
                file_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
                logger.addHandler(file_handler)
            except Exception as e:
                logger.warning(f"[!] Could not set up log file at {log_file}, console-only: {e}")

        state = {'running': True}

        def _stop(signum, frame):
            logger.info("Daemon received stop signal, shutting down gracefully...")
            state['running'] = False

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)

        logger.info(f"[*] Cyber-Defense-Shield daemon started (PID={os.getpid()}, interval={interval}s)")
        self.check_root()

        while state['running']:
            cycle_start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            logger.info(f"--- Daemon cycle: {cycle_start} ---")
            findings = []

            try:
                findings.extend(self.ids.analyze_network_behavior())
            except Exception as e:
                logger.warning(f"[!] Daemon IDS check failed: {e}")

            try:
                suspicious_ips = self.network_monitor.detect_suspicious_ips()
                if suspicious_ips:
                    findings.append(f"{len(suspicious_ips)} suspicious source IP(s): {', '.join(suspicious_ips[:5])}")
            except Exception as e:
                logger.warning(f"[!] Daemon network check failed: {e}")

            try:
                suspicious_procs = self.security_scanner.check_suspicious_processes()
                if suspicious_procs:
                    findings.append(f"{len(suspicious_procs)} suspicious process(es) detected")
            except Exception as e:
                logger.warning(f"[!] Daemon process check failed: {e}")

            try:
                suspicious_files = self.malware_detector.scan_for_suspicious_files()
                if suspicious_files:
                    findings.append(f"{len(suspicious_files)} suspicious file(s) found")
            except Exception as e:
                logger.warning(f"[!] Daemon file scan failed: {e}")

            try:
                web_findings = self.web_attack_scanner.scan_web_logs()
                findings.extend(web_findings)
            except Exception as e:
                logger.warning(f"[!] Daemon web attack scan failed: {e}")

            try:
                arp_findings = self.ids.detect_arp_spoofing()
                findings.extend(arp_findings)
            except Exception as e:
                logger.warning(f"[!] Daemon ARP spoofing check failed: {e}")

            if findings:
                logger.info(f"[!] {len(findings)} finding(s) this cycle:")
                for item in findings:
                    logger.info(f"    - {item}")
                self.notifier.send_alert("Findings detected", findings)
            else:
                logger.info("[+] No actionable findings this cycle")

            # Sleep in short increments so a stop signal is honored quickly
            # rather than blocking for the full interval.
            slept = 0
            while slept < interval and state['running']:
                time.sleep(min(5, interval - slept))
                slept += 5

        logger.info("[+] Daemon stopped. Stay secure!")

    def run(self):
        """Main application loop"""
        self.print_banner()
        
        # Check root privileges
        is_root = self.check_root()
        
        while True:
            self.print_menu()
            
            try:
                choice = input("\n[*] Enter your choice (1-16): ").strip()
                
                if choice == '1':
                    self.run_option_1()
                elif choice == '2':
                    self.run_option_2()
                elif choice == '3':
                    self.run_option_3()
                elif choice == '4':
                    self.run_option_4()
                elif choice == '5':
                    self.run_option_5()
                elif choice == '6':
                    self.run_option_6()
                elif choice == '7':
                    self.run_option_7()
                elif choice == '8':
                    self.run_option_8()
                elif choice == '9':
                    self.run_option_9()
                elif choice == '10':
                    self.run_option_10()
                elif choice == '11':
                    self.run_option_11()
                elif choice == '12':
                    self.run_option_12()
                elif choice == '13':
                    self.run_option_13()
                elif choice == '14':
                    self.run_option_14()
                elif choice == '15':
                    self.run_option_15()
                elif choice == '16':
                    print("\n[*] Exiting Cyber-Defense-Shield...")
                    print("[+] Stay secure! 🛡️\n")
                    sys.exit(0)
                else:
                    print("\n[!] Invalid choice! Please enter a number between 1-16.\n")
            
            except KeyboardInterrupt:
                print("\n\n[*] Interrupted by user...")
                print("[+] Stay secure! 🛡️\n")
                sys.exit(0)
            except Exception as e:
                print(f"\n[!] Error: {e}\n")


def parse_args():
    """Parse command-line arguments for daemon mode."""
    parser = argparse.ArgumentParser(
        description="Cyber-Defense-Shield v1.4 - Multi-Layered Cybersecurity Defense System"
    )
    parser.add_argument(
        '--daemon', action='store_true',
        help='Run continuously in the background (detection + alerts only), skipping the interactive menu'
    )
    parser.add_argument(
        '--interval', type=int, default=None,
        help='Seconds between check cycles in --daemon mode (default: from config.py, or 300)'
    )
    return parser.parse_args()


def main():
    """Main entry point"""
    args = parse_args()
    app = CyberDefenseShield()

    if args.daemon:
        interval = args.interval
        if interval is None:
            try:
                import config as _cfg_mod
                interval = getattr(_cfg_mod, 'DAEMON_SCAN_INTERVAL_SECONDS', 300)
            except Exception:
                interval = 300
        app.run_daemon(interval=interval)
    else:
        app.run()


if __name__ == "__main__":
    main()
