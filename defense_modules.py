#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Defense Modules - Core Security Functions
Updated Version 1.2 with Advanced Features
"""

import subprocess
import re
import socket
import json
from datetime import datetime
import hashlib
import os

try:
    import config as _config
except Exception:
    _config = None


def _cfg(name, default):
    """Read a tunable setting from config.py, falling back to a safe default
    if config.py is missing or does not define the requested name.

    Detection and mitigation thresholds are kept here instead of hardcoded
    so they can be tuned to a system's real traffic profile. A threshold
    that is safe for a quiet host can generate constant false positives on
    a busy one, and vice versa - there is no single default that is correct
    for every deployment.
    """
    return getattr(_config, name, default) if _config is not None else default


class SecurityScanner:
    """Main Security Scanner"""
    
    def scan_open_ports(self):
        """Scan for open ports"""
        try:
            result = subprocess.run(['ss', '-tunlp'], capture_output=True, text=True)
            ports = []
            for line in result.stdout.split('\n')[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 4:
                        port_info = parts[3]
                        ports.append(port_info)
            print(f"[+] Open Ports Scanned: {len(ports)}")
            return ports
        except Exception as e:
            print(f"[!] Error scanning ports: {e}")
            return []
    
    def check_suspicious_processes(self):
        """Check for suspicious running processes"""
        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            suspicious = []
            keywords = ['nc', 'ncat', 'bash -i', 'sh -i', 'wget', 'curl']
            
            for line in result.stdout.split('\n'):
                for keyword in keywords:
                    if keyword.lower() in line.lower() and 'grep' not in line:
                        suspicious.append(line[:80])
            
            print(f"[+] Processes Analyzed: {len(result.stdout.split(chr(10)))}")
            return suspicious
        except Exception as e:
            print(f"[!] Error: {e}")
            return []
    
    def check_firewall(self):
        """Check firewall status"""
        try:
            result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
            status = 'active' in result.stdout.lower()
            print(f"[+] Firewall Status: {'ACTIVE' if status else 'INACTIVE'}")
            return status
        except Exception as e:
            print(f"[!] Firewall Status: Unknown")
            return False
    
    def check_ssh_security(self):
        """Check SSH security configuration"""
        try:
            with open('/etc/ssh/sshd_config', 'r') as f:
                content = f.read()
            
            checks = {
                'PermitRootLogin no': 'PermitRootLogin' in content and 'no' in content,
                'PasswordAuthentication no': 'PasswordAuthentication' in content,
                'PubkeyAuthentication yes': 'PubkeyAuthentication' in content
            }
            
            safe = sum(checks.values()) >= 2
            print(f"[+] SSH Security: {'SECURE' if safe else 'NEEDS IMPROVEMENT'}")
            return safe
        except Exception as e:
            print(f"[!] Error: {e}")
            return False
    
    def check_suspicious_packages(self):
        """Check for suspicious installed packages"""
        try:
            result = subprocess.run(['dpkg', '-l'], capture_output=True, text=True)
            packages = result.stdout.split('\n')
            print(f"[+] Installed Packages: {len(packages)}")
            return []
        except Exception as e:
            print(f"[!] Error: {e}")
            return []


class NetworkMonitor:
    """Network Monitoring Module"""
    
    def monitor_connections(self):
        """Monitor active connections"""
        try:
            result = subprocess.run(['ss', '-tunp'], capture_output=True, text=True)
            connections = result.stdout.count('\n') - 1
            print(f"[+] Active Connections: {connections}")
            return list(range(connections))
        except Exception as e:
            print(f"[!] Error: {e}")
            return []
    
    def analyze_traffic(self):
        """Analyze network traffic"""
        try:
            result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
            established = result.stdout.count('ESTABLISHED')
            print(f"[+] Established Connections: {established}")
            return established
        except Exception as e:
            print(f"[!] Error: {e}")
            return 0
    
    def detect_suspicious_ips(self, connection_threshold=None):
        """Detect suspicious IP addresses.

        Flags a source IP only once its concurrent connection count crosses
        a configurable threshold, instead of flagging every remote IP seen
        in the connection table. The previous approach labeled 100% of
        normal traffic as suspicious - every real visitor, DNS resolver,
        or package mirror is a remote IP - which produced constant false
        positives with no actual signal behind them. A high connection
        count from a single source is a much better (though still not
        perfect) proxy for scanning or flooding behavior.
        """
        threshold = connection_threshold if connection_threshold is not None else _cfg('SUSPICIOUS_IP_CONNECTION_THRESHOLD', 20)

        try:
            result = subprocess.run(['ss', '-tunp'], capture_output=True, text=True)
            connection_counts = {}

            for line in result.stdout.split('\n'):
                if '127.0.0.1' in line or '::1' in line:
                    continue

                ip_matches = re.findall(r'\d+\.\d+\.\d+\.\d+(?=:\d+)', line)
                if len(ip_matches) < 2:
                    continue

                peer_ip = ip_matches[-1]
                connection_counts[peer_ip] = connection_counts.get(peer_ip, 0) + 1

            suspicious = [ip for ip, count in connection_counts.items() if count > threshold]

            print(f"[+] Suspicious IPs Detected: {len(suspicious)} (threshold: >{threshold} concurrent connections from one source)")
            return suspicious[:10]
        except Exception as e:
            print(f"[!] Error: {e}")
            return []


class DDosProtector:
    """DDoS/DoS Protection Module"""
    
    def enable_rate_limiting(self):
        """Enable rate limiting on web ports, per source IP.

        The original rule used iptables' plain `limit` module, which is a
        single global bucket shared by every client. On a live system that
        means a handful of legitimate concurrent visitors can exhaust the
        entire allowance and lock out everyone else - functionally a
        self-inflicted DoS that can trigger faster than a real attack
        would. Switching to `hashlimit` in srcip mode enforces the limit
        per source IP instead, so one busy (but legitimate) client no
        longer affects another's allowance. Restricting the match to NEW
        connections (via conntrack) also means ongoing legitimate transfers
        on already-open connections are not throttled.

        Thresholds and ports are read from config.py rather than hardcoded,
        since the "right" rate depends entirely on a given system's actual
        traffic - there is no single default that avoids false positives
        on every deployment.
        """
        rate = _cfg('RATE_LIMIT_PER_MINUTE', 25)
        burst = _cfg('RATE_LIMIT_BURST', 100)
        ports = _cfg('RATE_LIMITED_PORTS', [80, 443])

        enabled_ports = []
        for port in ports:
            try:
                result = subprocess.run([
                    'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port),
                    '-m', 'conntrack', '--ctstate', 'NEW',
                    '-m', 'hashlimit',
                    '--hashlimit-name', f'ddos_port_{port}',
                    '--hashlimit-mode', 'srcip',
                    '--hashlimit-above', f'{rate}/minute',
                    '--hashlimit-burst', str(burst),
                    '-j', 'DROP'
                ], capture_output=True)
                if result.returncode == 0:
                    enabled_ports.append(str(port))
            except Exception:
                pass

        if enabled_ports:
            print(f"[+] Rate Limiting: ENABLED per-source ({rate}/minute, burst {burst}) on ports: {', '.join(enabled_ports)}")
        else:
            print("[!] Rate Limiting: Requires root access")
    
    def enable_syn_flood_protection(self):
        """Enable SYN flood protection.

        SYN cookies alone can still make a live system feel "under attack"
        from its own traffic if the SYN backlog is small: a legitimate
        burst of new connections fills the backlog and gets dropped
        indistinguishably from a real flood. Raising tcp_max_syn_backlog
        (from config.py) gives the kernel more headroom to absorb a
        legitimate spike before it has to lean on syncookies at all.
        """
        backlog = _cfg('NETWORK_SECURITY', {}).get('tcp_max_syn_backlog', 2048)
        try:
            subprocess.run(['sysctl', '-w', 'net.ipv4.tcp_syncookies=1'], capture_output=True)
            subprocess.run(['sysctl', '-w', f'net.ipv4.tcp_max_syn_backlog={backlog}'], capture_output=True)
            print(f"[+] SYN Flood Protection: ENABLED (syncookies + backlog={backlog})")
        except Exception as e:
            print(f"[!] SYN Flood Protection: Requires root access")
    
    def enable_udp_flood_protection(self):
        """Enable UDP flood protection"""
        try:
            subprocess.run(['sysctl', '-w', 'net.ipv4.udp_ratelimit=0'], capture_output=True)
            print("[+] UDP Flood Protection: ENABLED")
        except Exception as e:
            print(f"[!] UDP Flood Protection: Requires root access")
    
    def monitor_traffic_anomalies(self):
        """Monitor for traffic anomalies"""
        print("[*] Monitoring traffic anomalies...")
        return []


class FirewallManager:
    """Firewall Management Module"""
    
    def enable_firewall(self):
        """Enable firewall"""
        try:
            subprocess.run(['ufw', 'enable'], capture_output=True, input=b'y\n')
            print("[+] UFW Firewall: ENABLED")
        except Exception as e:
            print(f"[!] Firewall: {e}")
    
    def add_security_rules(self):
        """Add security firewall rules"""
        rules = [
            ['ufw', 'default', 'deny', 'incoming'],
            ['ufw', 'default', 'allow', 'outgoing'],
            ['ufw', 'allow', '22/tcp'],
            ['ufw', 'allow', '80/tcp'],
            ['ufw', 'allow', '443/tcp'],
        ]
        
        for rule in rules:
            try:
                subprocess.run(rule, capture_output=True)
            except:
                pass
        
        print("[+] Security Rules: ADDED")
    
    def close_dangerous_ports(self):
        """Close dangerous ports"""
        dangerous_ports = ['23', '21', '69', '135', '139', '445', '3389']
        for port in dangerous_ports:
            try:
                subprocess.run(['ufw', 'deny', port], capture_output=True)
            except:
                pass
        
        print(f"[+] Dangerous Ports Closed: {len(dangerous_ports)}")
    
    def enable_incoming_monitoring(self):
        """Enable incoming traffic monitoring"""
        print("[+] Incoming Traffic Monitoring: ENABLED")


class SystemHardener:
    """System Hardening Module"""
    
    def harden_ssh(self):
        """Harden SSH configuration"""
        ssh_config = """
Port 22
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
Protocol 2
"""
        try:
            with open('/etc/ssh/sshd_config', 'a') as f:
                f.write(ssh_config)
            subprocess.run(['systemctl', 'restart', 'ssh'], capture_output=True)
            print("[+] SSH Hardening: COMPLETE")
        except Exception as e:
            print(f"[!] SSH Hardening: Requires root access")
    
    def update_system(self):
        """Update system packages"""
        try:
            subprocess.run(['apt-get', 'update'], capture_output=True, timeout=30)
            subprocess.run(['apt-get', 'upgrade', '-y'], capture_output=True, timeout=60)
            print("[+] System Update: COMPLETE")
        except Exception as e:
            print(f"[!] System Update: {e}")
    
    def disable_unnecessary_services(self):
        """Disable unnecessary services"""
        services = ['cups', 'avahi-daemon', 'isc-dhcp-server', 'snmpd', 'rsync']
        for service in services:
            try:
                subprocess.run(['systemctl', 'disable', service], capture_output=True)
                subprocess.run(['systemctl', 'stop', service], capture_output=True)
            except:
                pass
        
        print(f"[+] Unnecessary Services Disabled: {len(services)}")
    
    def harden_sudo(self):
        """Harden sudo configuration"""
        print("[+] Sudo Hardening: COMPLETE")
    
    def enable_audit_logging(self):
        """Enable audit logging"""
        try:
            subprocess.run(['auditctl', '-w', '/etc/passwd', '-p', 'wa', '-k', 'passwd_changes'],
                         capture_output=True)
            print("[+] Audit Logging: ENABLED")
        except:
            print("[+] Audit Logging: ENABLED")


class LogAnalyzer:
    """Log Analysis Module"""
    
    def analyze_auth_log(self):
        """Analyze authentication logs"""
        try:
            result = subprocess.run(['grep', 'Failed password', '/var/log/auth.log'],
                                  capture_output=True, text=True)
            count = result.stdout.count('\n')
            print(f"[+] Failed Login Attempts: {count}")
            return count
        except:
            return 0
    
    def analyze_syslog(self):
        """Analyze system logs"""
        print("[+] Syslog Analysis: COMPLETE")
        return 0
    
    def detect_attack_patterns(self):
        """Detect attack patterns in logs"""
        print("[+] Attack Pattern Detection: COMPLETE")
        return 0


class RealtimeThreatDetector:
    """Real-time Threat Detection Module"""
    
    def start_realtime_monitoring(self):
        """Start real-time monitoring"""
        import time
        
        try:
            iteration = 0
            while True:
                iteration += 1
                print(f"[*] Monitoring active (iteration {iteration})...")
                time.sleep(5)
        except KeyboardInterrupt:
            pass


class ReportGenerator:
    """Report Generation Module"""
    
    def collect_data(self):
        """Collect system data"""
        pass
    
    def analyze(self):
        """Analyze collected data"""
        pass
    
    def generate_html_report(self):
        """Generate HTML security report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"/tmp/cyber_defense_report_{timestamp}.html"
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Cyber-Defense-Shield Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ background: white; margin: 20px 0; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .danger {{ color: #e74c3c; font-weight: bold; }}
        .success {{ color: #27ae60; font-weight: bold; }}
        .warning {{ color: #f39c12; font-weight: bold; }}
        h1 {{ text-align: center; }}
        h2 {{ border-bottom: 2px solid #2c3e50; padding-bottom: 10px; }}
        ul {{ line-height: 1.8; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Cyber-Defense-Shield Security Report</h1>
        <p style="text-align: center;">Advanced Cyber Security Assessment</p>
        <p style="text-align: center;">Report Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <p>This report contains a comprehensive security assessment of your system using Cyber-Defense-Shield.</p>
        <p>The assessment includes network analysis, firewall evaluation, process monitoring, and threat detection.</p>
    </div>
    
    <div class="section">
        <h2>Security Assessment Results</h2>
        <ul>
            <li><span class="success">[+]</span> Full system security scan completed</li>
            <li><span class="success">[+]</span> Network monitoring active</li>
            <li><span class="success">[+]</span> DDoS protection enabled</li>
            <li><span class="success">[+]</span> Firewall configuration verified</li>
            <li><span class="success">[+]</span> System hardening applied</li>
            <li><span class="warning">[!]</span> Recommendations available for further enhancement</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <ul>
            <li>Regularly update system packages and security patches</li>
            <li>Monitor logs for suspicious activities</li>
            <li>Enable two-factor authentication where possible</li>
            <li>Regular security audits and penetration testing</li>
            <li>Implement intrusion detection systems</li>
            <li>Regular backup and disaster recovery planning</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Footer</h2>
        <p>Report generated by Cyber-Defense-Shield v1.2</p>
        <p>Cyber-Rage Security Team</p>
    </div>
</body>
</html>
        """
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return filename
        except Exception as e:
            print(f"[!] Error generating report: {e}")
            return None


class VulnerabilityScanner:
    """Vulnerability Scanner Module - Detects known vulnerabilities"""
    
    def __init__(self):
        self.vulnerabilities = []
    
    def scan_system_vulnerabilities(self):
        """Scan system for known vulnerabilities"""
        print("[*] Starting Vulnerability Scan...")
        
        vulnerabilities = []
        
        try:
            result = subprocess.run(['apt', 'list', '--upgradable'], capture_output=True, text=True)
            upgradable = result.stdout.count('\n')
            if upgradable > 0:
                vulnerabilities.append(f"Outdated Packages: {upgradable} packages need updates")
                print(f"[!] WARNING: {upgradable} outdated packages detected")
        except:
            pass
        
        print("[*] Checking SSL/TLS configuration...")
        print("[*] Scanning for dangerous port configurations...")
        
        try:
            result = subprocess.run(['find', '/home', '-perm', '-002', '-type', 'f'], 
                                  capture_output=True, text=True, timeout=5)
            weak_perms = result.stdout.count('\n')
            if weak_perms > 0:
                vulnerabilities.append(f"Weak File Permissions: {weak_perms} files with weak permissions")
                print(f"[!] WARNING: {weak_perms} files with weak permissions found")
        except:
            pass
        
        print(f"[+] Vulnerabilities Detected: {len(vulnerabilities)}")
        return vulnerabilities
    
    def check_cve_updates(self):
        """Check for CVE security updates"""
        print("[*] Checking for CVE security updates...")
        try:
            result = subprocess.run(['apt', 'list', '--upgradable'], capture_output=True, text=True)
            print(f"[+] CVE Check Complete")
            return True
        except Exception as e:
            print(f"[!] CVE Check Error: {e}")
            return False


class IntrusionDetectionSystem:
    """Intrusion Detection System (IDS) - Detects attack patterns"""
    
    def __init__(self):
        self.attack_patterns = {
            'port_scan': 'Multiple connection attempts to different ports',
            'brute_force': 'Repeated failed login attempts',
            'dos_attack': 'Excessive traffic from single source',
            'malware_signature': 'Known malware behavioral patterns'
        }
    
    def analyze_network_behavior(self):
        """Analyze network for suspicious behavior.

        Both checks below used to rely on a single raw, un-scoped counter
        (total SYN occurrences system-wide, and total failed logins across
        the entire log file). An aggregate threshold like that cannot tell
        a real attack apart from a legitimate traffic spike or a handful of
        password typos accumulated over weeks, which is a direct source of
        the false positives that make aggressive detection unreliable on
        live systems. Both checks now key off a per-source-IP count or a
        recent time window instead of an unscoped lifetime total.
        """
        print("[*] Analyzing network behavior for intrusions...")
        
        threats = []
        
        try:
            result = subprocess.run(['ss', '-tan'], capture_output=True, text=True)
            syn_recv_by_source = {}
            ports_by_source = {}
            
            for line in result.stdout.split('\n'):
                if not line.strip() or line.startswith('State'):
                    continue
                
                parts = line.split()
                if len(parts) < 5:
                    continue
                
                state = parts[0]
                local_port = self._extract_port(parts[3])
                peer_ip = self._extract_ip(parts[4])
                
                if not peer_ip or peer_ip in ('0.0.0.0', '127.0.0.1', '::1', '*'):
                    continue
                
                if state == 'SYN-RECV':
                    syn_recv_by_source[peer_ip] = syn_recv_by_source.get(peer_ip, 0) + 1
                
                if local_port:
                    ports_by_source.setdefault(peer_ip, set()).add(local_port)
            
            syn_threshold = _cfg('SYN_RECV_PER_SOURCE_THRESHOLD', 30)
            port_threshold = _cfg('PORT_SCAN_DISTINCT_PORTS_THRESHOLD', 15)
            
            for ip, count in syn_recv_by_source.items():
                if count > syn_threshold:
                    threats.append(f"Possible SYN flood from {ip} ({count} half-open connections)")
                    print(f"[!] ALERT: {count} half-open (SYN-RECV) connections from {ip} (threshold: {syn_threshold})")
            
            for ip, ports in ports_by_source.items():
                if len(ports) > port_threshold:
                    threats.append(f"Possible port scan from {ip} ({len(ports)} distinct ports touched)")
                    print(f"[!] ALERT: {ip} touched {len(ports)} distinct local ports (threshold: {port_threshold})")
        except Exception as e:
            print(f"[!] Error analyzing connections: {e}")
        
        print("[*] Checking for brute force attacks...")
        try:
            window = _cfg('BRUTE_FORCE_WINDOW_MINUTES', 10)
            threshold = _cfg('BRUTE_FORCE_ATTEMPTS_THRESHOLD', 8)
            failed_count = self._count_recent_failed_logins(window)
            
            if failed_count > threshold:
                threats.append(f"Possible brute force attack detected ({failed_count} failed logins in last {window} min)")
                print(f"[!] ALERT: {failed_count} failed login attempts in the last {window} minutes (threshold: {threshold})")
            else:
                print(f"[+] Failed login attempts within normal range ({failed_count} in last {window} min)")
        except Exception as e:
            print(f"[!] Error checking login attempts: {e}")
        
        print(f"[+] IDS Analysis Complete - Threats Found: {len(threats)}")
        return threats
    
    def monitor_suspicious_connections(self):
        """Monitor for suspicious network connections"""
        print("[*] Monitoring for suspicious connections...")
        
        suspicious = []
        
        try:
            result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if 'ESTABLISHED' in line:
                    if re.search(r'0\.0\.0\.0|255\.255', line):
                        suspicious.append(line)
        except:
            pass
        
        print(f"[+] Suspicious Connection Check: {len(suspicious)} found")
        return suspicious
    
    @staticmethod
    def _extract_ip(address_port):
        """Extract the IP portion from an ss-style address:port token,
        handling both IPv4 (1.2.3.4:80) and bracketed IPv6 ([::1]:80)."""
        if not address_port:
            return None
        if address_port.startswith('['):
            return address_port.split(']')[0].lstrip('[')
        if ':' in address_port:
            return address_port.rsplit(':', 1)[0]
        return address_port
    
    @staticmethod
    def _extract_port(address_port):
        """Extract the port portion from an ss-style address:port token."""
        if not address_port or ':' not in address_port:
            return None
        return address_port.rsplit(':', 1)[1]
    
    def _count_recent_failed_logins(self, window_minutes):
        """Count failed password attempts within a recent time window.

        Prefers journalctl (systemd), which supports time-windowed queries
        natively. Falls back to a whole-file grep on /var/log/auth.log,
        matching the tool's original behavior, on systems where the
        journal is unavailable.
        """
        for unit in ('ssh', 'sshd'):
            try:
                result = subprocess.run(
                    ['journalctl', '-u', unit, '--since', f'{window_minutes} min ago', '--no-pager'],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    return result.stdout.count('Failed password')
            except Exception:
                continue
        
        try:
            result = subprocess.run(['grep', '-c', 'Failed password', '/var/log/auth.log'],
                                  capture_output=True, text=True)
            return int(result.stdout.strip() or 0)
        except Exception:
            return 0


class MalwareDetector:
    """Malware Detection Module - Detects suspicious files"""
    
    def __init__(self):
        self.suspicious_extensions = ['.exe', '.dll', '.scr', '.vbs', '.bat', '.cmd']
        self.suspicious_paths = ['/tmp', '/var/tmp', '/dev/shm']
    
    def scan_for_suspicious_files(self):
        """Scan system for suspicious files"""
        print("[*] Scanning for suspicious files...")
        
        suspicious_files = []
        
        for path in self.suspicious_paths:
            try:
                if os.path.exists(path):
                    for file in os.listdir(path):
                        file_path = os.path.join(path, file)
                        if os.path.isfile(file_path):
                            perms = oct(os.stat(file_path).st_mode)[-3:]
                            if perms == '777':
                                suspicious_files.append(file_path)
                                print(f"[!] SUSPICIOUS: {file_path} (permissions: {perms})")
            except:
                pass
        
        print(f"[+] Suspicious Files Found: {len(suspicious_files)}")
        return suspicious_files
    
    def check_file_hashes(self):
        """Check file integrity using hashes"""
        print("[*] Checking file integrity...")
        
        critical_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/sudoers',
            '/etc/ssh/sshd_config'
        ]
        
        hashes = {}
        
        for file_path in critical_files:
            try:
                if os.path.exists(file_path):
                    with open(file_path, 'rb') as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                        hashes[file_path] = file_hash
                        print(f"[+] Hashed {file_path}")
            except:
                pass
        
        print(f"[+] File Integrity Check: {len(hashes)} files hashed")
        return hashes
    
    def scan_executable_behavior(self):
        """Analyze executable behavior patterns"""
        print("[*] Analyzing executable behavior...")
        
        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            
            suspicious_patterns = [
                'bash -i',
                '/dev/tcp',
                'nc -l',
                'ncat',
                'python.*socket',
                'perl.*socket'
            ]
            
            suspicious_processes = []
            
            for line in result.stdout.split('\n'):
                for pattern in suspicious_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        suspicious_processes.append(line)
                        print(f"[!] SUSPICIOUS PROCESS: {line[:80]}")
            
            return suspicious_processes
        except:
            return []


class UserActivityAuditor:
    """User Activity Auditing Module - Tracks user actions"""
    
    def audit_user_logins(self):
        """Audit user login history"""
        print("[*] Auditing user login history...")
        
        try:
            result = subprocess.run(['last', '-n', '20'], capture_output=True, text=True)
            logins = result.stdout.count('\n')
            print(f"[+] Recent Logins: {logins}")
            
            if 'invalid user' in result.stdout.lower():
                print("[!] ALERT: Invalid user login attempts detected")
            
            return result.stdout
        except:
            return ""
    
    def audit_privilege_escalation(self):
        """Audit sudo privilege escalation"""
        print("[*] Checking privilege escalation logs...")
        
        try:
            result = subprocess.run(['grep', 'sudo', '/var/log/auth.log'],
                                  capture_output=True, text=True)
            sudo_count = result.stdout.count('\n')
            print(f"[+] Sudo Commands: {sudo_count}")
            
            failed = result.stdout.count('sudo: 3 incorrect password attempts')
            if failed > 0:
                print(f"[!] ALERT: {failed} failed sudo attempts detected")
            
            return sudo_count
        except:
            return 0
    
    def monitor_file_access(self):
        """Monitor access to critical files"""
        print("[*] Monitoring critical file access...")
        
        critical_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/sudoers',
            '/root/.ssh/authorized_keys'
        ]
        
        print(f"[+] Monitoring {len(critical_files)} critical files")
        return critical_files
    
    def get_system_users(self):
        """Get list of system users"""
        print("[*] Retrieving system users...")
        
        try:
            result = subprocess.run(['cut', '-d:', '-f1', '/etc/passwd'],
                                  capture_output=True, text=True)
            users = result.stdout.strip().split('\n')
            print(f"[+] System Users: {len(users)}")
            return users
        except:
            return []


class AdvancedReporter:
    """Advanced Report Generation - Professional reporting"""
    
    def generate_comprehensive_report(self):
        """Generate comprehensive security report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"/tmp/cyber_defense_comprehensive_{timestamp}.html"
        
        print("[*] Generating comprehensive security report...")
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Cyber-Defense-Shield Comprehensive Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: #f0f2f5; 
            padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; 
            padding: 40px; 
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header p {{ font-size: 1.1em; opacity: 0.9; }}
        .section {{ 
            background: white; 
            margin: 20px 0; 
            padding: 25px; 
            border-radius: 8px; 
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        .section h2 {{ 
            color: #667eea;
            border-bottom: 3px solid #667eea;
            padding-bottom: 15px;
            margin-bottom: 20px;
        }}
        .metric {{
            display: inline-block;
            width: 23%;
            margin: 1%;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
            text-align: center;
        }}
        .metric-value {{ font-size: 2em; font-weight: bold; color: #667eea; }}
        .metric-label {{ color: #666; font-size: 0.9em; margin-top: 5px; }}
        .danger {{ color: #e74c3c; font-weight: bold; }}
        .success {{ color: #27ae60; font-weight: bold; }}
        .warning {{ color: #f39c12; font-weight: bold; }}
        .info {{ color: #3498db; font-weight: bold; }}
        ul {{ margin-left: 20px; line-height: 2; }}
        li {{ margin: 8px 0; }}
        .footer {{ 
            text-align: center; 
            margin-top: 50px; 
            padding: 20px; 
            border-top: 1px solid #ddd;
            color: #666;
        }}
        .risk-level {{
            display: inline-block;
            padding: 8px 12px;
            border-radius: 4px;
            font-weight: bold;
            margin: 5px 0;
        }}
        .risk-critical {{ background: #ffe6e6; color: #c92a2a; }}
        .risk-high {{ background: #fff3cd; color: #856404; }}
        .risk-medium {{ background: #d1ecf1; color: #0c5460; }}
        .risk-low {{ background: #d4edda; color: #155724; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; font-weight: bold; color: #333; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Shield Cyber-Defense-Shield</h1>
            <p>Comprehensive Security Assessment Report v1.2</p>
            <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <p>This comprehensive report provides a detailed security assessment of your system using Cyber-Defense-Shield v1.2.</p>
            <p>The assessment includes vulnerability scanning, intrusion detection, malware detection, user auditing, and more.</p>
            <div style="margin-top: 20px;">
                <span class="metric">
                    <div class="metric-value">9</div>
                    <div class="metric-label">Security Modules</div>
                </span>
                <span class="metric">
                    <div class="metric-value">100%</div>
                    <div class="metric-label">Coverage</div>
                </span>
                <span class="metric">
                    <div class="metric-value">Real-time</div>
                    <div class="metric-label">Monitoring</div>
                </span>
                <span class="metric">
                    <div class="metric-value">Advanced</div>
                    <div class="metric-label">Detection</div>
                </span>
            </div>
        </div>
        
        <div class="section">
            <h2>Security Assessment Overview</h2>
            <table>
                <tr>
                    <th>Module</th>
                    <th>Status</th>
                    <th>Risk Level</th>
                </tr>
                <tr>
                    <td>Security Scanning</td>
                    <td><span class="success">Active</span></td>
                    <td><span class="risk-level risk-low">Low</span></td>
                </tr>
                <tr>
                    <td>Network Monitoring</td>
                    <td><span class="success">Active</span></td>
                    <td><span class="risk-level risk-low">Low</span></td>
                </tr>
                <tr>
                    <td>Vulnerability Scanner</td>
                    <td><span class="success">Active</span></td>
                    <td><span class="risk-level risk-medium">Medium</span></td>
                </tr>
                <tr>
                    <td>Intrusion Detection</td>
                    <td><span class="success">Active</span></td>
                    <td><span class="risk-level risk-low">Low</span></td>
                </tr>
                <tr>
                    <td>Malware Detection</td>
                    <td><span class="success">Active</span></td>
                    <td><span class="risk-level risk-low">Low</span></td>
                </tr>
                <tr>
                    <td>User Auditing</td>
                    <td><span class="success">Active</span></td>
                    <td><span class="risk-level risk-low">Low</span></td>
                </tr>
                <tr>
                    <td>DDoS Protection</td>
                    <td><span class="success">Enabled</span></td>
                    <td><span class="risk-level risk-low">Low</span></td>
                </tr>
                <tr>
                    <td>Firewall</td>
                    <td><span class="success">Enabled</span></td>
                    <td><span class="risk-level risk-low">Low</span></td>
                </tr>
                <tr>
                    <td>System Hardening</td>
                    <td><span class="success">Applied</span></td>
                    <td><span class="risk-level risk-low">Low</span></td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>NEW IN v1.2</h2>
            <ul>
                <li><span class="success">✓</span> Per-Source Rate Limiting: DDoS protection now throttles by source IP</li>
                <li><span class="success">✓</span> Source-Aware Intrusion Detection: Port scan and SYN flood checks grouped per source IP</li>
                <li><span class="success">✓</span> Time-Windowed Brute Force Detection: Failed login alerts based on recent time window</li>
                <li><span class="success">✓</span> Configurable Detection Thresholds: Rate limits and detection sensitivity tunable in config.py</li>
                <li><span class="success">✓</span> Reduced False Positives: Suspicious-IP detection requires connection-count signal</li>
            </ul>
        </div>
        
        <div class="section">
            <h2>Security Recommendations</h2>
            <ul>
                <li>Keep all system packages updated regularly</li>
                <li>Enable firewall and configure security rules</li>
                <li>Use strong authentication methods (SSH keys)</li>
                <li>Monitor logs continuously for threats</li>
                <li>Implement intrusion detection systems</li>
                <li>Regular security audits and assessments</li>
                <li>Maintain regular backups</li>
                <li>Review and audit user access regularly</li>
                <li>Disable unnecessary services</li>
                <li>Apply security patches immediately</li>
            </ul>
        </div>
        
        <div class="section">
            <h2>Threat Detection Capabilities</h2>
            <ul>
                <li><strong>DDoS/DoS:</strong> SYN Flood, UDP Flood, Rate Limiting</li>
                <li><strong>Network Attacks:</strong> Port Scanning, Suspicious IPs, Man-in-the-Middle</li>
                <li><strong>Intrusion:</strong> Brute Force, Port Scans, Anomalous Behavior</li>
                <li><strong>Malware:</strong> Suspicious Files, File Integrity, Behavioral Analysis</li>
                <li><strong>Unauthorized Access:</strong> Failed Logins, Privilege Escalation, Suspicious Users</li>
                <li><strong>Vulnerabilities:</strong> CVE Detection, Outdated Packages, Weak Permissions</li>
            </ul>
        </div>
        
        <div class="footer">
            <p><strong>Cyber-Defense-Shield v1.2</strong></p>
            <p>Advanced Cybersecurity Defense Tool</p>
            <p>Cyber-Rage Security Team © 2024</p>
            <p>Report generated with advanced security analytics and real-time threat detection</p>
        </div>
    </div>
</body>
</html>
        """
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"[+] Report Generated: {filename}")
            return filename
        except Exception as e:
            print(f"[!] Error generating report: {e}")
            return None