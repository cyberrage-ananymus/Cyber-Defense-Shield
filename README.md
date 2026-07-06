# Cyber-Defense-Shield v1.2

Advanced Cyber Security Defense & Protection Tool for Linux Systems

![Version](https://img.shields.io/badge/version-1.2-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)

## Overview

Cyber-Defense-Shield is a comprehensive, enterprise-grade cybersecurity defense tool designed for Linux systems. It provides multi-layered protection against various cyber attacks including DDoS, DoS, XSS, SQL injection, malware, and other sophisticated threats.

## Key Features

### 🔍 Security Scanning
- Full System Security Scan: Comprehensive security assessment of entire system
- Open Port Detection: Identify all exposed ports and services
- Suspicious Process Monitoring: Detect malicious or unauthorized processes
- SSH Security Verification: Validate SSH configuration security
- Package Analysis: Scan installed packages for vulnerabilities
- File Integrity Checking: Monitor critical system files for changes

### 🌐 Network Protection
- Real-time Network Monitoring: Continuous network activity analysis
- Connection Tracking: Monitor and log all network connections
- Traffic Analysis: Detailed network traffic inspection
- Suspicious IP Detection: Identify and log malicious IP addresses
- Protocol Analysis: Deep packet inspection and analysis
- Bandwidth Monitoring: Track network usage patterns

### 🚨 DDoS/DoS Protection
- Rate Limiting: Limit connection rates per IP address
- SYN Flood Protection: Defend against SYN flood attacks
- UDP Flood Protection: Protect against UDP-based attacks
- ICMP Flood Protection: Block ICMP echo request floods
- Traffic Anomaly Detection: Identify unusual traffic patterns
- Automatic Mitigation: Real-time attack response and blocking

### 🔥 Firewall Management
- UFW Firewall Control: Enable and configure firewall rules
- Security Rule Implementation: Apply best-practice security rules
- Port Management: Close dangerous ports, open safe ports
- Incoming Traffic Monitoring: Log and monitor all inbound traffic
- Outgoing Traffic Control: Manage and restrict outbound connections
- Rule Persistence: Save firewall rules permanently

### 🔐 System Hardening
- SSH Configuration Hardening: Disable root login, password auth
- System Package Updates: Keep all packages current
- Service Hardening: Disable unnecessary services
- Sudo Configuration: Strengthen privilege escalation controls
- Audit Logging: Enable comprehensive system auditing
- Kernel Parameter Tuning: Optimize security-related kernel settings

### 🎯 Threat Detection
- Log Analysis: Analyze authentication and system logs
- Failed Login Tracking: Monitor failed login attempts
- Attack Pattern Recognition: Identify known attack signatures
- Real-time Monitoring: Continuous threat detection
- Behavioral Analysis: Detect anomalous system behavior
- Alert Generation: Immediate notification of threats

### 📊 Advanced Features
- HTML Report Generation: Professional security reports
- Threat Severity Classification: Rate threat severity levels
- Recommendations Engine: Provide actionable security recommendations
- Multi-layered Defense: Network, protocol, system, and application levels
- Compliance Checking: CIS Benchmark compliance verification
- Historical Analysis: Track security trends over time

## System Requirements

### Minimum Requirements
- OS: Kali Linux / Debian-based Linux
- Python: 3.8 or higher
- RAM: 512 MB
- Disk Space: 100 MB
- Privileges: Root/sudo access required

### Recommended Requirements
- OS: Kali Linux 2023+
- Python: 3.10+
- RAM: 2 GB+
- Disk Space: 500 MB+
- Network: Active internet connection for updates

### Required Tools
- ss - Socket statistics
- netstat - Network statistics
- iptables - Firewall rules
- sysctl - Kernel parameters
- ufw - Uncomplicated Firewall
- auditctl - Audit framework
- grep - Text search
- ps - Process status
- dpkg - Package management

## Installation

### Step 1: Clone Repository
git clone https://github.com/cyberrage-ananymus/Cyber-Defense-Shield.git
cd Cyber-Defense-Shield

### Step 2: Install Dependencies
sudo pip3 install -r requirements.txt

### Step 3: Verify Installation
sudo python3 main.py --version

### Step 4: Run the Tool
sudo python3 main.py

## Usage

### Basic Execution
sudo python3 main.py

### Menu System
After running the tool, you'll see the main menu with 9 options:

MAIN MENU - Select an Option
1. Full System Security Scan
2. Network Monitoring & Analysis
3. DDoS/DoS Protection & Mitigation
4. Firewall Management & Configuration
5. System Hardening & Security Enhancement
6. Log Analysis & Threat Detection
7. Real-time Threat Detection & Prevention
8. Generate Security Report
9. Exit Program

### Option 1: Full System Security Scan
Performs a comprehensive security assessment:
# Select: 1
- Scans all open ports
- Checks for suspicious processes
- Analyzes firewall status
- Verifies SSH security
- Scans installed packages

### Option 2: Network Monitoring
Monitors network activity in real-time:
# Select: 2
- Displays active connections
- Shows established connections
- Detects suspicious IPs
- Analyzes traffic patterns

### Option 3: DDoS/DoS Protection
Activates DDoS protection mechanisms:
# Select: 3
- Enables rate limiting
- Activates SYN flood protection
- Enables UDP flood protection
- Monitors for anomalies

### Option 4: Firewall Management
Configures and manages firewall:
# Select: 4
- Enables UFW firewall
- Applies security rules
- Closes dangerous ports
- Enables traffic monitoring

### Option 5: System Hardening
Hardens system security configuration:
# Select: 5
- Hardens SSH configuration
- Updates system packages
- Disables unnecessary services
- Configures sudo properly
- Enables audit logging

### Option 6: Log Analysis
Analyzes system logs for threats:
# Select: 6
- Analyzes authentication logs
- Analyzes system logs
- Detects attack patterns
- Reports findings

### Option 7: Real-time Detection
Enables real-time threat monitoring:
# Select: 7
- Monitors processes continuously
- Monitors network traffic
- Monitors file system
- Press Ctrl+C to stop

### Option 8: Generate Report
Creates detailed security report:
# Select: 8
- Collects system data
- Analyzes threats
- Generates HTML report
- Saves to /tmp/cyber_defense_report_*.html

### Option 9: Exit
Exits the program:
# Select: 9

## Configuration

### Editing Configuration
Edit config.py to customize settings:

# Firewall settings
FIREWALL_ENABLED = True
FIREWALL_TYPE = "UFW"

# DDoS protection
DDOS_PROTECTION_ENABLED = True
RATE_LIMIT_PER_MINUTE = 25

# SSH configuration
SSH_PORT = 22
PERMIT_ROOT_LOGIN = False

# Dangerous ports to block
DANGEROUS_PORTS = [21, 23, 69, 135, 139, 445, ...]

# Email alerts (optional)
EMAIL_CONFIG = {
    'enabled': False,
    'smtp_server': 'smtp.gmail.com',
    ...
}

### Tuning Detection Thresholds

Every detection threshold in this tool is a tradeoff. Set it too low and
you get false positives that can disrupt legitimate traffic on a live
system - sometimes worse than the attack you were defending against. Set
it too high and real attacks slip through unnoticed. There is no universal
default that is correct for every deployment: a quiet personal server and
a busy production host need different numbers.

As of v1.2, rate limiting is enforced per source IP rather than as one
shared global bucket, and IDS checks (port scan, SYN flood, brute force)
are grouped per source IP or a recent time window instead of a single
unscoped counter. This removes the worst false-positive cases, but the
numeric thresholds below still need to match your own traffic:

# DDoS protection - per-source rate limiting
RATE_LIMIT_PER_MINUTE = 25
RATE_LIMIT_BURST = 100
RATE_LIMITED_PORTS = [80, 443]

# Intrusion detection - grouped per source IP / time window
SYN_RECV_PER_SOURCE_THRESHOLD = 30
PORT_SCAN_DISTINCT_PORTS_THRESHOLD = 15
BRUTE_FORCE_WINDOW_MINUTES = 10
BRUTE_FORCE_ATTEMPTS_THRESHOLD = 8
SUSPICIOUS_IP_CONNECTION_THRESHOLD = 20

Before trusting any of these for an automated response, watch how the
tool behaves against your own normal traffic for a while. If you see
alerts that don't match real attack activity, raise the relevant
threshold; if you suspect attacks are going unreported, lower it and
cross-check against your actual logs.

## Project Structure

Cyber-Defense-Shield/
├── main.py                    # Main application entry point
├── defense_modules.py         # Core security modules
├── config.py                 # Configuration settings
├── requirements.txt          # Python dependencies
├── README.md                 # This file
└── .gitignore               # Git ignore file

## Module Descriptions

### main.py
Main application controller with user interface and menu system.

Classes:
- CyberDefenseShield: Main application class

Functions:
- print_banner(): Display application banner
- print_menu(): Display menu options
- check_root(): Verify root privileges
- run(): Main program loop

### defense_modules.py
Core security modules implementing protection mechanisms.

Classes:
- SecurityScanner: System security scanning
- NetworkMonitor: Network monitoring and analysis
- DDosProtector: DDoS/DoS protection
- FirewallManager: Firewall configuration
- SystemHardener: System security hardening
- LogAnalyzer: Log analysis and threat detection
- RealtimeThreatDetector: Real-time monitoring
- ReportGenerator: Report generation

### config.py
Configuration settings for all protection mechanisms.

Settings:
- Firewall configuration
- DDoS protection parameters
- SSH security settings
- Network security options
- System hardening options
- Attack pattern signatures
- Alert thresholds
- Compliance settings

## Threat Protection Capabilities

### DDoS/DoS Attacks
- SYN Flood Protection
- UDP Flood Protection
- ICMP Flood Protection
- Rate Limiting
- Traffic Analysis

### Network Attacks
- Port Scanning Detection
- Suspicious Connection Detection
- IP Spoofing Detection
- Man-in-the-Middle Detection

### Application Attacks
- SQL Injection Detection
- XSS Attack Detection
- Path Traversal Detection
- Command Injection Detection

### Malware & Backdoors
- Suspicious Process Detection
- Rootkit Detection
- Kernel Module Analysis
- System Call Monitoring

### Unauthorized Access
- Failed Login Monitoring
- Brute Force Attack Detection
- Unauthorized Service Detection
- Privilege Escalation Detection

## Security Best Practices

1. Regular Updates
   - Keep system packages updated
   - Update security tools regularly

2. Monitoring
   - Regularly review logs
   - Monitor network traffic
   - Check firewall rules

3. Hardening
   - Follow CIS Benchmarks
   - Disable unnecessary services
   - Use strong authentication

4. Backup
   - Regular system backups
   - Test backup restoration
   - Keep backup copies secure

5. Incident Response
   - Have incident response plan
   - Document security events
   - Investigate threats thoroughly

## Troubleshooting

### Permission Denied Error
Solution: Run with sudo
sudo python3 main.py

### Module Not Found Error
Solution: Install dependencies
sudo pip3 install -r requirements.txt

### Firewall Not Working
Solution: Install UFW
sudo apt-get install ufw

Enable UFW
sudo ufw enable

### SSH Configuration Error
Solution: Check SSH config
sudo nano /etc/ssh/sshd_config

Restart SSH service
sudo systemctl restart ssh

## Performance Considerations

- Scan Duration: Full scans may take 2-5 minutes
- Resource Usage: Minimal CPU/memory impact
- Network Impact: Minimal bandwidth consumption
- Real-time Detection: Low overhead continuous monitoring

## Limitations

Important Notes:
- No tool provides 100% protection against all attacks
- Zero-day exploits may bypass protections
- Regular updates and monitoring are essential
- Manual review of logs recommended
- Cannot protect against physical attacks
- Requires proper configuration for effectiveness

## Legal Disclaimer

This tool is designed for defensive cybersecurity purposes only on systems you own or have explicit permission to test.

Unauthorized access to computer systems is illegal. Users are solely responsible for:
- Compliance with all applicable laws and regulations
- Obtaining proper authorization before testing
- Responsible and ethical use of the tool
- Consequences of misuse

## Contributing

Contributions are welcome! Please ensure:
- Code follows Python best practices
- All functions are properly documented
- Security is prioritized
- Testing is performed before submission
- Changes are backwards compatible

## Bug Reports

Found a bug? Please report it:
1. Check existing issues
2. Provide detailed description
3. Include steps to reproduce
4. Attach relevant logs

## Support

For support and questions:
- Open GitHub Issues
- Contact via Session Messenger: 05fd51ac639edc257133f9364529eff3af1d69c5c18b31f321ba466b3823a0a805

## Changelog

### v1.2 (2026)
- Rate limiting is now enforced per source IP (iptables hashlimit) instead of one shared global limit, so concurrent legitimate users no longer exhaust each other's allowance
- SYN flood protection now also raises the SYN backlog size, giving legitimate traffic bursts more headroom before syncookies kick in
- Port scan and SYN flood detection in the IDS are now grouped per source IP instead of a single system-wide counter
- Brute force detection now uses a configurable recent time window instead of a lifetime log total
- Suspicious-IP detection now requires an actual connection-count signal instead of flagging every remote address seen
- All of the above thresholds are now configurable in config.py

### v1.0 (2026)
- Initial release
- Core security modules
- DDoS protection
- Firewall management
- System hardening
- Log analysis
- Report generation

## Roadmap

- Machine learning threat detection
- Cloud integration support
- Mobile app for monitoring
- Advanced threat intelligence
- SIEM integration
- Kubernetes support

## License

MIT License - See LICENSE file for details

MIT License

Copyright (c) 2026 Cyber-Rage Security Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

## Authors

Cyber-Rage Security Team

Advanced Cybersecurity Defense Solutions

### Team Members
- Security Architecture
- Threat Analysis
- System Administration
- Penetration Testing

## Acknowledgments

Special thanks to:
- Linux security community
- Open-source contributors
- Security researchers
- Beta testers

---

Version: 1.2
Last Updated: 2026
Status: Active Development & Maintenance
Maintained By: Cyber-Rage Security Team

Protect Your Systems. Defend Your Network. Secure Your Future.
