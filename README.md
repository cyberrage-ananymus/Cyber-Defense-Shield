# Cyber-Defense-Shield v1.4

Multi-Layered Security Tool for Linux Systems

![Version](https://img.shields.io/badge/version-1.4-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)

## Overview

Cyber-Defense-Shield is a practical, multi-layered defense tool for Linux systems. It combines firewall management, system hardening, and lightweight detection - DDoS/DoS mitigation, intrusion detection, basic malware/rootkit indicators, and web attack log scanning - into a single command-line tool with an optional background daemon. See [Limitations](#limitations) below for what it deliberately does not try to be.

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
- Traffic Analysis: Connection-level traffic inspection (via `ss`/`netstat` - not packet-level DPI)
- Suspicious IP Detection: Identify and log malicious IP addresses
- Protocol Analysis: Connection state and port-level analysis
- Bandwidth Monitoring: Track network usage patterns

### 🚨 DDoS/DoS Protection
- Rate Limiting: Per-source-IP connection rate limiting (iptables hashlimit)
- SYN Flood Protection: SYN cookies + backlog tuning
- UDP Flood Protection: Protect against UDP-based attacks
- ICMP Flood Protection: Block ICMP echo request floods
- Anti-Spoofing Protection: Kernel-level reverse-path filtering
- Traffic Anomaly Detection: Identify unusual traffic patterns

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
- HTML Report Generation: Styled, readable HTML security reports
- Threat Severity Classification: Rate threat severity levels
- Recommendations Engine: Provide actionable security recommendations
- Multi-layered Defense: Network, protocol, system, and application levels

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
```
git clone https://github.com/cyberrage-ananymus/Cyber-Defense-Shield.git
cd Cyber-Defense-Shield
```
```
### Step 2: Install Dependencies
sudo pip3 install -r requirements.txt
```
```
### Step 3: Verify Installation
sudo python3 main.py --version
```
```
### Step 4: Run the Tool
sudo python3 main.py
```
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

## Daemon Mode & Alerts

By default, Cyber-Defense-Shield only runs when you're sitting at the
interactive menu. For continuous protection on a live server, run it as
a background daemon instead:

sudo python3 main.py --daemon
sudo python3 main.py --daemon --interval 60   # custom interval in seconds

**What daemon mode does, on a loop:**
- IDS checks (port scans, SYN floods, brute-force attempts)
- Suspicious source IP detection
- Suspicious process detection
- Suspicious file scanning

**What daemon mode deliberately does NOT do:** re-apply firewall rules,
SSH/sudo hardening, or `apt-get upgrade` automatically each cycle. Those
are mutating changes and stay under manual control via the interactive
menu - a monitoring loop silently reconfiguring your system on a timer
is a different, much riskier feature than a monitoring loop that just
watches and alerts.

### Previewing changes with --dry-run

Every state-changing action available from the interactive menu -
firewall rules, SSH/sudo hardening, sysctls, service disabling, `apt-get
upgrade` - can be previewed instead of applied:

sudo python3 main.py --dry-run

Detection and reporting run completely normally under `--dry-run`; only
the mutating operations are simulated. Each one prints exactly what it
would have run (or, for SSH/sudo hardening, validates the proposed
config against a temporary file with `sshd -t`/`visudo -c` and tells you
whether it would pass, without ever touching the real files). Nothing
under `--dry-run` restarts a service, writes to `/etc`, or changes a
sysctl. Combine with `--daemon` if you want to test a fresh deployment
end-to-end before trusting it with real changes.

### Running as a systemd service

A ready-to-use unit file is included: `cyber-defense-shield.service`.

sudo cp cyber-defense-shield.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cyber-defense-shield
sudo systemctl status cyber-defense-shield
journalctl -u cyber-defense-shield -f

Edit the `WorkingDirectory` and `ExecStart` paths in the unit file first
if you didn't install to `/opt/Cyber-Defense-Shield`.

### Telegram / Discord Alerts

Daemon mode can push findings to Telegram and/or Discord instead of
only logging locally. Both are optional and off by default.

**Recommended (keeps credentials out of the public repo):** set these
as environment variables wherever the daemon actually runs - e.g. in
`cyber-defense-shield.service` (see the commented `Environment=` lines
already in that file):

export CDS_TELEGRAM_BOT_TOKEN="your-bot-token-from-BotFather"
export CDS_TELEGRAM_CHAT_ID="your-chat-id"
export CDS_DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."

Then flip `'enabled': True` for whichever channel(s) you're using in
`config.py`:

TELEGRAM_CONFIG = {
    'enabled': True,   # bot_token/chat_id are read from env vars above
    ...
}

DISCORD_CONFIG = {
    'enabled': True,   # webhook_url is read from the env var above
    ...
}

**Do not paste a real bot token or webhook URL directly into
config.py** if this repo (or your fork) is public - anyone who reads
the file would have your credentials.

To get a Telegram `chat_id`: message your bot once, then visit
`https://api.telegram.org/bot<your-bot-token>/getUpdates` and read the
`chat.id` field from the response.

If neither is enabled, daemon mode still runs fine - it just logs to
the console/`LOG_FILE` without pushing anywhere.

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

# Allowlist for Option 1's running-service check (empty = list-only, no flagging)
EXPECTED_SERVICES = ['ssh', 'cron', 'rsyslog', 'ufw']

# Email alerts (optional)
EMAIL_CONFIG = {
    'enabled': False,
    'smtp_server': 'smtp.gmail.com',
    ...
}

# Daemon mode interval (seconds)
DAEMON_SCAN_INTERVAL_SECONDS = 300

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
├── main.py                          # Main application entry point
├── defense_modules.py               # Core security modules
├── config.py                        # Configuration settings
├── requirements.txt                 # Python dependencies
├── cyber-defense-shield.service     # systemd unit for --daemon mode
├── tests/
│   └── test_defense_modules.py      # Core logic tests (unittest, stdlib only)
├── README.md                        # This file
└── .gitignore                       # Git ignore file

## Module Descriptions

### main.py
Main application controller with user interface, menu system, and daemon mode.

Classes:
- CyberDefenseShield: Main application class

Functions:
- print_banner(): Display application banner
- print_menu(): Display menu options
- check_root(): Verify root privileges
- run(): Main interactive program loop
- run_daemon(): Continuous background loop (detection + alerts only), used by --daemon
- parse_args(): Parses --daemon / --interval CLI flags

### defense_modules.py
Core security modules implementing protection mechanisms.

Classes:
- SecurityScanner: System security scanning
- NetworkMonitor: Network monitoring and analysis
- DDosProtector: DDoS/DoS protection (rate limiting, SYN/UDP/ICMP flood, anti-spoofing)
- FirewallManager: Firewall configuration
- SystemHardener: System security hardening (SSH, sudo, services, syscall-level audit rules)
- LogAnalyzer: Log analysis, attack pattern detection, syscall audit event queries
- RealtimeThreatDetector: Tight-loop monitoring (suspicious IPs, ARP spoofing) for Option 7
- ReportGenerator: Report generation, pulls in all v1.4 checks (rootkit/kernel/ARP/services)
- VulnerabilityScanner: Known vulnerability / outdated package checks
- IntrusionDetectionSystem: Per-source IDS (port scan, SYN flood, brute force, ARP spoofing/MITM)
- MalwareDetector: Suspicious file/process detection, kernel module analysis, basic rootkit indicators
- UserActivityAuditor: Login and privilege escalation auditing
- AdvancedReporter: Comprehensive HTML reporting
- AlertNotifier: Sends findings to Telegram/Discord (used by --daemon)
- WebAttackScanner: SQLi/XSS/path-traversal/command-injection signature scan against web server access logs (Option 15)

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
- Daemon mode interval
- Telegram / Discord alert credentials
- Compliance settings

## Threat Protection Capabilities

### DDoS/DoS Attacks
- SYN Flood Protection
- UDP Flood Protection
- ICMP Flood Protection (Option 3)
- Rate Limiting (per-source IP)
- Traffic Analysis

### Network Attacks
- Port Scanning Detection
- Suspicious Connection Detection
- IP Spoofing Protection (kernel reverse-path filtering, Option 3)
- ARP Spoofing / Man-in-the-Middle Detection (Option 10 - basic, single-snapshot ARP table check)

### Application Attacks
- SQL Injection Detection (access log signature scan, Option 15)
- XSS Attack Detection (access log signature scan, Option 15)
- Path Traversal Detection (access log signature scan, Option 15)
- Command Injection Detection (access log signature scan, Option 15)

### Malware & Backdoors
- Suspicious Process Detection
- Basic Rootkit Indicators (Option 11 - process-count discrepancy + known-path check; not a substitute for rkhunter/chkrootkit)
- Kernel Module Analysis (Option 11 - flags modules loaded but missing from disk)
- System Call Monitoring (Option 5 enables; Option 6 queries - real auditd syscall rules on execve/connect)

### Unauthorized Access
- Failed Login Monitoring
- Brute Force Attack Detection (time-windowed)
- Running Service Review (Option 1 - allowlist-based if you populate EXPECTED_SERVICES in config.py)
- Privilege Escalation Detection

**On honesty about scope:** every item above now has real code behind
it (no more capabilities that were just text in this README). That
said, several are intentionally lightweight heuristics, not
replacements for dedicated tools - the docstring on each method in
defense_modules.py says plainly what it does and does not catch.
Rootkit/kernel-module checks in particular are a basic first-pass
signal, not equivalent to rkhunter, chkrootkit, or a real EDR.

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

- Interactive menu scans (Options 1-16): on-demand, one-shot subprocess calls (`ss`, `ps`, `grep`, etc.) - generally sub-second, negligible impact.
- Daemon mode (`--daemon`): runs a small check cycle once per interval (5 min default, configurable via `--interval` or `DAEMON_SCAN_INTERVAL_SECONDS`). Fully idle (zero CPU) between cycles.
- Most daemon checks (connection state, ARP table, suspicious IPs) read kernel tables directly - fast regardless of server load.
- The Web Attack Scan (Option 15 / daemon) tails access logs incrementally - cost scales with *new* traffic since the last check, not total log size.
- None of this sits inline in the request path. It's a periodic background checker, not a WAF/IPS/proxy, so it cannot add latency to real traffic.
- No built-in benchmarking exists yet - the above is based on what each check actually does, not measured numbers under production load. If you run it on a busy server, real numbers would be genuinely useful feedback.

## Limitations

This tool does what's described above and nothing more. Specifically, it does **not**:
- Perform deep packet inspection or payload-level packet capture (no scapy/DPI - detection is connection/log/signature-based)
- Automatically block or respond to a detected threat (detection and mitigation are separate; nothing here auto-bans an IP because the IDS flagged it)
- Replace a real WAF, IDS/IPS (Suricata/Snort), or EDR - the web attack scanner is signature-based log scanning, not inline traffic filtering
- Replace dedicated rootkit scanners (rkhunter, chkrootkit) - the built-in checks are basic heuristics (process-count mismatch, known paths, kernel module vs. on-disk comparison), not a full rootkit database
- Detect zero-day exploits, novel attack patterns, or anything outside its hardcoded/configured signatures
- Protect against insider threats, physical access, or supply-chain compromise
- Work out of the box on non-Debian/Kali systems (assumes `ufw`, `iptables`, `ss`, `dpkg`, `auditctl` are present)
- Guarantee CIS Benchmark or any other compliance framework (the `COMPLIANCE` config flag is not currently backed by real checks - see Roadmap)

General notes that apply regardless of tooling:
- No tool provides 100% protection against all attacks
- Regular updates and manual log review are still recommended
- Requires correct configuration (thresholds, `EXPECTED_SERVICES`, etc.) for the checks to be meaningful on your specific system

## Legal Disclaimer

This tool is designed for defensive cybersecurity purposes only on systems you own or have explicit permission to test.

Unauthorized access to computer systems is illegal. Users are solely responsible for:
- Compliance with all applicable laws and regulations
- Obtaining proper authorization before testing
- Responsible and ethical use of the tool
- Consequences of misuse

## Testing

A basic test suite covers the core detection/parsing logic (web attack
scanning + incremental log tailing, ARP spoofing detection, kernel
module comparison, config validation, `--dry-run`'s command interception)
using only the standard library's `unittest`/`unittest.mock` - no test
dependency to install, no root or real system tools required to run:

python3 -m unittest tests.test_defense_modules -v

This is not full coverage of every method (many wrap subprocess calls
to system tools in ways that are more meaningfully tested by hand on a
real Kali/Debian box), but it does cover the pieces where a wrong
result matters most and where pure logic can be tested in isolation.

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

### v1.4 (2026)
- Every capability the README previously described with no code behind it now has a real, tested implementation:
  - ICMP Flood Protection and IP Spoofing Protection (Option 3)
  - ARP Spoofing / basic Man-in-the-Middle Detection (Option 10)
  - Command Injection signatures added to the Option 15 web attack scan
  - Kernel Module Analysis and basic Rootkit Indicators (Option 11)
  - Real syscall-level audit rules via auditd (`execve`, `connect`) plus a query command (Option 5 to enable, Option 6 to check)
  - Running Service review, with optional allowlist checking via `EXPECTED_SERVICES` in config.py (Option 1)
- Fixed a pre-existing bug where `enable_audit_logging` printed "ENABLED" even when it failed or auditd wasn't installed
- Daemon mode now also runs the web attack scan and ARP spoofing check each cycle
- Full audit of every claim in "Threat Protection Capabilities" against the actual code - anything without a real implementation was either built for real (this release) or removed from the list
- Web Attack Scan (Option 15) now tails the access log incrementally (tracks byte offset, rotation-aware) instead of re-reading and re-scanning the entire file every cycle - keeps daemon mode's cost proportional to recent traffic, not total log size, on a busy server
- File Integrity Checking (Option 11) now actually compares against a stored baseline and reports what changed, instead of only computing and printing hashes with nothing to compare against
- Real-time Monitoring (Option 7) now actually checks something each iteration (suspicious IPs, ARP spoofing) instead of an empty sleep loop
- Report generation (Options 8/13) now includes the v1.4 checks (rootkit indicators, kernel modules, ARP spoofing, running services), not just the original v1.3 set
- Removed two README claims that weren't backed by code ("deep packet inspection", "automatic real-time mitigation") and rewrote Performance Considerations / Limitations with specifics instead of generic boilerplate
- Fixed a version-string inconsistency: some code comments/banners still said v1.3 after the README had already moved to v1.4
- Fixed `enable_udp_flood_protection`: it called a sysctl key (`net.ipv4.udp_ratelimit`) that does not exist in the Linux kernel (verified against kernel.org's ip-sysctl docs) and always claimed "ENABLED" regardless of the (always-failing) result. Replaced with a real per-source iptables hashlimit rule, the same mechanism already used for TCP/ICMP
- Removed remaining marketing language across the README, banner, and generated HTML reports ("enterprise-grade", "Advanced Security Tool", "Professional reports", hardcoded/inaccurate "100% Coverage" and module-count metrics) in favor of accurate, specific descriptions
- **Security fix:** the file integrity baseline moved from `/var/tmp` (predictable, often world-writable) to `/var/lib/cyber-defense-shield` - a local attacker who could write to the old location could update the baseline to match their own tampering and defeat the check entirely
- Added `--dry-run`: previews every state-changing action (firewall rules, SSH/sudo hardening, sysctls, service changes, `apt-get upgrade`) without applying it; detection/reporting still run normally. SSH/sudo hardening validate the *proposed* config against a temp file (`sshd -t` / `visudo -c`) so dry-run tells you whether it would actually pass, not just what command would run
- Added `config.py` validation at startup - catches wrong types/values (e.g. a threshold set to a string, a negative rate limit) with a clear message instead of a confusing traceback deep inside some method
- Added a basic test suite (`tests/test_defense_modules.py`, stdlib `unittest` only) covering web-attack-scan tailing/rotation, ARP spoofing detection, kernel module comparison, config validation, and `--dry-run`'s command interception
- Documented an optional, reduced-privilege systemd configuration for `--daemon` (capabilities instead of full root) in `cyber-defense-shield.service` - commented out by default since it needs verification on your specific distro, but available for anyone who wants it

### v1.3.1 (2026)
- Added Web Attack Scan (Option 15): actually wires up the SQL_INJECTION/XSS/PATH_TRAVERSAL signatures in config.py's ATTACK_PATTERNS to a real check against nginx/apache access logs - these patterns previously existed in config.py but were never read by any code
- Telegram/Discord alert credentials now read from environment variables (CDS_TELEGRAM_BOT_TOKEN, CDS_TELEGRAM_CHAT_ID, CDS_DISCORD_WEBHOOK_URL) instead of needing to be hardcoded in config.py, so they can't end up committed to the public repo by accident
- Daemon mode now uses Python's `logging` module with size-based log rotation (5MB x 3 backups) instead of an unbounded manual file write
- Daemon mode cycles now also run the Web Attack Scan

### v1.3 (2026)
- Added `--daemon` mode: runs detection continuously in the background instead of only via the interactive menu, on a configurable interval (see cyber-defense-shield.service for systemd deployment)
- Added optional Telegram and Discord alerts, sent automatically when daemon mode finds something actionable (both off by default, stdlib-only, no new dependency)
- Daemon mode intentionally only runs detection checks (IDS, suspicious IPs/processes/files) - it does not re-apply firewall/SSH/sudo hardening or run system updates automatically on a timer
- SSH hardening is now idempotent (marker-guarded) and takes a one-time backup of the original sshd_config, validated with `sshd -t` before being applied
- iptables rate-limiting rules are now checked with `iptables -C` before being added, preventing duplicate rules on repeated runs, and are persisted across reboots via netfilter-persistent/iptables-save
- Sudo hardening, incoming-traffic monitoring, syslog analysis, and attack-pattern detection now perform real checks instead of placeholder output
- Security reports now reflect live system state (firewall/SSH/ports/suspicious IPs) instead of a static checklist
- Removed unused dependencies from requirements.txt (now only psutil, which is actually used)

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

- CIS Benchmark compliance checking (a real subset of controls, not just the current unused `COMPLIANCE` config flag)
- Historical trend tracking across scans (needs persistent storage - currently every scan is stateless)
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

Open-source, MIT-licensed Linux security tooling.

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

Version: 1.4
Last Updated: 2026
Status: Active Development & Maintenance
Maintained By: Cyber-Rage Security Team

Protect Your Systems. Defend Your Network. Secure Your Future.
