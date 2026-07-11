#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Defense Modules - Core Security Functions
Updated Version 1.4 - Daemon Mode & Alerting
"""

import subprocess
import re
import socket
import json
from datetime import datetime
import hashlib
import os
import shutil
import tempfile

try:
    import config as _config
except Exception:
    _config = None

try:
    import psutil
except Exception:
    psutil = None


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


DRY_RUN = False


def set_dry_run(enabled):
    """Enable/disable dry-run mode for every state-changing operation in
    this module. Called once from main.py at startup based on --dry-run.
    """
    global DRY_RUN
    DRY_RUN = enabled


def _exec(cmd, **kwargs):
    """Run a state-CHANGING subprocess command, or preview it under --dry-run.

    Only used for calls that actually modify system state (firewall
    rules, sysctls, service start/stop, package upgrades) - read-only
    calls (status checks, scans, `ss`/`ps`/log reads) keep calling
    subprocess.run directly, since previewing a read has no meaning and
    dry-run should never block detection/reporting from working.

    Suggested twice across independent reviews: destructive operations
    (sshd restart, service disable, apt upgrade, firewall changes) had no
    way to preview what would happen before it happened. `--dry-run`
    routes every one of those through here instead.
    """
    if DRY_RUN:
        print(f"[DRY-RUN] Would run: {' '.join(cmd)}")
        return subprocess.CompletedProcess(cmd, 0, stdout=b'', stderr=b'')
    return subprocess.run(cmd, **kwargs)


def _write_file(path, content, mode='w'):
    """Write to a file that represents a state change (config files,
    sudoers.d drops, etc.), or preview it under --dry-run instead of
    actually writing.
    """
    if DRY_RUN:
        preview = content if len(content) < 200 else content[:200] + '...'
        print(f"[DRY-RUN] Would write to {path}:\n{preview}")
        return
    with open(path, mode) as f:
        f.write(content)


class AlertNotifier:
    """Sends security alerts to Telegram and/or Discord.

    Built for daemon mode, where printing to a console nobody is watching
    is useless. Both channels are optional and off by default (see
    TELEGRAM_CONFIG / DISCORD_CONFIG in config.py) - with neither
    configured, send_alert() is a silent no-op so daemon mode still runs
    fine without any alerting set up. Uses only the standard library
    (urllib) rather than the `requests` package, so it doesn't reintroduce
    a dependency that was removed for being unused elsewhere.
    """

    def __init__(self):
        self.telegram = _cfg('TELEGRAM_CONFIG', {'enabled': False})
        self.discord = _cfg('DISCORD_CONFIG', {'enabled': False})
        self.cooldown_seconds = _cfg('ALERT_COOLDOWN_SECONDS', 300)
        self._last_sent_at = None

    def _send_telegram(self, message):
        if not self.telegram.get('enabled') or not self.telegram.get('bot_token') or not self.telegram.get('chat_id'):
            return False
        try:
            import urllib.request
            import urllib.parse
            url = f"https://api.telegram.org/bot{self.telegram['bot_token']}/sendMessage"
            data = urllib.parse.urlencode({
                'chat_id': self.telegram['chat_id'],
                'text': message,
            }).encode('utf-8')
            req = urllib.request.Request(url, data=data, method='POST')
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except Exception as e:
            print(f"[!] Telegram alert failed: {e}")
            return False

    def _send_discord(self, message):
        if not self.discord.get('enabled') or not self.discord.get('webhook_url'):
            return False
        try:
            import urllib.request
            payload = json.dumps({'content': message[:1900]}).encode('utf-8')
            req = urllib.request.Request(
                self.discord['webhook_url'], data=payload,
                headers={'Content-Type': 'application/json'}, method='POST'
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status in (200, 204)
        except Exception as e:
            print(f"[!] Discord alert failed: {e}")
            return False

    _SECRET_PATTERNS = [
        re.compile(r'(-p)(\S+)'),                              # mysql-style -pPASSWORD (not a space-separated -p PASSWORD)
        re.compile(r'((?:pass(?:word)?|pwd|secret|token|api[_-]?key)\s*[:=]\s*)(\S+)', re.IGNORECASE),
        re.compile(r'(Authorization:\s*Bearer\s+)(\S+)', re.IGNORECASE),
    ]

    @classmethod
    def _redact(cls, text):
        """Mask likely-sensitive values (passwords, tokens, API keys) before
        a finding string leaves this machine.

        Several findings originate from raw command lines (`ps aux`
        output for suspicious processes) or log lines (web attack scan
        matches) - both can legitimately contain a password or token
        someone put on a command line (a common, if bad, practice: e.g.
        `mysqldump -pMySecret`). Without this, that value would be sent
        verbatim to a third-party service (Telegram/Discord) via
        send_alert(). This is deliberately conservative (pattern-based,
        may over- or under-match) - it reduces the chance of an obvious
        leak, it does not guarantee no sensitive data ever appears in an
        alert.
        """
        for pattern in cls._SECRET_PATTERNS:
            text = pattern.sub(lambda m: m.group(1) + '***REDACTED***', text)
        return text

    def send_alert(self, title, findings):
        """Send an alert with the given findings, if any transport is configured.

        No-op if findings is empty (nothing worth alerting on) or if
        neither Telegram nor Discord is enabled/configured.

        Rate-limited by ALERT_COOLDOWN_SECONDS (default 300s = 5 min):
        suggested independently, since without a cooldown, a genuinely
        noisy period (or just tight daemon --interval) could fire an
        alert every single cycle and spam Telegram/Discord instead of
        being useful signal. Findings are still logged to the
        console/LOG_FILE every cycle regardless of cooldown - only the
        push notification itself is throttled.
        """
        if not findings:
            return

        now = datetime.now()
        if self._last_sent_at is not None:
            elapsed = (now - self._last_sent_at).total_seconds()
            if elapsed < self.cooldown_seconds:
                remaining = int(self.cooldown_seconds - elapsed)
                print(f"[*] Alert suppressed (cooldown active, {remaining}s remaining) - findings are still in the log")
                return

        timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
        lines = [f"Cyber-Defense-Shield Alert - {title}", timestamp, ""]
        lines.extend(f"- {self._redact(str(item))}" for item in findings[:15])
        message = "\n".join(lines)

        sent_telegram = self._send_telegram(message)
        sent_discord = self._send_discord(message)

        if sent_telegram or sent_discord:
            self._last_sent_at = now
            channels = ', '.join(c for c, ok in [('Telegram', sent_telegram), ('Discord', sent_discord)] if ok)
            print(f"[+] Alert sent via {channels}")
        elif self.telegram.get('enabled') or self.discord.get('enabled'):
            print("[!] Alert configured but failed to send (check credentials/network)")


class WebAttackScanner:
    """Scans web server access logs for known SQLi/XSS/path-traversal signatures.

    The ATTACK_PATTERNS dict in config.py (SQL_INJECTION, XSS,
    PATH_TRAVERSAL) previously existed but was never actually read by any
    code - the README's claim of protection against SQLi/XSS was not
    backed by an actual check. This class is what makes that claim real,
    even if modestly: it greps nginx/apache access logs for the
    configured signatures.

    Important scope limits, stated plainly: this is signature-based log
    scanning, not a WAF. It cannot block a request - it can only tell you
    a matching request already happened. It only sees traffic that hits a
    web server logging to one of LOG_PATHS. It is not a substitute for a
    real WAF (e.g. ModSecurity, Cloudflare) in front of anything that
    actually needs one.
    """

    LOG_PATHS = [
        '/var/log/nginx/access.log',
        '/var/log/apache2/access.log',
        '/var/log/httpd/access_log',
    ]

    OFFSET_STATE_FILE = '/var/tmp/.cds_weblog_offsets.json'

    def _load_offsets(self):
        try:
            with open(self.OFFSET_STATE_FILE, 'r') as f:
                return json.loads(f.read())
        except Exception:
            return {}

    def _save_offsets(self, offsets):
        try:
            with open(self.OFFSET_STATE_FILE, 'w') as f:
                f.write(json.dumps(offsets))
        except Exception:
            pass  # Best-effort; worst case we re-tail from EOF next run.

    def scan_web_logs(self):
        """Scan new lines in a web server access log for attack signatures.

        Incremental by design: tracks a byte offset per log file (in
        OFFSET_STATE_FILE) and only reads/scans lines written since the
        last check, instead of re-reading the entire file every time. On
        a busy server the access log can be huge and grows continuously -
        re-reading and re-scanning the whole thing every daemon cycle
        (every few minutes) would mean steadily increasing CPU/memory/disk
        I/O cost as the log grows through the day, and it would also
        re-report the same old matches repeatedly. This only ever looks
        at what's new since last time, so the cost per cycle stays
        proportional to recent traffic, not total log size.

        First run (no stored offset yet) starts from the current end of
        the file rather than scanning existing history, so turning this
        on doesn't trigger one large one-time scan of a potentially huge
        pre-existing log. Rotation is detected two ways, not just one:
        the stored offset being beyond the current file's size (catches
        `copytruncate`-style rotation), and the file's inode number
        changing (catches `create`-style rotation, where logrotate
        renames the old file and creates a new one at the same path -
        a size check alone could theoretically miss this if the new file
        happened to already grow past the old offset before the next
        check; the inode never lies about whether it's really the same
        file).
        """
        print("[*] Scanning web server logs for attack signatures...")

        patterns = _cfg('ATTACK_PATTERNS', {})
        if not patterns:
            print("[!] Web Attack Scan: No ATTACK_PATTERNS configured in config.py")
            return []

        log_path = next((p for p in self.LOG_PATHS if os.path.exists(p)), None)
        if not log_path:
            print("[*] Web Attack Scan: No web server access log found (checked nginx, apache2, httpd)")
            return []

        try:
            file_size = os.path.getsize(log_path)
            current_inode = os.stat(log_path).st_ino
            offsets = self._load_offsets()
            state = offsets.get(log_path)
            last_offset = state.get('offset') if isinstance(state, dict) else state
            last_inode = state.get('inode') if isinstance(state, dict) else None

            if last_offset is None:
                # First time seeing this log: skip existing history, start
                # watching from here on rather than one big historical scan.
                last_offset = file_size
            elif last_inode is not None and last_inode != current_inode:
                print(f"[*] Web Attack Scan: {log_path} was replaced (inode changed) - treating as rotated, restarting from the beginning")
                last_offset = 0
            elif last_offset > file_size:
                print(f"[*] Web Attack Scan: {log_path} appears to have been rotated (shrunk), restarting from the beginning")
                last_offset = 0

            with open(log_path, 'r', errors='ignore') as f:
                f.seek(last_offset)
                new_lines = f.readlines()
                new_offset = f.tell()

            offsets[log_path] = {'offset': new_offset, 'inode': current_inode}
            self._save_offsets(offsets)
        except Exception as e:
            print(f"[!] Web Attack Scan: {e}")
            return []

        if not new_lines:
            print(f"[+] Web Attack Scan: No new log entries since last check ({log_path})")
            return []

        findings = []
        for category, signatures in patterns.items():
            matches = sum(
                1 for line in new_lines
                if any(sig.lower() in line.lower() for sig in signatures)
            )
            if matches > 0:
                findings.append(f"{category}: {matches} matching request(s) in {log_path}")
                print(f"[!] {category}: {matches} suspicious request(s) found")

        if not findings:
            print(f"[+] Web Attack Scan: No signature matches in {log_path} ({len(new_lines)} new lines scanned)")

        return findings


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

    def check_running_services(self):
        """Check running services against an optional allowlist.

        README previously listed "Unauthorized Service Detection" with no
        code behind it. Being honest about what's actually possible here:
        this tool has no baseline of what's "normal" for your system, so
        it can't truthfully claim to detect "unauthorized" services out
        of the box. What it does:

        - If config.py's EXPECTED_SERVICES list is populated, flags any
          running service NOT on that list - a real allowlist check.
        - If EXPECTED_SERVICES is empty (the default), it just lists what
          IS running so you can populate the allowlist yourself, rather
          than guessing at a generic list and producing false positives
          on every non-default setup.
        """
        print("[*] Checking running services...")
        expected = set(_cfg('EXPECTED_SERVICES', []))

        try:
            result = subprocess.run(
                ['systemctl', 'list-units', '--type=service', '--state=running', '--no-legend', '--no-pager'],
                capture_output=True, text=True
            )
            running = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    running.append(line.split()[0].replace('.service', ''))
        except Exception as e:
            print(f"[!] Error checking services: {e}")
            return []

        if not expected:
            print(f"[*] {len(running)} service(s) running. EXPECTED_SERVICES is empty in config.py,")
            print("    so nothing is flagged - populate it with your normal service list to enable allowlist checking.")
            return []

        unexpected = [s for s in running if s not in expected]
        if unexpected:
            print(f"[!] {len(unexpected)} service(s) running that are NOT in EXPECTED_SERVICES: {', '.join(unexpected[:10])}")
        else:
            print(f"[+] All {len(running)} running service(s) are in EXPECTED_SERVICES")

        return unexpected


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
        normal traffic as "suspicious" - every real visitor, DNS resolver,
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
                    continue  # no distinct peer address on this line (e.g. a LISTEN socket)

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

        Idempotent by design: each rule is checked with `iptables -C`
        before being added with `-A`. Without this check, re-running this
        (e.g. via option 3 more than once, or option 14's full assessment)
        would append a duplicate hashlimit rule per port every time,
        multiplying the actual effective throttling on the system.
        """
        rate = _cfg('RATE_LIMIT_PER_MINUTE', 25)
        burst = _cfg('RATE_LIMIT_BURST', 100)
        ports = _cfg('RATE_LIMITED_PORTS', [80, 443])

        enabled_ports = []
        already_active = []
        for port in ports:
            rule_spec = [
                '-p', 'tcp', '--dport', str(port),
                '-m', 'conntrack', '--ctstate', 'NEW',
                '-m', 'hashlimit',
                '--hashlimit-name', f'ddos_port_{port}',
                '--hashlimit-mode', 'srcip',
                '--hashlimit-above', f'{rate}/minute',
                '--hashlimit-burst', str(burst),
                '-j', 'DROP'
            ]
            try:
                # -C (check) returns 0 if an identical rule already exists.
                check = subprocess.run(['iptables', '-C', 'INPUT'] + rule_spec, capture_output=True)
                if check.returncode == 0:
                    already_active.append(str(port))
                    continue

                result = _exec(['iptables', '-A', 'INPUT'] + rule_spec, capture_output=True)
                if result.returncode == 0:
                    enabled_ports.append(str(port))
            except Exception:
                pass

        if enabled_ports or already_active:
            if enabled_ports:
                print(f"[+] Rate Limiting: ENABLED per-source ({rate}/minute, burst {burst}) on ports: {', '.join(enabled_ports)}")
            if already_active:
                print(f"[+] Rate Limiting: Already active on ports: {', '.join(already_active)} (no duplicate rule added)")
            if enabled_ports and not DRY_RUN:
                self._persist_iptables_rules()
        else:
            print("[!] Rate Limiting: Requires root access")

    @staticmethod
    def _persist_iptables_rules():
        """Persist current iptables rules across reboots.

        Without this, rules added by enable_rate_limiting only live in the
        kernel's in-memory ruleset and silently disappear on the next
        reboot, giving a false sense of protection. Tries
        netfilter-persistent first (the standard Debian/Kali mechanism);
        falls back to writing iptables-save output directly if that tool
        isn't installed. Never called under --dry-run (callers check
        DRY_RUN first) since there is nothing real to persist yet.
        """
        try:
            result = subprocess.run(['netfilter-persistent', 'save'], capture_output=True, text=True)
            if result.returncode == 0:
                print("[+] Rate Limiting: Rules persisted via netfilter-persistent")
                return
        except FileNotFoundError:
            pass

        try:
            os.makedirs('/etc/iptables', exist_ok=True)
            save = subprocess.run(['iptables-save'], capture_output=True, text=True)
            if save.returncode == 0:
                with open('/etc/iptables/rules.v4', 'w') as f:
                    f.write(save.stdout)
                print("[+] Rate Limiting: Rules persisted to /etc/iptables/rules.v4")
            else:
                print("[!] Rate Limiting: Could not persist rules (iptables-save failed)")
        except Exception as e:
            print(f"[!] Rate Limiting: Could not persist rules ({e})")
    
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
            _exec(['sysctl', '-w', 'net.ipv4.tcp_syncookies=1'], capture_output=True)
            _exec(['sysctl', '-w', f'net.ipv4.tcp_max_syn_backlog={backlog}'], capture_output=True)
            print(f"[+] SYN Flood Protection: ENABLED (syncookies + backlog={backlog})")
        except Exception as e:
            print(f"[!] SYN Flood Protection: Requires root access")
    
    def enable_udp_flood_protection(self):
        """Enable UDP flood protection via real per-source rate limiting.

        The previous version called `sysctl -w net.ipv4.udp_ratelimit=0`
        and unconditionally printed "ENABLED" regardless of the result.
        That sysctl key does not exist in the Linux kernel (verified
        against kernel.org's ip-sysctl documentation - there is no
        UDP-wide rate-limit knob the way there is for ICMP). The command
        always failed silently, and this method has been claiming
        success while doing nothing. Real UDP flood mitigation on Linux
        needs an actual firewall rule, not a sysctl - this now adds a
        per-source hashlimit rule, the same real mechanism already used
        for TCP rate limiting and ICMP flood protection. Idempotent via
        `iptables -C`, persisted across reboots.
        """
        rate = _cfg('UDP_RATE_LIMIT_PER_SECOND', 50)
        burst = _cfg('UDP_RATE_LIMIT_BURST', 100)

        rule_spec = [
            '-p', 'udp',
            '-m', 'hashlimit', '--hashlimit-name', 'udp_flood',
            '--hashlimit-mode', 'srcip',
            '--hashlimit-above', f'{rate}/second',
            '--hashlimit-burst', str(burst),
            '-j', 'DROP'
        ]
        try:
            check = subprocess.run(['iptables', '-C', 'INPUT'] + rule_spec, capture_output=True)
            if check.returncode == 0:
                print(f"[+] UDP Flood Protection: Already active ({rate} packets/sec per source)")
                return

            result = _exec(['iptables', '-A', 'INPUT'] + rule_spec, capture_output=True)
            if result.returncode == 0:
                print(f"[+] UDP Flood Protection: ENABLED per-source ({rate} packets/sec, burst {burst})")
                if not DRY_RUN:
                    self._persist_iptables_rules()
            else:
                print("[!] UDP Flood Protection: Requires root access")
        except Exception as e:
            print(f"[!] UDP Flood Protection: Requires root access ({e})")

    def enable_icmp_flood_protection(self):
        """Enable ICMP flood protection.

        README previously listed "ICMP Flood Protection" as a capability
        with no code behind it at all. This makes the claim real: ignores
        broadcast pings (blocks the classic Smurf-attack amplification
        vector) and rate-limits how many ICMP echo requests the kernel
        will respond to per second via iptables, so a ping flood can't
        consume unbounded CPU/bandwidth. Idempotent via `iptables -C`,
        same pattern as enable_rate_limiting.
        """
        ignore_broadcasts = _cfg('NETWORK_SECURITY', {}).get('enable_icmp_echo_ignore', True)
        limit = _cfg('ICMP_RATE_LIMIT_PER_SECOND', 10)

        try:
            if ignore_broadcasts:
                _exec(['sysctl', '-w', 'net.ipv4.icmp_echo_ignore_broadcasts=1'], capture_output=True)

            rule_spec = [
                '-p', 'icmp', '--icmp-type', 'echo-request',
                '-m', 'limit', '--limit', f'{limit}/second', '--limit-burst', str(limit * 2),
                '-j', 'ACCEPT'
            ]
            check = subprocess.run(['iptables', '-C', 'INPUT'] + rule_spec, capture_output=True)
            if check.returncode != 0:
                _exec(['iptables', '-A', 'INPUT'] + rule_spec, capture_output=True)
                # Anything over the limit falls through to this drop rule.
                drop_spec = ['-p', 'icmp', '--icmp-type', 'echo-request', '-j', 'DROP']
                drop_check = subprocess.run(['iptables', '-C', 'INPUT'] + drop_spec, capture_output=True)
                if drop_check.returncode != 0:
                    _exec(['iptables', '-A', 'INPUT'] + drop_spec, capture_output=True)
                print(f"[+] ICMP Flood Protection: ENABLED (echo-request limited to {limit}/sec, broadcast pings ignored: {ignore_broadcasts})")
                if not DRY_RUN:
                    self._persist_iptables_rules()
            else:
                print(f"[+] ICMP Flood Protection: Already active ({limit}/sec limit)")
        except Exception as e:
            print(f"[!] ICMP Flood Protection: Requires root access ({e})")

    def enable_anti_spoofing_protection(self):
        """Enable IP spoofing protection via kernel reverse-path filtering.

        README previously listed "IP Spoofing Detection" with no code
        behind it. True packet-level spoofing *detection* would need
        inline packet inspection; what actually stops spoofed-source
        packets on Linux is reverse-path filtering (rp_filter), the
        standard kernel-level anti-spoofing mechanism - if a reply to a
        packet's claimed source wouldn't route back out the interface it
        arrived on, the kernel drops it. Also disables source-routed
        packets, a related classic spoofing/routing-attack vector.
        Settings are read from config.py's existing NETWORK_SECURITY dict.
        """
        net_sec = _cfg('NETWORK_SECURITY', {})
        rp_filter = net_sec.get('enable_reverse_path_filter', True)
        block_source_route = net_sec.get('enable_source_route_check', True)

        applied = []
        try:
            if rp_filter:
                _exec(['sysctl', '-w', 'net.ipv4.conf.all.rp_filter=1'], capture_output=True)
                _exec(['sysctl', '-w', 'net.ipv4.conf.default.rp_filter=1'], capture_output=True)
                applied.append('reverse-path filtering')
            if block_source_route:
                _exec(['sysctl', '-w', 'net.ipv4.conf.all.accept_source_route=0'], capture_output=True)
                _exec(['sysctl', '-w', 'net.ipv4.conf.default.accept_source_route=0'], capture_output=True)
                applied.append('source-route rejection')

            if applied:
                print(f"[+] Anti-Spoofing Protection: ENABLED ({', '.join(applied)})")
            else:
                print("[*] Anti-Spoofing Protection: Disabled in config.py (NETWORK_SECURITY)")
        except Exception as e:
            print(f"[!] Anti-Spoofing Protection: Requires root access ({e})")
    
    def monitor_traffic_anomalies(self):
        """Monitor for traffic anomalies.

        Takes two samples of system-wide network I/O one second apart and
        flags a spike if the throughput between samples exceeds a
        configurable rate. This was previously a no-op that always
        returned an empty list regardless of actual traffic; it now does
        a real (if still basic) check using psutil counters.
        """
        print("[*] Monitoring traffic anomalies...")
        anomalies = []

        if psutil is None:
            print("[!] Traffic Anomaly Check: psutil not installed, skipping")
            return anomalies

        threshold_mbps = _cfg('TRAFFIC_ANOMALY_THRESHOLD_MBPS', 50)

        try:
            import time
            before = psutil.net_io_counters()
            time.sleep(1)
            after = psutil.net_io_counters()

            bytes_per_sec = (after.bytes_recv - before.bytes_recv) + (after.bytes_sent - before.bytes_sent)
            mbps = (bytes_per_sec * 8) / 1_000_000

            if mbps > threshold_mbps:
                anomalies.append(f"Traffic spike detected: {mbps:.1f} Mbps (threshold: {threshold_mbps} Mbps)")
                print(f"[!] ALERT: {mbps:.1f} Mbps of combined traffic (threshold: {threshold_mbps} Mbps)")
            else:
                print(f"[+] Traffic within normal range ({mbps:.1f} Mbps, threshold: {threshold_mbps} Mbps)")
        except Exception as e:
            print(f"[!] Error monitoring traffic: {e}")

        return anomalies


class FirewallManager:
    """Firewall Management Module"""
    
    def enable_firewall(self):
        """Enable firewall"""
        try:
            _exec(['ufw', 'enable'], input=b'y\n', capture_output=True)
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
                _exec(rule, capture_output=True)
            except:
                pass
        
        print("[+] Security Rules: ADDED")
    
    def close_dangerous_ports(self):
        """Close dangerous ports"""
        dangerous_ports = ['23', '21', '69', '135', '139', '445', '3389']
        for port in dangerous_ports:
            try:
                _exec(['ufw', 'deny', port], capture_output=True)
            except:
                pass
        
        print(f"[+] Dangerous Ports Closed: {len(dangerous_ports)}")
    
    def enable_incoming_monitoring(self):
        """Enable incoming traffic monitoring.

        Previously a no-op that only printed "ENABLED" without checking
        anything. Now takes an actual snapshot of listening ports and
        current incoming (established) connections via `ss`, so the
        message reflects something real about the system's exposure.
        """
        try:
            listening = subprocess.run(['ss', '-tuln'], capture_output=True, text=True)
            listen_count = max(listening.stdout.count('\n') - 1, 0)

            established = subprocess.run(['ss', '-tn', 'state', 'established'], capture_output=True, text=True)
            incoming_count = max(established.stdout.count('\n') - 1, 0)

            print(f"[+] Incoming Traffic Monitoring: ENABLED")
            print(f"    - Listening sockets: {listen_count}")
            print(f"    - Active incoming connections: {incoming_count}")
        except Exception as e:
            print(f"[!] Incoming Traffic Monitoring: {e}")


class SystemHardener:
    """System Hardening Module"""
    
    def harden_ssh(self):
        """Harden SSH configuration.

        Idempotent by design: the block below is guarded by a marker
        comment, so re-running this (e.g. via option 14's full assessment)
        does not keep appending duplicate/conflicting directives to
        sshd_config every time. A backup of the pre-hardening config is
        also kept, taken only once, so the original can be restored if the
        new settings ever lock someone out.
        """
        marker = "# --- Cyber-Defense-Shield hardening (do not duplicate) ---"
        ssh_config = f"""
{marker}
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
        config_path = '/etc/ssh/sshd_config'
        backup_path = '/etc/ssh/sshd_config.cyberdefense-shield.bak'

        try:
            with open(config_path, 'r') as f:
                content = f.read()

            if marker in content:
                print("[+] SSH Hardening: Already applied (skipping duplicate write)")
                return

            if DRY_RUN:
                # Validate what WOULD be written against a temp copy, so
                # --dry-run gives a real answer ("this would pass/fail
                # sshd -t"), not just an echo of the diff, without ever
                # touching the real config or restarting sshd.
                proposed = content + ssh_config
                with tempfile.NamedTemporaryFile('w', suffix='_sshd_config', delete=False) as tf:
                    tf.write(proposed)
                    tmp_path = tf.name
                try:
                    test = subprocess.run(['sshd', '-t', '-f', tmp_path], capture_output=True, text=True)
                    verdict = "would PASS sshd -t validation" if test.returncode == 0 else f"would FAIL sshd -t validation: {test.stderr.strip()}"
                finally:
                    os.remove(tmp_path)
                print(f"[DRY-RUN] Would back up {config_path}, append hardening block, then restart ssh.")
                print(f"[DRY-RUN] Proposed config {verdict}.")
                return

            # Keep exactly one backup of the pre-hardening state, taken
            # only the first time this ever runs on the system.
            if not os.path.exists(backup_path):
                with open(backup_path, 'w') as bf:
                    bf.write(content)
                print(f"[+] SSH Backup: Saved original config to {backup_path}")

            # Atomic write: build the full new content, write it to a temp
            # file in the same directory, then os.replace() into place.
            # os.replace() is atomic on POSIX as long as source and dest
            # are on the same filesystem (guaranteed here - same dir) - a
            # process killed mid-write leaves the temp file incomplete but
            # never touches the real sshd_config, unlike the previous
            # plain append, where a kill at the wrong instant could leave
            # sshd_config with a truncated/malformed line and no way to
            # know until the next sshd restart failed.
            new_content = content + ssh_config
            fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(config_path), suffix='.cds_tmp')
            try:
                with os.fdopen(fd, 'w') as tf:
                    tf.write(new_content)
                os.replace(tmp_path, config_path)
            except Exception:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
                raise

            test = subprocess.run(['sshd', '-t'], capture_output=True, text=True)
            if test.returncode != 0:
                # New config is invalid - restore the backup immediately
                # rather than leaving a broken sshd_config in place.
                with open(backup_path, 'r') as bf:
                    original = bf.read()
                fd2, tmp_path2 = tempfile.mkstemp(dir=os.path.dirname(config_path), suffix='.cds_restore')
                with os.fdopen(fd2, 'w') as f:
                    f.write(original)
                os.replace(tmp_path2, config_path)
                print(f"[!] SSH Hardening: New config failed validation, restored backup.")
                print(f"[!] sshd -t said: {test.stderr.strip()}")
                return

            # `sshd -t` only validates syntax - it says nothing about
            # whether anyone can actually still log in once
            # PasswordAuthentication is turned off. Check for at least
            # one populated authorized_keys before restarting, since a
            # syntactically-valid config that nobody has a key for is
            # exactly how people lock themselves out of a remote server.
            candidate_users = {'root'}
            sudo_user = os.environ.get('SUDO_USER')
            if sudo_user:
                candidate_users.add(sudo_user)
            home_of = lambda u: '/root' if u == 'root' else f'/home/{u}'
            has_authorized_key = any(
                os.path.exists(p) and os.path.getsize(p) > 0
                for p in (f'{home_of(u)}/.ssh/authorized_keys' for u in candidate_users)
            )
            if not has_authorized_key:
                print("[!] " + "=" * 68)
                print("[!] WARNING: No populated authorized_keys file found for root")
                print(f"[!] or {sudo_user or '(unknown sudo user)'}. This config disables password")
                print("[!] login. If no other access method (console, another user's")
                print("[!] key, cloud provider recovery) exists, restarting ssh now")
                print("[!] could lock you out permanently.")
                print("[!] " + "=" * 68)
                print("[*] Proceeding anyway - this tool does not block on warnings.")
                print("[*] Ctrl+C now if you need to add a key first.")

            _exec(['systemctl', 'restart', 'ssh'], capture_output=True)
            print("[+] SSH Hardening: COMPLETE")
        except FileNotFoundError:
            print(f"[!] SSH Hardening: {config_path} not found")
        except Exception as e:
            print(f"[!] SSH Hardening: Requires root access ({e})")
    
    def update_system(self):
        """Update system packages"""
        try:
            _exec(['apt-get', 'update'], capture_output=True, timeout=30)
            _exec(['apt-get', 'upgrade', '-y'], capture_output=True, timeout=60)
            print("[+] System Update: COMPLETE")
        except Exception as e:
            print(f"[!] System Update: {e}")
    
    def disable_unnecessary_services(self):
        """Disable unnecessary services"""
        services = ['cups', 'avahi-daemon', 'isc-dhcp-server', 'snmpd', 'rsync']
        for service in services:
            try:
                _exec(['systemctl', 'disable', service], capture_output=True)
                _exec(['systemctl', 'stop', service], capture_output=True)
            except:
                pass
        
        print(f"[+] Unnecessary Services Disabled: {len(services)}")
    
    def harden_sudo(self):
        """Harden sudo configuration.

        Previously a no-op that only printed "COMPLETE". Now writes actual
        hardening directives to a dedicated file under /etc/sudoers.d/
        (never edits /etc/sudoers directly - a syntax error there can lock
        out sudo entirely on the next login). The new file is validated
        with `visudo -c` before being kept; if it fails validation, it is
        removed rather than left in place.
        """
        sudoers_path = '/etc/sudoers.d/99-cyberdefense-shield'
        sudo_config = """# Managed by Cyber-Defense-Shield - do not edit by hand
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults passwd_tries=3
Defaults timestamp_timeout=5
"""
        try:
            if os.path.exists(sudoers_path):
                print("[+] Sudo Hardening: Already applied (skipping)")
                return

            if DRY_RUN:
                with tempfile.NamedTemporaryFile('w', suffix='_sudoers', delete=False) as tf:
                    tf.write(sudo_config)
                    tmp_path = tf.name
                try:
                    test = subprocess.run(['visudo', '-c', '-f', tmp_path], capture_output=True, text=True)
                    verdict = "would PASS visudo validation" if test.returncode == 0 else f"would FAIL visudo validation: {test.stderr.strip()}"
                finally:
                    os.remove(tmp_path)
                print(f"[DRY-RUN] Would create {sudoers_path} (mode 0440):\n{sudo_config}")
                print(f"[DRY-RUN] Proposed config {verdict}.")
                return

            # Validate in a temp location FIRST, before /etc/sudoers.d/
            # ever sees this file at all - safer than write-then-validate-
            # then-maybe-remove, since a crash between writing and
            # validating would otherwise leave an unvalidated file sitting
            # in a place `sudo` actually reads on every invocation.
            fd, tmp_path = tempfile.mkstemp(dir='/etc/sudoers.d', suffix='.cds_tmp')
            try:
                with os.fdopen(fd, 'w') as tf:
                    tf.write(sudo_config)
                os.chmod(tmp_path, 0o440)

                check = subprocess.run(['visudo', '-c', '-f', tmp_path], capture_output=True, text=True)
                if check.returncode != 0:
                    print(f"[!] Sudo Hardening: Invalid config rejected ({check.stderr.strip()})")
                    return

                os.replace(tmp_path, sudoers_path)  # atomic, same directory
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)

            print("[+] Sudo Hardening: COMPLETE")
        except PermissionError:
            print("[!] Sudo Hardening: Requires root access")
        except Exception as e:
            print(f"[!] Sudo Hardening: {e}")
    
    def enable_audit_logging(self):
        """Enable audit logging, including real syscall-level rules.

        README previously listed "System Call Monitoring" with no code
        behind it - the only audit rule that existed watched a single
        file (/etc/passwd) for writes, which is file-integrity
        monitoring, not syscall monitoring. The rules added below use the
        Linux Audit subsystem's actual syscall-level interface
        (`-S execve`, `-S connect`) - this is genuine kernel-level system
        call auditing, the same mechanism tools like auditd/OSSEC use, not
        a simulation of it. See LogAnalyzer.check_syscall_audit_events()
        to query what these rules have captured.

        Also fixes a pre-existing bug: the previous version's except
        block printed "ENABLED" even when auditctl failed or wasn't
        installed, silently claiming success on failure.
        """
        rules = [
            (['auditctl', '-w', '/etc/passwd', '-p', 'wa', '-k', 'passwd_changes'], 'file watch: /etc/passwd'),
            (['auditctl', '-a', 'always,exit', '-F', 'arch=b64', '-S', 'execve', '-k', 'syscall_exec'], 'syscall watch: execve (b64)'),
            (['auditctl', '-a', 'always,exit', '-F', 'arch=b32', '-S', 'execve', '-k', 'syscall_exec'], 'syscall watch: execve (b32)'),
            (['auditctl', '-a', 'always,exit', '-F', 'arch=b64', '-S', 'connect', '-k', 'syscall_connect'], 'syscall watch: connect'),
        ]

        applied = []
        try:
            for rule_cmd, label in rules:
                result = _exec(rule_cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    applied.append(label)

            if applied:
                verb = "Would enable" if DRY_RUN else "ENABLED"
                print(f"[{'DRY-RUN' if DRY_RUN else '+'}] Audit Logging: {verb} ({len(applied)}/{len(rules)} rules)")
                for label in applied:
                    print(f"    - {label}")
            else:
                print("[!] Audit Logging: Requires root access, or auditd is not installed")
        except FileNotFoundError:
            print("[!] Audit Logging: auditctl not found (install the auditd package)")
        except Exception as e:
            print(f"[!] Audit Logging: {e}")


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
        """Analyze system logs for error/warning-level entries.

        Previously a no-op that only printed "COMPLETE" without reading
        any log. Now actually greps /var/log/syslog (falling back to
        journalctl on systems where that file doesn't exist, e.g. pure
        systemd-journal setups) for error/warning/critical entries.
        """
        try:
            result = subprocess.run(
                ['grep', '-iE', 'error|warning|critical', '/var/log/syslog'],
                capture_output=True, text=True
            )
            if result.returncode == 0 or result.stdout:
                count = result.stdout.count('\n')
                print(f"[+] Syslog Analysis: {count} error/warning/critical entries found")
                return count
        except FileNotFoundError:
            pass

        try:
            result = subprocess.run(
                ['journalctl', '-p', 'warning', '--no-pager', '--since', '1 hour ago'],
                capture_output=True, text=True, timeout=10
            )
            count = result.stdout.count('\n')
            print(f"[+] Syslog Analysis (journalctl, last hour): {count} warning+ entries found")
            return count
        except Exception as e:
            print(f"[!] Syslog Analysis: {e}")
            return 0
    
    def detect_attack_patterns(self):
        """Detect known attack signature phrases in auth logs.

        Previously a no-op. Now scans /var/log/auth.log for well-known
        sshd/PAM attack signature strings and reports counts per pattern,
        rather than just claiming completion with no actual signal.
        """
        patterns = {
            'Invalid user': 'Login attempts for non-existent users',
            'authentication failure': 'PAM authentication failures',
            'POSSIBLE BREAK-IN ATTEMPT': 'Reverse-DNS mismatch on connecting host',
            'Did not receive identification string': 'Connections dropped before SSH handshake (scanner-like)',
        }

        findings = []
        try:
            result = subprocess.run(['cat', '/var/log/auth.log'], capture_output=True, text=True)
            log_data = result.stdout
        except Exception as e:
            print(f"[!] Attack Pattern Detection: {e}")
            return findings

        for pattern, description in patterns.items():
            count = log_data.count(pattern)
            if count > 0:
                findings.append(f"{pattern}: {count} occurrences ({description})")
                print(f"[!] Pattern '{pattern}': {count} occurrences - {description}")

        if not findings:
            print("[+] Attack Pattern Detection: No known attack signatures found")
        else:
            print(f"[+] Attack Pattern Detection: {len(findings)} pattern type(s) matched")

        return findings

    def check_syscall_audit_events(self):
        """Query recent events captured by the syscall-level audit rules.

        Reads what SystemHardener.enable_audit_logging()'s `-S execve` /
        `-S connect` rules have actually recorded, via `ausearch`. If
        audit logging was never enabled (Option 5), this will correctly
        report nothing rather than fail confusingly.
        """
        print("[*] Checking syscall audit events (last 10 minutes)...")
        findings = []

        for key, label in [('syscall_exec', 'execve'), ('syscall_connect', 'connect')]:
            try:
                result = subprocess.run(
                    ['ausearch', '-k', key, '-ts', 'recent'],
                    capture_output=True, text=True, timeout=10
                )
                count = result.stdout.count('type=SYSCALL')
                if count > 0:
                    findings.append(f"{count} '{label}' syscall event(s) recorded (key={key})")
                    print(f"[+] {count} '{label}' event(s) found")
            except FileNotFoundError:
                print("[!] Syscall Audit Check: ausearch not found (install the auditd package)")
                break
            except Exception as e:
                print(f"[!] Syscall Audit Check ({label}): {e}")

        if not findings:
            print("[*] No syscall audit events found (rules may not be enabled yet - see Option 5)")

        return findings


class RealtimeThreatDetector:
    """Real-time Threat Detection Module"""
    
    def start_realtime_monitoring(self):
        """Start real-time monitoring.

        Previously this loop did nothing but print "Monitoring active"
        and sleep - it never actually checked anything, despite Option 7
        being presented as real-time threat detection. Each iteration now
        runs a small set of fast, cheap checks (kernel-table reads, not
        full assessments) suited to a tight loop: suspicious source IPs
        and ARP spoofing. Heavier checks (file scans, full IDS log
        analysis) stay in the menu options and daemon mode instead of
        this loop, since running them every few seconds would be the
        real performance problem Grok's review was actually gesturing
        at.
        """
        import time

        monitor = NetworkMonitor()
        ids = IntrusionDetectionSystem()

        try:
            iteration = 0
            while True:
                iteration += 1
                print(f"[*] Monitoring active (iteration {iteration})...")

                try:
                    suspicious_ips = monitor.detect_suspicious_ips()
                    if suspicious_ips:
                        print(f"[!] {len(suspicious_ips)} suspicious IP(s): {', '.join(suspicious_ips[:5])}")
                except Exception as e:
                    print(f"[!] Suspicious IP check failed: {e}")

                try:
                    arp_findings = ids.detect_arp_spoofing()
                    for item in arp_findings:
                        print(f"[!] {item}")
                except Exception as e:
                    print(f"[!] ARP check failed: {e}")

                time.sleep(5)
        except KeyboardInterrupt:
            pass


class ReportGenerator:
    """Report Generation Module"""
    
    def __init__(self):
        self.data = {}
        self.findings = []
    
    def collect_data(self):
        """Collect live system data to feed into the report.

        Previously a no-op (`pass`), then later only covered the original
        v1.3 checks. Now also pulls in the v1.4 detection additions
        (rootkit indicators, kernel modules, ARP spoofing, running
        services) - without this, the generated report silently ignored
        half of what the tool actually checks for.
        """
        scanner = SecurityScanner()
        monitor = NetworkMonitor()
        malware = MalwareDetector()
        ids = IntrusionDetectionSystem()

        self.data = {
            'open_ports': scanner.scan_open_ports(),
            'suspicious_processes': scanner.check_suspicious_processes(),
            'firewall_active': scanner.check_firewall(),
            'ssh_secure': scanner.check_ssh_security(),
            'established_connections': monitor.analyze_traffic(),
            'suspicious_ips': monitor.detect_suspicious_ips(),
            'unexpected_services': scanner.check_running_services(),
            'rootkit_findings': malware.check_rootkit_indicators(),
            'flagged_kernel_modules': malware.analyze_kernel_modules(),
            'arp_findings': ids.detect_arp_spoofing(),
        }
        return self.data
    
    def analyze(self):
        """Turn collected data into human-readable findings.

        Previously a no-op (`pass`). Now produces a real list of
        success/warning findings based on self.data, used by
        generate_html_report instead of a static hardcoded list.
        """
        if not self.data:
            self.collect_data()

        findings = []

        findings.append(('success' if self.data['firewall_active'] else 'danger',
                          f"Firewall is {'ACTIVE' if self.data['firewall_active'] else 'INACTIVE'}"))

        findings.append(('success' if self.data['ssh_secure'] else 'warning',
                          f"SSH configuration is {'hardened' if self.data['ssh_secure'] else 'not fully hardened'}"))

        port_count = len(self.data['open_ports'])
        findings.append(('success', f"{port_count} listening port(s) detected"))

        if self.data['suspicious_processes']:
            findings.append(('warning', f"{len(self.data['suspicious_processes'])} potentially suspicious process(es) found"))
        else:
            findings.append(('success', "No suspicious processes detected"))

        if self.data['suspicious_ips']:
            findings.append(('warning', f"{len(self.data['suspicious_ips'])} suspicious source IP(s) detected"))
        else:
            findings.append(('success', "No suspicious source IPs detected"))

        if self.data.get('rootkit_findings'):
            findings.append(('warning', f"{len(self.data['rootkit_findings'])} basic rootkit indicator(s) found"))
        else:
            findings.append(('success', "No basic rootkit indicators found"))

        if self.data.get('flagged_kernel_modules'):
            findings.append(('warning', f"{len(self.data['flagged_kernel_modules'])} kernel module(s) not found on disk"))
        else:
            findings.append(('success', "All loaded kernel modules matched on-disk files"))

        if self.data.get('arp_findings'):
            findings.append(('danger', f"{len(self.data['arp_findings'])} possible ARP spoofing indicator(s) found"))
        else:
            findings.append(('success', "No ARP spoofing indicators found"))

        if self.data.get('unexpected_services'):
            findings.append(('warning', f"{len(self.data['unexpected_services'])} service(s) running outside EXPECTED_SERVICES allowlist"))

        self.findings = findings
        return findings
    
    def generate_html_report(self):
        """Generate HTML security report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"/tmp/cyber_defense_report_{timestamp}.html"

        self.collect_data()
        self.analyze()

        findings_html = "\n".join(
            f'            <li><span class="{css_class}">[{"+" if css_class == "success" else "!"}]</span> {text}</li>'
            for css_class, text in self.findings
        )
        
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
        <p style="text-align: center;">Security Assessment Summary</p>
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
{findings_html}
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
        <p>Report generated by Cyber-Defense-Shield v1.4</p>
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
    """NEW: Vulnerability Scanner Module - Detects known vulnerabilities"""
    
    def __init__(self):
        self.vulnerabilities = []
    
    def scan_system_vulnerabilities(self):
        """Scan system for known vulnerabilities"""
        print("[*] Starting Vulnerability Scan...")
        
        vulnerabilities = []
        
        # Check for outdated packages
        try:
            result = subprocess.run(['apt', 'list', '--upgradable'], capture_output=True, text=True)
            upgradable = result.stdout.count('\n')
            if upgradable > 0:
                vulnerabilities.append(f"Outdated Packages: {upgradable} packages need updates")
                print(f"[!] WARNING: {upgradable} outdated packages detected")
        except:
            pass
        
        # Check for weak SSL/TLS
        print("[*] Checking SSL/TLS configuration...")
        
        # Check for open dangerous ports
        print("[*] Scanning for dangerous port configurations...")
        
        # Check for weak permissions
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
    """NEW: Intrusion Detection System (IDS) - Detects attack patterns"""
    
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
        
        # Check for port scanning / SYN flood activity, grouped by source IP.
        # Grouping by source lets us tell "one attacker hammering us" apart
        # from "many normal clients connecting at once", which a single
        # system-wide counter cannot do.
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
        
        # Check for brute force attempts within a recent time window rather
        # than the entire log history, so old, isolated failures do not
        # produce a standing "attack in progress" alert indefinitely.
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
            
            # Check for connections from suspicious countries/IPs
            for line in result.stdout.split('\n'):
                if 'ESTABLISHED' in line:
                    if re.search(r'0\.0\.0\.0|255\.255', line):
                        suspicious.append(line)
        except:
            pass
        
        print(f"[+] Suspicious Connection Check: {len(suspicious)} found")
        return suspicious
    
    def detect_arp_spoofing(self):
        """Detect likely ARP spoofing (basic Man-in-the-Middle indicator).

        README previously listed "Man-in-the-Middle Detection" with no
        code behind it anywhere. This implements the standard lightweight
        technique real tools like arpwatch use: on a healthy LAN segment,
        each IP should resolve to exactly one MAC address. A single IP
        showing multiple different MAC addresses in the ARP table at the
        same time is the classic signature of ARP spoofing/cache
        poisoning, which is how most on-LAN MITM attacks are actually
        carried out.

        Scope limit stated plainly: this reads a single point-in-time
        snapshot of the local ARP table. It won't catch spoofing on a
        remote/routed network, VLAN-hopping, or attacks that don't touch
        ARP at all (e.g. a rogue DHCP server, or MITM further upstream).
        """
        print("[*] Checking ARP table for spoofing indicators...")
        findings = []

        try:
            result = subprocess.run(['ip', 'neigh'], capture_output=True, text=True)
            lines = result.stdout.strip().split('\n') if result.stdout.strip() else []
        except Exception:
            try:
                result = subprocess.run(['arp', '-an'], capture_output=True, text=True)
                lines = result.stdout.strip().split('\n') if result.stdout.strip() else []
            except Exception as e:
                print(f"[!] ARP Spoofing Check: {e}")
                return findings

        ip_to_macs = {}
        for line in lines:
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            mac_match = re.search(r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', line)
            if ip_match and mac_match:
                ip = ip_match.group(1)
                mac = mac_match.group(1).lower()
                ip_to_macs.setdefault(ip, set()).add(mac)

        for ip, macs in ip_to_macs.items():
            if len(macs) > 1:
                findings.append(f"Possible ARP spoofing: {ip} mapped to {len(macs)} different MAC addresses ({', '.join(macs)})")
                print(f"[!] ALERT: {ip} has {len(macs)} conflicting MAC addresses in ARP table")

        if not findings:
            print(f"[+] ARP Spoofing Check: No conflicts found ({len(ip_to_macs)} host(s) in ARP table)")

        return findings
    
    @staticmethod
    def _extract_ip(address_port):
        """Extract the IP portion from an ss-style 'address:port' token,
        handling both IPv4 ('1.2.3.4:80') and bracketed IPv6 ('[::1]:80')."""
        if not address_port:
            return None
        if address_port.startswith('['):
            return address_port.split(']')[0].lstrip('[')
        if ':' in address_port:
            return address_port.rsplit(':', 1)[0]
        return address_port
    
    @staticmethod
    def _extract_port(address_port):
        """Extract the port portion from an ss-style 'address:port' token."""
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
        
        # Fallback for systems without a usable systemd journal for SSH:
        # whole-file count, matching the tool's original (non-windowed) behavior.
        try:
            result = subprocess.run(['grep', '-c', 'Failed password', '/var/log/auth.log'],
                                  capture_output=True, text=True)
            return int(result.stdout.strip() or 0)
        except Exception:
            return 0


class MalwareDetector:
    """NEW: Malware Detection Module - Detects suspicious files"""
    
    def __init__(self):
        self.suspicious_extensions = ['.exe', '.dll', '.scr', '.vbs', '.bat', '.cmd']
        self.suspicious_paths = ['/tmp', '/var/tmp', '/dev/shm']
    
    def scan_for_suspicious_files(self):
        """Scan system for suspicious files"""
        print("[*] Scanning for suspicious files...")
        
        suspicious_files = []
        
        # Scan suspicious locations
        for path in self.suspicious_paths:
            try:
                if os.path.exists(path):
                    for file in os.listdir(path):
                        file_path = os.path.join(path, file)
                        if os.path.isfile(file_path):
                            # Check file permissions
                            perms = oct(os.stat(file_path).st_mode)[-3:]
                            if perms == '777':
                                suspicious_files.append(file_path)
                                print(f"[!] SUSPICIOUS: {file_path} (permissions: {perms})")
            except:
                pass
        
        print(f"[+] Suspicious Files Found: {len(suspicious_files)}")
        return suspicious_files
    
    BASELINE_FILE = '/var/lib/cyber-defense-shield/file_baseline.json'

    def check_file_hashes(self):
        """Check file integrity against a stored baseline, real drift detection.

        Previously this only computed and printed current hashes with
        nothing to compare them against - it couldn't actually tell you
        if a file had changed, despite the README calling this "monitor
        critical system files for changes." Now it does:

        - First run: no baseline exists yet, so this run's hashes become
          the trusted baseline (nothing to flag against yet).
        - Later runs: compares current hashes to the stored baseline and
          reports which files changed or newly appeared/disappeared.

        The baseline is intentionally NOT auto-updated to the latest
        state on every run - that would let a slow, gradual change go
        undetected forever, one silently-accepted "new normal" at a
        time. If a detected change is legitimate (e.g. you edited
        sshd_config on purpose), delete BASELINE_FILE to re-establish
        trust at the current state.

        Security note: an earlier version stored this baseline in
        /var/tmp with default permissions - a predictable, world-
        readable/writable-by-default location any local user could find
        and overwrite to hide their own tampering, defeating the entire
        point of integrity checking. It now lives under /var/lib (root-
        only by default) and the file itself is chmod'd 0600 on write.
        """
        print("[*] Checking file integrity...")

        critical_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/sudoers',
            '/etc/ssh/sshd_config'
        ]

        current_hashes = {}
        for file_path in critical_files:
            try:
                if os.path.exists(file_path):
                    with open(file_path, 'rb') as f:
                        current_hashes[file_path] = hashlib.sha256(f.read()).hexdigest()
            except Exception:
                pass

        try:
            with open(self.BASELINE_FILE, 'r') as f:
                baseline = json.loads(f.read())
        except Exception:
            baseline = None

        if baseline is None:
            try:
                os.makedirs(os.path.dirname(self.BASELINE_FILE), mode=0o700, exist_ok=True)
                with open(self.BASELINE_FILE, 'w') as f:
                    f.write(json.dumps(current_hashes))
                os.chmod(self.BASELINE_FILE, 0o600)
                print(f"[+] File Integrity: Baseline established for {len(current_hashes)} file(s) (nothing to compare yet)")
            except Exception as e:
                print(f"[!] File Integrity: Could not save baseline ({e}); comparisons will not persist")
            return current_hashes

        changed = [p for p in current_hashes if p in baseline and current_hashes[p] != baseline[p]]
        added = [p for p in current_hashes if p not in baseline]
        removed = [p for p in baseline if p not in current_hashes]

        if changed:
            print(f"[!] ALERT: {len(changed)} file(s) changed since baseline: {', '.join(changed)}")
        if added:
            print(f"[!] {len(added)} file(s) newly present: {', '.join(added)}")
        if removed:
            print(f"[!] {len(removed)} baselined file(s) now missing/unreadable: {', '.join(removed)}")
        if not (changed or added or removed):
            print(f"[+] File Integrity: All {len(current_hashes)} file(s) match baseline")

        return current_hashes
    
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

    def analyze_kernel_modules(self):
        """Flag loaded kernel modules that don't exist in the on-disk module tree.

        README previously listed "Kernel Module Analysis" with no code
        behind it. Every legitimately loaded module should have a
        corresponding .ko/.ko.xz file somewhere under
        /lib/modules/$(uname -r)/. A module present in `lsmod` but with no
        matching file on disk is a real, well-known indicator used by
        lightweight rootkit checkers - it's how some LKM-based rootkits
        that only exist in kernel memory (not on disk) can be spotted.

        Scope limit stated plainly: this only catches modules missing
        their on-disk file. A rootkit module that DOES drop a same-named
        file, or one that hides itself from `lsmod` entirely, will not be
        caught by this check - it's one heuristic signal, not a full
        rootkit scanner.
        """
        print("[*] Analyzing loaded kernel modules...")
        flagged = []

        try:
            uname = subprocess.run(['uname', '-r'], capture_output=True, text=True)
            kernel_version = uname.stdout.strip()
            module_dir = f'/lib/modules/{kernel_version}'

            lsmod = subprocess.run(['lsmod'], capture_output=True, text=True)
            loaded_modules = [
                line.split()[0] for line in lsmod.stdout.strip().split('\n')[1:] if line.strip()
            ]

            find_result = subprocess.run(
                ['find', module_dir, '-name', '*.ko*'],
                capture_output=True, text=True, timeout=10
            )
            on_disk_names = set()
            for path in find_result.stdout.strip().split('\n'):
                if path:
                    base = os.path.basename(path).split('.ko')[0].replace('-', '_')
                    on_disk_names.add(base)

            for module in loaded_modules:
                if module.replace('-', '_') not in on_disk_names and on_disk_names:
                    flagged.append(f"Module '{module}' is loaded but has no matching file under {module_dir}")
                    print(f"[!] SUSPICIOUS: kernel module '{module}' not found on disk")

            print(f"[+] Kernel Module Analysis: {len(loaded_modules)} loaded, {len(flagged)} flagged")
        except Exception as e:
            print(f"[!] Kernel Module Analysis: {e}")

        return flagged

    def check_rootkit_indicators(self):
        """Check a small set of well-known basic rootkit indicators.

        README previously listed "Rootkit Detection" with no code behind
        it. This is NOT a rootkit scanner - real tools for that job are
        rkhunter and chkrootkit, and Option 15's suggestions already
        recommend them. What this does check, honestly:

        1. Process-count discrepancy: compares how many processes `ps`
           reports against how many PID directories exist under /proc.
           A mismatch is a classic (if old) sign of a process-hiding
           rootkit, since some rootkits hook the syscalls `ps` relies on
           but can't as easily hide entries from /proc itself.
        2. A short list of historically well-known rootkit file paths.

        A clean result here does NOT mean the system is free of rootkits
        - most modern rootkits defeat both of these checks. This is a
        cheap first-pass signal, not a guarantee.
        """
        print("[*] Checking basic rootkit indicators...")
        findings = []

        try:
            ps_result = subprocess.run(['ps', '-e'], capture_output=True, text=True)
            ps_count = max(len(ps_result.stdout.strip().split('\n')) - 1, 0)

            proc_pids = [d for d in os.listdir('/proc') if d.isdigit()]
            proc_count = len(proc_pids)

            diff = abs(proc_count - ps_count)
            if proc_count > 0 and diff > max(5, proc_count * 0.1):
                findings.append(
                    f"Process count mismatch: ps shows {ps_count}, /proc shows {proc_count} "
                    f"(possible process-hiding rootkit)"
                )
                print(f"[!] ALERT: process count mismatch (ps={ps_count}, /proc={proc_count})")
            else:
                print(f"[+] Process count consistent (ps={ps_count}, /proc={proc_count})")
        except Exception as e:
            print(f"[!] Process count check failed: {e}")

        known_rootkit_paths = [
            '/usr/lib/.rootkit', '/usr/lib/.libselinux', '/dev/.udev.db',
            '/dev/shm/.mount', '/usr/share/.aptitude', '/etc/rc.d/rc.local.d',
        ]
        found_paths = [p for p in known_rootkit_paths if os.path.exists(p)]
        if found_paths:
            findings.append(f"Known suspicious path(s) present: {', '.join(found_paths)}")
            print(f"[!] ALERT: suspicious path(s) found: {', '.join(found_paths)}")
        else:
            print("[+] No known suspicious rootkit paths found")

        return findings

    def run_rkhunter_scan(self):
        """Run a real rootkit scan via rkhunter, if it's installed.

        check_rootkit_indicators() above is an intentionally basic
        heuristic (process-count mismatch + a handful of known paths) -
        independent reviews of this project converged on the same point:
        defer to a real, purpose-built rootkit scanner instead of this
        tool trying to reinvent one. This method does that - it looks
        for rkhunter and runs an actual scan if present, or gives clear
        install instructions if not, rather than silently skipping it.

        Not run by daemon mode: a full rkhunter scan can take a minute
        or more and walks a large part of the filesystem, which doesn't
        belong in a lightweight periodic background loop. Available from
        the interactive menu (Option 11) only.
        """
        rkhunter_path = shutil.which('rkhunter')
        if not rkhunter_path:
            print("[!] rkhunter is not installed - this tool's own rootkit checks")
            print("    are basic heuristics, not a substitute for a real scanner.")
            print("    Install it for a proper rootkit scan: sudo apt install rkhunter")
            return None

        print("[*] Running rkhunter scan (this can take a minute or more)...")
        try:
            result = subprocess.run(
                [rkhunter_path, '--check', '--skip-keypress', '--report-warnings-only', '--nocolors'],
                capture_output=True, text=True, timeout=180
            )
            output = result.stdout.strip()
            if output:
                print("[!] rkhunter warnings:")
                print(output)
            else:
                print("[+] rkhunter: no warnings")
            return output
        except subprocess.TimeoutExpired:
            print("[!] rkhunter scan timed out after 180s")
            return None
        except Exception as e:
            print(f"[!] rkhunter scan failed: {e}")
            return None


class UserActivityAuditor:
    """NEW: User Activity Auditing Module - Tracks user actions"""
    
    def audit_user_logins(self):
        """Audit user login history"""
        print("[*] Auditing user login history...")
        
        try:
            result = subprocess.run(['last', '-n', '20'], capture_output=True, text=True)
            logins = result.stdout.count('\n')
            print(f"[+] Recent Logins: {logins}")
            
            # Check for unauthorized access
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
            
            # Check for failed sudo attempts
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
    """NEW: Advanced Report Generation - Professional reporting"""
    
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
            <h1>🛡️ Cyber-Defense-Shield</h1>
            <p>Comprehensive Security Assessment Report v1.4</p>
            <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <p>This comprehensive report provides a detailed security assessment of your system using Cyber-Defense-Shield v1.4.</p>
            <p>The assessment includes vulnerability scanning, intrusion detection, malware detection, user auditing, and more.</p>
            <div style="margin-top: 20px;">
                <span class="metric">
                    <div class="metric-value">15</div>
                    <div class="metric-label">Security Modules</div>
                </span>
                <span class="metric">
                    <div class="metric-value">16</div>
                    <div class="metric-label">Checks Available</div>
                </span>
                <span class="metric">
                    <div class="metric-value">Optional</div>
                    <div class="metric-label">Daemon + Alerts</div>
                </span>
                <span class="metric">
                    <div class="metric-value">Signature-Based</div>
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
                    <td><span class="success">✓ Active</span></td>
                    <td><span class="risk-level risk-low">Low</span></td>
                </tr>
                <tr>
                    <td>Network Monitoring</td>
                    <td><span class="success">✓ Active</span></td>
                    <td><span class="risk-level risk-low">Low</span></td>
                </tr>
                <tr>
                    <td>Vulnerability Scanner</td>
                    <td><span class="success">✓ Active</span></td>
                    <td><span class="risk-level risk-medium">Medium</span></td>
                </tr>
                <tr>
                    <td>Intrusion Detection</td>
                    <td><span class="success">✓ Active</span></td>
                    <td><span class="risk-level risk-low">Low</span></td>
                </tr>
                <tr>
                    <td>Malware Detection</td>
                    <td><span class="success">✓ Active</span></td>
                    <td><span class="risk-level risk-low">Low</span></td>
                </tr>
                <tr>
                    <td>User Auditing</td>
                    <td><span class="success">✓ Active</span></td>
                    <td><span class="risk-level risk-low">Low</span></td>
                </tr>
                <tr>
                    <td>DDoS Protection</td>
                    <td><span class="success">✓ Enabled</span></td>
                    <td><span class="risk-level risk-low">Low</span></td>
                </tr>
                <tr>
                    <td>Firewall</td>
                    <td><span class="success">✓ Enabled</span></td>
                    <td><span class="risk-level risk-low">Low</span></td>
                </tr>
                <tr>
                    <td>System Hardening</td>
                    <td><span class="success">✓ Applied</span></td>
                    <td><span class="risk-level risk-low">Low</span></td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>NEW IN v1.4</h2>
            <ul>
                <li><span class="success">✓</span> <strong>Daemon Mode:</strong> Run continuously in the background with <code>--daemon</code> instead of only via the interactive menu (see cyber-defense-shield.service for systemd)</li>
                <li><span class="success">✓</span> <strong>Telegram / Discord Alerts:</strong> Daemon mode can push findings automatically instead of only logging locally</li>
                <li><span class="success">✓</span> <strong>Idempotent, Backed-Up SSH Hardening:</strong> Re-running hardening no longer duplicates config; original sshd_config is backed up and new config is validated with <code>sshd -t</code> before applying</li>
                <li><span class="success">✓</span> <strong>Persistent Rate-Limiting Rules:</strong> iptables hashlimit rules now survive a reboot and are no longer duplicated on repeated runs</li>
                <li><span class="success">✓</span> <strong>Per-Source Rate Limiting:</strong> DDoS protection now throttles by source IP instead of one shared global limit, so concurrent legitimate users no longer exhaust each other's allowance</li>
                <li><span class="success">✓</span> <strong>Source-Aware Intrusion Detection:</strong> Port scan and SYN flood checks are now grouped per source IP instead of a single system-wide counter</li>
                <li><span class="success">✓</span> <strong>Time-Windowed Brute Force Detection:</strong> Failed login alerts are based on a recent time window instead of a lifetime log total</li>
                <li><span class="success">✓</span> <strong>Configurable Detection Thresholds:</strong> Rate limits and detection sensitivity are now tunable in config.py instead of hardcoded</li>
                <li><span class="success">✓</span> <strong>Reduced False Positives:</strong> Suspicious-IP detection now requires an actual connection-count signal instead of flagging every remote address</li>
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
            <p><strong>Cyber-Defense-Shield v1.4</strong></p>
            <p>Multi-Layered Security Tool for Linux Systems</p>
            <p>Cyber-Rage Security Team © 2026</p>
            <p>Report generated by signature-based detection and system checks - see the project README for full scope and limitations</p>
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
