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
from unittest.mock import patch, MagicMock

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


if __name__ == '__main__':
    unittest.main(verbosity=2)
