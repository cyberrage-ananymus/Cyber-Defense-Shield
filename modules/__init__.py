"""
Defense Modules Package - Core Security Components
Cyber-Defense-Shield v1.5
"""

from .alerts import AlertNotifier
from .scanner import SecurityScanner, VulnerabilityScanner
from .network import NetworkMonitor, DDosProtector
from .firewall import FirewallManager
from .hardening import SystemHardener
from .logging_analyzer import LogAnalyzer
from .realtime import RealtimeThreatDetector
from .reporting import ReportGenerator, AdvancedReporter
from .ids import IntrusionDetectionSystem
from .malware import MalwareDetector
from .auditing import UserActivityAuditor
from .web import WebAttackScanner

__all__ = [
    'AlertNotifier',
    'SecurityScanner',
    'VulnerabilityScanner',
    'NetworkMonitor',
    'DDosProtector',
    'FirewallManager',
    'SystemHardener',
    'LogAnalyzer',
    'RealtimeThreatDetector',
    'ReportGenerator',
    'AdvancedReporter',
    'IntrusionDetectionSystem',
    'MalwareDetector',
    'UserActivityAuditor',
    'WebAttackScanner',
]
