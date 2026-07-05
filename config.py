#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Configuration Settings - Cyber-Defense-Shield
"""

# ============================================
# FIREWALL CONFIGURATION
# ============================================
FIREWALL_ENABLED = True
FIREWALL_TYPE = "UFW"
DEFAULT_POLICY_INCOMING = "deny"
DEFAULT_POLICY_OUTGOING = "allow"

# ============================================
# DDoS PROTECTION SETTINGS
# ============================================
DDOS_PROTECTION_ENABLED = True
RATE_LIMIT_PER_MINUTE = 25
RATE_LIMIT_BURST = 100
RATE_LIMITED_PORTS = [80, 443]  # ports covered by the per-source rate limit
SYN_COOKIES_ENABLED = True
TCP_SYNCOOKIES = 1

# ============================================
# SSH CONFIGURATION
# ============================================
SSH_PORT = 22
PERMIT_ROOT_LOGIN = False
PASSWORD_AUTH_ENABLED = False
PUBKEY_AUTH_ENABLED = True
X11_FORWARDING = False
MAX_AUTH_TRIES = 3
CLIENT_ALIVE_INTERVAL = 300
CLIENT_ALIVE_COUNT_MAX = 2
SSH_PROTOCOL = 2

# ============================================
# MONITORING SETTINGS
# ============================================
MONITORING_INTERVAL = 5  # seconds
LOG_FILE = "/var/log/cyber-defense.log"
ALERT_EMAIL = "admin@example.com"
ENABLE_EMAIL_ALERTS = False

# ============================================
# DANGEROUS PORTS TO BLOCK
# ============================================
DANGEROUS_PORTS = [
    21,     # FTP
    23,     # Telnet
    69,     # TFTP
    135,    # RPC Endpoint Mapper
    139,    # NetBIOS Session Service
    445,    # SMB
    1433,   # MS SQL Server
    3306,   # MySQL
    3389,   # RDP
    5900,   # VNC
    5984,   # CouchDB
    6379,   # Redis
    7000,   # Cassandra
    8086,   # InfluxDB
    9042,   # Cassandra
    9160,   # Cassandra Thrift
    27017,  # MongoDB
    50070,  # Hadoop NameNode
]

# ============================================
# SAFE PORTS TO ALLOW
# ============================================
SAFE_PORTS = [
    22,     # SSH
    80,     # HTTP
    443,    # HTTPS
    53,     # DNS
    123,    # NTP
]

# ============================================
# UNNECESSARY SERVICES TO DISABLE
# ============================================
UNNECESSARY_SERVICES = [
    'cups',
    'avahi-daemon',
    'isc-dhcp-server',
    'snmpd',
    'rsync',
    'telnet',
    'vsftpd',
    'bind9',
    'dhcp3-server',
    'slapd',
]

# ============================================
# SUSPICIOUS PROCESS PATTERNS
# ============================================
SUSPICIOUS_PATTERNS = [
    'nc ',
    'ncat ',
    '/dev/tcp',
    '/dev/udp',
    'curl http',
    'wget http',
    'bash -i',
    'sh -i',
    'exec',
    '/bin/bash',
]

# ============================================
# FIREWALL RULES CONFIGURATION
# ============================================
FIREWALL_RULES = {
    'default_incoming': 'deny',
    'default_outgoing': 'allow',
    'allow_protocols': ['tcp', 'udp', 'icmp'],
    'enable_logging': True,
}

# ============================================
# REPORT SETTINGS
# ============================================
REPORT_FORMAT = "html"
REPORT_DIR = "/tmp/cyber_defense_reports/"
AUTO_GENERATE_REPORT = True
REPORT_INCLUDE_GRAPHS = True
REPORT_INCLUDE_RECOMMENDATIONS = True

# ============================================
# LOGGING CONFIGURATION
# ============================================
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_ROTATION_SIZE = 10485760  # 10MB
LOG_RETENTION_DAYS = 30
LOG_FORMAT = "[%(asctime)s] [%(levelname)s] %(message)s"

# ============================================
# THREAT DETECTION SETTINGS
# ============================================
THREAT_DETECTION_ENABLED = True
ALERT_ON_THREATS = True
THREAT_SEVERITY_LEVELS = {
    'CRITICAL': 1,
    'HIGH': 2,
    'MEDIUM': 3,
    'LOW': 4,
    'INFO': 5,
}

# ============================================
# INTRUSION DETECTION SYSTEM (IDS) TUNING
# ============================================
# These thresholds control when the IDS reports a possible attack. There is
# no single "correct" value: a threshold that is safe for a quiet personal
# server can fire constantly on a busy production host, and a threshold
# tuned for a busy host may be too loose to catch anything on a quiet one.
# Review your own normal traffic/logs before relying on these for any
# automated response, and adjust them to match your actual baseline.
SYN_RECV_PER_SOURCE_THRESHOLD = 30       # half-open (SYN-RECV) connections from one source IP
PORT_SCAN_DISTINCT_PORTS_THRESHOLD = 15  # distinct local ports touched by one source IP
BRUTE_FORCE_WINDOW_MINUTES = 10          # time window used when counting failed logins
BRUTE_FORCE_ATTEMPTS_THRESHOLD = 8       # failed logins within the window above
SUSPICIOUS_IP_CONNECTION_THRESHOLD = 20  # concurrent connections from one source IP

# ============================================
# NETWORK SECURITY SETTINGS
# ============================================
NETWORK_SECURITY = {
    'enable_syn_protection': True,
    'enable_icmp_echo_ignore': False,
    'enable_reverse_path_filter': True,
    'enable_source_route_check': True,
    'tcp_max_syn_backlog': 2048,
}

# ============================================
# SYSTEM HARDENING SETTINGS
# ============================================
SYSTEM_HARDENING = {
    'disable_ipv6': False,
    'disable_uncommon_protocols': True,
    'set_umask': '0077',
    'enable_process_accounting': True,
    'enable_audit': True,
}

# ============================================
# ATTACK PATTERNS SIGNATURES
# ============================================
ATTACK_PATTERNS = {
    'SQL_INJECTION': [
        'union select',
        'or 1=1',
        'drop table',
        'insert into',
        'delete from',
    ],
    'XSS': [
        '<script',
        'javascript:',
        'onerror=',
        'onload=',
    ],
    'PATH_TRAVERSAL': [
        '../',
        '..\\',
        '%2e%2e/',
    ],
}

# ============================================
# EMAIL ALERT SETTINGS
# ============================================
EMAIL_CONFIG = {
    'enabled': False,
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'sender_email': 'security@example.com',
    'sender_password': 'password',
    'recipient_emails': ['admin@example.com'],
}

# ============================================
# SLACK INTEGRATION (Optional)
# ============================================
SLACK_CONFIG = {
    'enabled': False,
    'webhook_url': 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL',
    'channel': '#security-alerts',
    'username': 'Cyber-Defense-Shield',
}

# ============================================
# DATABASE SETTINGS (Optional)
# ============================================
DATABASE_CONFIG = {
    'enabled': False,
    'type': 'sqlite',  # sqlite, mysql, postgresql
    'host': 'localhost',
    'port': 3306,
    'username': 'root',
    'password': 'password',
    'database': 'cyber_defense',
}

# ============================================
# PERFORMANCE SETTINGS
# ============================================
PERFORMANCE = {
    'max_threads': 10,
    'scan_timeout': 300,  # seconds
    'cache_enabled': True,
    'cache_ttl': 3600,  # seconds
}

# ============================================
# NOTIFICATION SETTINGS
# ============================================
NOTIFICATIONS = {
    'console_output': True,
    'log_file_output': True,
    'email_notifications': False,
    'slack_notifications': False,
    'sound_alerts': False,
}

# ============================================
# CUSTOM ALERT THRESHOLDS
# ============================================
ALERT_THRESHOLDS = {
    'failed_login_attempts': 5,
    'connection_timeout': 30,
    'high_cpu_usage': 80,
    'high_memory_usage': 85,
    'disk_space_warning': 90,
}

# ============================================
# ADVANCED OPTIONS
# ============================================
ADVANCED = {
    'enable_experimental_features': False,
    'enable_debug_mode': False,
    'enable_verbose_output': False,
    'save_pcap_files': False,
    'enable_packet_analysis': False,
}

# ============================================
# FILE INTEGRITY MONITORING
# ============================================
FILE_INTEGRITY_PATHS = [
    '/etc/passwd',
    '/etc/shadow',
    '/etc/sudoers',
    '/etc/ssh/sshd_config',
    '/root',
    '/boot',
]

# ============================================
# CRITICAL SYSTEM CHECKS
# ============================================
CRITICAL_CHECKS = {
    'check_rootkit': True,
    'check_malware': True,
    'check_kernel_modules': True,
    'check_system_calls': True,
    'check_loaded_libraries': True,
}

# ============================================
# COMPLIANCE SETTINGS
# ============================================
COMPLIANCE = {
    'cis_benchmark': True,
    'pci_dss': False,
    'hipaa': False,
    'gdpr': False,
}
