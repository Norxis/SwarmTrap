#!/usr/bin/env python3
"""
evidence_ingest.py — Merged UDP rsyslog receiver + ClickHouse evidence writer.

Replaces the former two-service pipeline (dfi2-log-bridge → dfi2-evidence-ingest).

Thread 1 (main) — UDP receiver:
    recvfrom() → parse JSON → batch-write SQLite → enqueue events for CH

Thread 2 (daemon) — ClickHouse writer:
    drain queue → batch INSERT into dfi.evidence_events_buffer → advance watermark
    On startup/reconnect: replay un-ingested rows from SQLite via watermark.

SQLite writes kept for crash safety — if ClickHouse is down, events are recoverable.
"""
import json
import logging
import os
import queue
import re
import socket
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone

from clickhouse_driver import Client

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s')
log = logging.getLogger('evidence_ingest')

# ── SQLite / Bridge constants ─────────────────────────────────────────────────
EVIDENCE_DB  = os.environ.get('EVIDENCE_DB',  '/mnt/dfi-data/evidence/evidence.db')
BRIDGE_HOST  = os.environ.get('BRIDGE_HOST',  '127.0.0.1')
BRIDGE_PORT  = int(os.environ.get('BRIDGE_PORT',  '1514'))
SQLITE_BATCH = int(os.environ.get('SQLITE_BATCH', '500'))
SQLITE_FLUSH = float(os.environ.get('SQLITE_FLUSH', '1.0'))

# ── ClickHouse constants ──────────────────────────────────────────────────────
CH_HOST        = os.environ.get('CH_HOST', 'localhost')
CH_PORT        = int(os.environ.get('CH_PORT', '9000'))
WATERMARK_FILE = os.environ.get('WATERMARK_FILE', '/opt/dfi2/evidence_watermark.txt')
CH_BATCH_SIZE  = int(os.environ.get('CH_BATCH_SIZE', '2000'))
CH_FLUSH_SEC   = float(os.environ.get('CH_FLUSH_SEC', '2.0'))

# ── VM IP → name / os / type (from dfi_log_bridge) ───────────────────────────
_IP_MAP = {
    '172.16.3.168': ('UBT20',  'Ubuntu 20.04',      'linux'),
    '172.16.3.166': ('UBT22',  'Ubuntu 22.04',      'linux'),
    '172.16.3.167': ('UBT24',  'Ubuntu 24.04',      'linux'),
    '172.16.3.213': ('SRV19',  'Win Server 2019',   'windows'),
    '172.16.3.212': ('SRV22',  'Win Server 2022',   'windows'),
    '172.16.3.170': ('SRV25',  'Win Server 2025',   'windows'),
    '172.16.3.210': ('WIN10',  'Windows 10 Pro',    'windows'),
    '172.16.3.209': ('SQL19',  'MSSQL 2019',        'windows'),
    '172.16.3.208': ('SQL22',  'MSSQL 2022',        'windows'),
    '172.16.3.169': ('SQL25',  'MSSQL 2025',        'windows'),
}

# ── Event maps ────────────────────────────────────────────────────────────────
WINDOWS_EVENT_MAP = {
    # §4.1 Authentication / Session (WIN-EVENT-C v2.1)
    4625: ('auth_failure', 0),           # Logon failed
    4624: ('auth_success', 1),           # Logon succeeded
    4648: ('auth_success', 1),           # Explicit-credentials logon
    4740: ('auth_failure', 0),           # Account locked out
    4768: ('auth_failure', 0),           # Kerberos TGT request failure
    4769: ('auth_failure', 0),           # Kerberos service ticket failure
    4771: ('auth_failure', 0),           # Kerberos pre-auth failure
    4776: ('auth_failure', 0),           # NTLM credential validation
    4777: ('auth_failure', 0),           # Credential validation failed
    4778: ('auth_success', 1),           # RDP session reconnected
    1149: ('auth_success', 1),           # NLA auth succeeded (TS-RCM)
    # §4.3 SMB
    551:  ('auth_failure', 0),           # SMB session setup failed
    # §4.4 MSSQL / Application
    18452: ('auth_failure', 0),          # MSSQL login failed untrusted
    18453: ('auth_success', 1),          # MSSQL login success
    18454: ('auth_success', 1),          # MSSQL login success
    18456: ('auth_failure', 0),          # MSSQL login failure
    33205: ('auth_failure', 0),          # MSSQL audit login failed
    # §4.5 Process / Command
    4688: ('process_create', 2),         # Process creation (SUSP override applies)
    # 4104: BLOCKED — PowerShell ScriptBlock fires on built-in modules (Windows housekeeping)
    4103: ('suspicious_command', 4),     # PowerShell module logging
    # 53504: BLOCKED — WinRM operational startup (fires every boot, no attacker info)
    # §4.6 Service / Task Persistence
    7045: ('service_install', 3),        # Service installed (System)
    4697: ('service_install', 3),        # Service installed (Security)
    4698: ('service_install', 3),        # Scheduled task created
    4699: ('suspicious_command', 4),     # Scheduled task deleted
    4700: ('service_install', 3),        # Scheduled task enabled
    4702: ('suspicious_command', 4),     # Scheduled task updated
    # 7040: BLOCKED — BITS/WMI service start type toggling (Windows Update housekeeping)
    # §4.7 Account / Group / Privilege
    # 4672: BLOCKED — SYSTEM account special privilege logon (fires every boot/service start)
    # 4717: BLOCKED — System security access granted to machine account (housekeeping)
    # 4718: BLOCKED — System security access removed from machine account (housekeeping)
    4720: ('privilege_escalation', 6),   # User account created
    4722: ('privilege_escalation', 6),   # User account enabled
    4723: ('privilege_escalation', 6),   # Password change attempt
    4724: ('privilege_escalation', 6),   # Password reset attempt
    4725: ('privilege_escalation', 6),   # User account disabled
    4726: ('suspicious_command', 4),     # User account deleted
    4728: ('privilege_escalation', 6),   # Member added to global group
    4732: ('privilege_escalation', 6),   # Member added to local group
    4733: ('suspicious_command', 4),     # Member removed from local group
    4756: ('privilege_escalation', 6),   # Member added to universal group
    # §4.8 Object Access / Tamper / Evasion
    4656: ('suspicious_command', 4),     # Object handle requested
    4657: ('suspicious_command', 4),     # Registry value modified
    4660: ('suspicious_command', 4),     # Object deleted
    4663: ('suspicious_command', 4),     # Object access attempt
    4670: ('privilege_escalation', 6),   # Permissions changed
    1102: ('suspicious_command', 4),     # Audit log cleared (critical)
    4719: ('suspicious_command', 4),     # Audit policy changed
    4907: ('suspicious_command', 4),     # Object audit settings changed
    # §4.9 Firewall / Network Control
    4946: ('suspicious_command', 4),     # Firewall rule added
    4947: ('suspicious_command', 4),     # Firewall rule modified
    4948: ('suspicious_command', 4),     # Firewall rule deleted
    4950: ('suspicious_command', 4),     # Firewall setting changed
    5025: ('suspicious_command', 4),     # Firewall service stopped
    5030: ('suspicious_command', 4),     # Firewall service failed start
}

# §4.10 Defender events — channel-gated to avoid collision with SmbClient 1006
DEFENDER_EVENT_MAP = {
    1006: ('suspicious_command', 4),     # Malware detected
    1007: ('suspicious_command', 4),     # Action taken
    1008: ('suspicious_command', 4),     # Action failed
    1116: ('suspicious_command', 4),     # Threat detected
    1117: ('suspicious_command', 4),     # Threat action
    5001: ('suspicious_command', 4),     # Real-time protection disabled
    5004: ('suspicious_command', 4),     # RTP configuration changed
    5007: ('suspicious_command', 4),     # Defender configuration changed
    5010: ('suspicious_command', 4),     # Scanning disabled
    5012: ('suspicious_command', 4),     # Virus scanning disabled
    5013: ('suspicious_command', 4),     # Tamper-protection blocked change
}

# §4.11 Sysmon events — channel-gated to avoid collision with TS-LSM 21/25
SYSMON_EVENT_MAP = {
    1:  ('process_create', 2),           # Process creation (SUSP override applies)
    2:  ('suspicious_command', 4),       # File creation time changed
    # 3: context (network connection) — skip
    # 5: context (process terminated) — skip
    6:  ('suspicious_command', 4),       # Driver loaded
    7:  ('suspicious_command', 4),       # Image loaded
    8:  ('suspicious_command', 4),       # CreateRemoteThread
    9:  ('suspicious_command', 4),       # RawAccessRead
    10: ('suspicious_command', 4),       # ProcessAccess (LSASS)
    11: ('file_download', 5),            # FileCreate
    12: ('suspicious_command', 4),       # Registry object create/delete
    13: ('suspicious_command', 4),       # Registry value set
    15: ('suspicious_command', 4),       # ADS/stream hash
    17: ('suspicious_command', 4),       # Pipe created
    18: ('suspicious_command', 4),       # Pipe connected
    19: ('service_install', 3),          # WMI event filter
    20: ('service_install', 3),          # WMI event consumer
    21: ('service_install', 3),          # WMI filter-consumer binding
    22: ('suspicious_command', 4),       # DNS query
    23: ('suspicious_command', 4),       # File delete archived
    25: ('suspicious_command', 4),       # Process tampering
    26: ('suspicious_command', 4),       # File delete detected
    27: ('suspicious_command', 4),       # Executable block
    28: ('suspicious_command', 4),       # Shredding block
    29: ('process_create', 2),           # FileExecutableDetected
}

SSHD_PATTERNS = [
    (re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+)'), 'auth_failure', 0),
    (re.compile(r'Accepted (?:password|publickey) for (\S+) from (\S+)'), 'auth_success', 1),
    (re.compile(r'Invalid user (\S+) from (\S+)'), 'auth_failure', 0),
    (re.compile(r'Connection closed by authenticating user (\S+) (\S+)'), 'auth_failure', 0),
    (re.compile(r'Disconnected from authenticating user (\S+) (\S+)'), 'auth_failure', 0),
]

# ── Service-specific patterns ────────────────────────────────────────────────
SERVICE_PATTERNS = [
    (re.compile(r'\[(?P<ip>\d+\.\d+\.\d+\.\d+)\].*SASL (?:LOGIN|PLAIN) authentication failed.*sasl_username=(?P<user>\S+)'),
     'auth_failure', 0, 'postfix_sasl'),
    (re.compile(r'\[(?P<ip>\d+\.\d+\.\d+\.\d+)\].*sasl_method=\S+,\s*sasl_username=(?P<user>\S+)'),
     'auth_success', 1, 'postfix_sasl'),
    (re.compile(r'(?:auth.*(?:failed|invalid)|(?:failed|invalid).*auth).*(?:user=<?(?P<user>[^>}\s]*)>?)?.*(?:rip=)?(?P<ip>\d+\.\d+\.\d+\.\d+)'),
     'auth_failure', 0, 'dovecot'),
    (re.compile(r'\[client (?P<ip>\d+\.\d+\.\d+\.\d+):\d+\].*(?:AH10244|invalid URI|\.\./)'),
     'path_traversal', 2, 'apache'),
    (re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - (?P<user>\S+) .*" 401 '),
     'auth_failure', 0, 'apache'),
    (re.compile(r"Access denied for user '(?P<user>[^']*)'@'(?P<ip>\d+\.\d+\.\d+\.\d+)'"),
     'auth_failure', 0, 'mysql'),
    (re.compile(r'connection.*host=(?P<ip>\d+\.\d+\.\d+\.\d+).*FATAL.*password authentication failed for user "(?P<user>[^"]*)"'),
     'auth_failure', 0, 'postgresql'),
    (re.compile(r'no pg_hba.conf entry for host "(?P<ip>\d+\.\d+\.\d+\.\d+)".*user "(?P<user>[^"]*)"'),
     'auth_failure', 0, 'postgresql'),
    (re.compile(r'Client.*(?P<ip>\d+\.\d+\.\d+\.\d+):\d+.*(?:NOAUTH|AUTH failed|permission denied)'),
     'auth_failure', 0, 'redis'),
    (re.compile(r'(?:authentication|auth).*failed.*client:(?P<ip>\d+\.\d+\.\d+\.\d+)'),
     'auth_failure', 0, 'mongodb'),
    (re.compile(r'(?:org\.elasticsearch|\[o\.e\.|ElasticsearchSecurityException).*\b(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'),
     'auth_failure', 0, 'elasticsearch'),
    (re.compile(r"(?:NOTICE|WARNING).*'(?P<user>[^']*)'.*failed.*from.*'(?:sip:|udp:)?(?P<ip>\d+\.\d+\.\d+\.\d+)"),
     'auth_failure', 0, 'asterisk_sip'),
    (re.compile(r'conn=\d+.*BIND.*dn="(?P<user>[^"]*)".*err=49'),
     'auth_failure', 0, 'slapd'),
    (re.compile(r'FAIL LOGIN.*Client "(?P<ip>\d+\.\d+\.\d+\.\d+)".*user "(?P<user>[^"]*)"'),
     'auth_failure', 0, 'vsftpd'),
    (re.compile(r'fail2ban.*Ban (?P<ip>\d+\.\d+\.\d+\.\d+)'),
     'auth_failure', 0, 'fail2ban'),
    (re.compile(r'FTP: USER (?P<user>\S+)'), 'auth_attempt', 0, 'trap_ftp'),
    (re.compile(r'FTP: PASS '), 'credential_capture', 1, 'trap_ftp'),
    (re.compile(r'Telnet user: (?P<user>\S+)'), 'auth_attempt', 0, 'trap_telnet'),
    (re.compile(r'Telnet pass: '), 'credential_capture', 1, 'trap_telnet'),
    (re.compile(r'SMTP AUTH: '), 'auth_attempt', 0, 'trap_smtp'),
    (re.compile(r'POP3 cred: '), 'credential_capture', 1, 'trap_pop3'),
    (re.compile(r'IMAP cred: '), 'credential_capture', 1, 'trap_imap'),
    (re.compile(r'SIP-(?:UDP|TCP): INVITE.*from (?P<ip>\d+\.\d+\.\d+\.\d+)'),
     'auth_attempt', 0, 'trap_sip'),
]

SUSP = re.compile(
    r'(powershell|certutil|bitsadmin|wget|curl|nc\.exe|netcat|mimikatz|psexec'
    r'|mshta|regsvr32|rundll32|wmic|cmstp|msiexec|schtasks|at\.exe'
    r'|whoami|net\s+user|net\s+localgroup|net\s+group|ipconfig|systeminfo'
    r'|tasklist|cmd\.exe\s+/c|bash\s+-i|python\s+-c|perl\s+-e'
    r'|chmod\s+\+[xs]|chown|useradd|passwd|shadow|\.ssh/authorized_keys'
    r'|/etc/crontab|crontab\s+-[el]|ncat|socat'
    # §6 additions: encoded command / shell
    r'|-enc(?:oded)?(?:c(?:ommand)?)?|FromBase64String|ToBase64String'
    # §6 additions: lolbins
    r'|wscript|cscript|forfiles|pcalua|infdefaultinstall'
    # §6 additions: credential access
    r'|procdump|comsvcs\.dll|sekurlsa|lsass'
    # §6 additions: defense evasion / anti-forensics
    r'|vssadmin|wevtutil\s+cl|bcdedit|Set-MpPreference'
    # §6 additions: lateral movement
    r'|Enter-PSSession|Invoke-Command|winrs'
    # §6 additions: persistence
    r'|sc\s+(create|config))',
    re.I,
)
IP_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')
EVID_RE = re.compile(r'EventID=(\d+)')


# ── Helpers ───────────────────────────────────────────────────────────────────

def _valid_ip(ip: str):
    if not ip or ip == '0.0.0.0':
        return False
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    if not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return False
    # .0 and .255 ARE valid host IPs in CIDR blocks smaller than /24
    return True


def _safe_ip(ip):
    return ip if ip and _valid_ip(ip) else '0.0.0.0'


_SRC_NET_RE = re.compile(
    r'Source Network Address\S*\s+(\d{1,3}(?:\.\d{1,3}){3})')
_SRC_ADDR_RE = re.compile(
    r'(?:Source Address|IpAddress|Client Address)\S*\s+(\d{1,3}(?:\.\d{1,3}){3})')
_INTERNAL_PREFIXES = ('10.', '127.', '192.168.', '0.0.') + tuple(
    f'172.{i}.' for i in range(16, 32))
_ACCOUNT_NAME_RE = re.compile(r'Account Name\S*\s+(\S+)')


def _extract_ip(text: str):
    """Extract attacker IP from Windows event log message.
    Normalizes #011 (rsyslog tab encoding) to space, then tries
    field-specific patterns before falling back to generic IP search.
    """
    if not text:
        return None
    t = text.replace('#011', ' ')
    for pat in (_SRC_NET_RE, _SRC_ADDR_RE):
        m = pat.search(t)
        if m and _valid_ip(m.group(1)) and not m.group(1).startswith(_INTERNAL_PREFIXES):
            return m.group(1)
    m = IP_RE.search(t)
    if m and _valid_ip(m.group(1)) and not m.group(1).startswith(_INTERNAL_PREFIXES):
        return m.group(1)
    return None


def _parse_ts(v):
    ts = None
    if isinstance(v, (int, float)):
        ts = float(v)
    elif isinstance(v, str):
        try:
            ts = float(v)
        except Exception:
            try:
                return datetime.fromisoformat(v.replace('Z', '+00:00'))
            except Exception:
                ts = time.time()
    else:
        ts = time.time()
    return datetime.fromtimestamp(float(ts), tz=timezone.utc)


# ── Event parsers ─────────────────────────────────────────────────────────────

def _parse_windows(row: dict, ev_id: int):
    prog = str(row.get('program', '')).lower()

    # Channel-gated: Sysmon events (avoid collision with TS-LSM 21/25)
    if 'sysmon' in prog and ev_id in SYSMON_EVENT_MAP:
        event_type, mask_bit = SYSMON_EVENT_MAP[ev_id]
        source_tag = f'sysmon_{ev_id}'
    # Channel-gated: Defender events (avoid collision with SmbClient 1006)
    elif 'defender' in prog and ev_id in DEFENDER_EVENT_MAP:
        event_type, mask_bit = DEFENDER_EVENT_MAP[ev_id]
        source_tag = f'defender_{ev_id}'
    # Standard Windows events
    elif ev_id in WINDOWS_EVENT_MAP:
        event_type, mask_bit = WINDOWS_EVENT_MAP[ev_id]
        source_tag = f'windows_{ev_id}'
    else:
        return None  # Unknown or context-only event — skip ingestion

    msg = row.get('message', '')
    # SUSP override for process creation events (4688, Sysmon 1, Sysmon 29)
    if event_type == 'process_create' and SUSP.search(msg):
        event_type, mask_bit = ('suspicious_command', 4)
    # Post-auth events (suspicious_command, privilege_escalation, etc.) don't have
    # attacker IP in the message — only host-side activity. Set to 0.0.0.0 and let
    # _flush_ch post-auth attribution fill it from the _target_attacker cache.
    if event_type in _POST_AUTH_TYPES:
        src_ip = '0.0.0.0'
    else:
        src_ip = _safe_ip(row.get('attacker_ip')) if _valid_ip(row.get('attacker_ip', '')) else (_extract_ip(msg) or '0.0.0.0')
    target_ip = _safe_ip(row.get('source_ip') or row.get('host_ip', ''))
    detail = {'event_id': ev_id}
    if event_type in ('auth_failure', 'auth_success'):
        cleaned = msg.replace('#011', ' ')
        for u in _ACCOUNT_NAME_RE.findall(cleaned):
            if u not in ('-', '') and not u.endswith('$'):
                detail['username'] = u
                break
    return _make_event(row, src_ip, target_ip, event_type, mask_bit, source_tag, detail, msg)


def _make_event(row, src_ip, target_ip, event_type, mask_bit, source_tag, detail, msg):
    """Build the standard evidence event dict. Used by all parsers."""
    return {
        'event_id': str(uuid.uuid4()),
        'ts': _parse_ts(row.get('ts') or row.get('timestamp')),
        'src_ip': src_ip,
        'target_ip': target_ip,
        'target_vlan': 0,
        'event_type': event_type,
        'event_detail': json.dumps(detail),
        'evidence_mask_bit': mask_bit,
        'source_program': source_tag,
        'source_log': msg[:4096],
    }


def _parse_sshd(row: dict):
    msg = row.get('message', '')
    for pat, ev_type, bit in SSHD_PATTERNS:
        m = pat.search(msg)
        if m:
            user = m.group(1)
            src_ip = m.group(2)
            if not _valid_ip(src_ip):
                src_ip = _safe_ip(row.get('attacker_ip', ''))
            if src_ip.startswith(_INTERNAL_PREFIXES):
                src_ip = '0.0.0.0'
            target_ip = _safe_ip(row.get('source_ip') or row.get('host_ip', ''))
            return _make_event(row, src_ip, target_ip, ev_type, bit, 'sshd', {'username': user}, msg)
    return None


# ── Watermark ─────────────────────────────────────────────────────────────────

def _get_wm():
    try:
        return int(open(WATERMARK_FILE, 'r', encoding='utf-8').read().strip())
    except Exception:
        return 0


def _set_wm(v: int):
    os.makedirs(os.path.dirname(WATERMARK_FILE), exist_ok=True)
    with open(WATERMARK_FILE, 'w', encoding='utf-8') as f:
        f.write(str(v))


# ── Post-auth attribution (CH writer thread only — no lock needed) ────────────
_POST_AUTH_TYPES = frozenset((
    'suspicious_command', 'process_create', 'service_install',
    'file_download', 'privilege_escalation',
))
_target_attacker = {}


def _parse_service(row: dict):
    """Parse service-specific auth events (Postfix, MySQL, PostgreSQL, etc.)."""
    msg = row.get('message', '')
    for pat, event_type, mask_bit, source_tag in SERVICE_PATTERNS:
        m = pat.search(msg)
        if m:
            groups = m.groupdict()
            src_ip = groups.get('ip', '')
            username = groups.get('user', '')
            if not src_ip or not _valid_ip(src_ip):
                src_ip = _extract_ip(msg) or '0.0.0.0'
            if src_ip.startswith(_INTERNAL_PREFIXES):
                src_ip = '0.0.0.0'
            target_ip = _safe_ip(row.get('source_ip') or row.get('host_ip', ''))
            detail = {'username': username} if username else {}
            return _make_event(row, src_ip, target_ip, event_type, mask_bit, source_tag, detail, msg)
    return None


# ── SQLite (from dfi_log_bridge) ──────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(EVIDENCE_DB, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("""CREATE TABLE IF NOT EXISTS logs (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts          TEXT NOT NULL,
        received_at TEXT NOT NULL,
        source_ip   TEXT NOT NULL,
        vm_name     TEXT NOT NULL DEFAULT '',
        vm_os       TEXT NOT NULL DEFAULT '',
        os_type     TEXT NOT NULL DEFAULT '',
        facility    TEXT DEFAULT '',
        severity    TEXT DEFAULT '',
        program     TEXT DEFAULT '',
        pid         TEXT DEFAULT '',
        message     TEXT NOT NULL DEFAULT '',
        attacker_ip TEXT DEFAULT '',
        raw         TEXT DEFAULT ''
    )""")
    conn.commit()
    return conn


def _flush_sqlite(conn: sqlite3.Connection, batch: list) -> int:
    """Write batch of rows to SQLite, return max rowid after insert."""
    if not batch:
        return 0
    conn.executemany(
        """INSERT INTO logs
           (ts, received_at, source_ip, vm_name, vm_os, os_type,
            facility, severity, program, message, attacker_ip, raw)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        batch,
    )
    conn.commit()
    row = conn.execute('SELECT MAX(rowid) FROM logs').fetchone()
    return row[0] if row and row[0] else 0


# ── Classification (extracted from old main() poll loop) ──────────────────────

def _classify_row(d: dict):
    """Classify a row dict (SQLite column names) → evidence event dict or None."""
    prog = str(d.get('program', '')).lower()
    msg = d.get('message', '')

    ev_id = d.get('event_id')
    if ev_id is None:
        eid_m = EVID_RE.search(msg)
        if eid_m:
            ev_id = eid_m.group(1)
    try:
        ev_id_int = int(ev_id) if ev_id is not None else 0
    except (TypeError, ValueError):
        ev_id_int = 0

    if 'sshd' in prog or 'winssh' in prog:
        return _parse_sshd(d)
    if ev_id_int > 0:
        return _parse_windows(d, ev_id_int)
    if 'sshd' in msg.lower():
        return _parse_sshd(d)
    if 'winlure' in prog:
        return None
    return _parse_service(d)


# ── Bridge parse + classify in one pass ───────────────────────────────────────

def _receive_and_parse(data: bytes):
    """Parse raw UDP datagram → (sqlite_tuple, event_dict | None) or (None, None)."""
    raw = data.decode('utf-8', errors='replace').strip()
    try:
        d = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None, None

    src_ip = d.get('fromhost', '')
    prog   = d.get('programname', '')
    msg    = d.get('msg', '')
    ts     = d.get('timestamp', datetime.now(timezone.utc).isoformat())
    now_s  = datetime.now(timezone.utc).isoformat()
    vm_name, vm_os, os_type = _IP_MAP.get(src_ip, ('', '', ''))

    sqlite_row = (
        ts, now_s, src_ip, vm_name, vm_os, os_type,
        d.get('facility', ''), d.get('severity', ''),
        prog, msg, '', raw,
    )

    row = {
        'ts': ts, 'source_ip': src_ip, 'program': prog,
        'message': msg, 'attacker_ip': '', 'host_ip': src_ip,
    }
    ev = _classify_row(row)
    return sqlite_row, ev


# ── ClickHouse flush ──────────────────────────────────────────────────────────

def _flush_ch(ch, events: list) -> int:
    """Apply post-auth attribution, filter 0.0.0.0 src, INSERT into CH. Return count."""
    out = []
    for ev in events:
        src = ev.get('src_ip', '0.0.0.0')
        tgt = ev.get('target_ip', '0.0.0.0')

        if src != '0.0.0.0' and tgt != '0.0.0.0':
            _target_attacker[tgt] = src

        if src == '0.0.0.0' and ev['event_type'] in _POST_AUTH_TYPES:
            cached = _target_attacker.get(tgt)
            if cached:
                ev['src_ip'] = cached

        if ev['src_ip'] != '0.0.0.0':
            ev['ingested_at'] = datetime.now(tz=timezone.utc)
            out.append(ev)

    if out:
        ch.execute('INSERT INTO dfi.evidence_events_buffer VALUES', out)
    return len(out)


# ── Replay from watermark (startup / reconnect) ──────────────────────────────

def _replay_from_watermark(ch):
    """Re-classify + push any SQLite rows beyond the watermark into CH."""
    wm = _get_wm()
    conn = sqlite3.connect(EVIDENCE_DB, timeout=10)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        'SELECT rowid,* FROM logs WHERE rowid > ? ORDER BY rowid LIMIT 50000', (wm,)
    ).fetchall()
    conn.close()

    if not rows:
        log.info('replay: nothing to replay (watermark=%d)', wm)
        return

    events = []
    max_id = wm
    for r in rows:
        d = dict(r)
        max_id = max(max_id, int(d.get('rowid') or d.get('id') or 0))
        ev = _classify_row(d)
        if ev:
            events.append(ev)

    inserted = _flush_ch(ch, events) if events else 0
    _set_wm(max_id)
    log.info('replay: classified=%d inserted=%d from %d rows, watermark=%d->%d',
             len(events), inserted, len(rows), wm, max_id)


# ── UDP Receiver (main thread) ────────────────────────────────────────────────

def _udp_receiver(ch_queue: queue.Queue):
    """Main thread: receive UDP syslog, write SQLite, enqueue for CH."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.bind((BRIDGE_HOST, BRIDGE_PORT))
    sock.settimeout(SQLITE_FLUSH)
    log.info('udp_receiver listening on %s:%d → %s', BRIDGE_HOST, BRIDGE_PORT, EVIDENCE_DB)

    conn = _get_conn()
    sqlite_batch: list = []
    event_batch: list = []
    last_flush = time.time()
    total = 0

    def _do_flush():
        nonlocal sqlite_batch, event_batch, last_flush, total
        if not sqlite_batch:
            return
        max_rowid = _flush_sqlite(conn, sqlite_batch)
        total += len(sqlite_batch)
        if total % 10000 < len(sqlite_batch):
            log.info('sqlite flushed=%d total=%d', len(sqlite_batch), total)
        if event_batch:
            try:
                ch_queue.put_nowait((event_batch, max_rowid))
            except queue.Full:
                log.warning('ch_queue full, dropping %d events (recoverable via replay)',
                            len(event_batch))
        sqlite_batch = []
        event_batch = []
        last_flush = time.time()

    while True:
        try:
            data, _ = sock.recvfrom(65535)
            sqlite_row, ev = _receive_and_parse(data)
            if sqlite_row is None:
                continue
            sqlite_batch.append(sqlite_row)
            if ev:
                event_batch.append(ev)

            if len(sqlite_batch) >= SQLITE_BATCH or (time.time() - last_flush) >= SQLITE_FLUSH:
                _do_flush()

        except socket.timeout:
            _do_flush()
        except Exception as exc:
            log.error('udp_receiver error: %s', exc)
            try:
                conn = _get_conn()
            except Exception:
                pass


# ── ClickHouse Writer (daemon thread) ─────────────────────────────────────────

def _ch_writer(ch_queue: queue.Queue):
    """Daemon thread: drain queue, batch-insert into ClickHouse."""
    ch = None
    pending: list = []
    pending_wm = 0
    last_flush = time.time()

    while True:
        # ── Connect / reconnect ───────────────────────────────────────────────
        if ch is None:
            try:
                ch = Client(CH_HOST, port=CH_PORT)
                ch.execute('SELECT 1')
                log.info('ch_writer connected to %s:%d', CH_HOST, CH_PORT)
                _replay_from_watermark(ch)
            except Exception as exc:
                log.error('ch_writer connect failed: %s, retrying in 5s', exc)
                ch = None
                time.sleep(5)
                continue

        # ── Drain queue ───────────────────────────────────────────────────────
        try:
            events, wm = ch_queue.get(timeout=CH_FLUSH_SEC)
            pending.extend(events)
            pending_wm = max(pending_wm, wm)
        except queue.Empty:
            pass

        # Drain any extras already queued
        while True:
            try:
                events, wm = ch_queue.get_nowait()
                pending.extend(events)
                pending_wm = max(pending_wm, wm)
            except queue.Empty:
                break

        # ── Flush to CH ───────────────────────────────────────────────────────
        should_flush = (
            len(pending) >= CH_BATCH_SIZE
            or (pending and (time.time() - last_flush) >= CH_FLUSH_SEC)
        )
        if should_flush and pending:
            try:
                inserted = _flush_ch(ch, pending)
                old_wm = _get_wm()
                _set_wm(pending_wm)
                log.info('ch_writer inserted=%d watermark=%d->%d', inserted, old_wm, pending_wm)
                pending = []
                pending_wm = 0
                last_flush = time.time()
            except Exception as exc:
                log.error('ch_writer insert failed: %s, will reconnect', exc)
                ch = None


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    q = queue.Queue(maxsize=10000)
    t = threading.Thread(target=_ch_writer, args=(q,), daemon=True)
    t.start()
    _udp_receiver(q)


if __name__ == '__main__':
    main()
