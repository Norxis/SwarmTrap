# Phase 6: Evidence Pipeline

> **Executor:** Codex
> **Reviewer:** Claude Code
> **Status:** Not started
> **Depends on:** Phase 1 (ClickHouse running), Phase 2 (Hunter on AIO for feedback socket)

## Objective

Get evidence events flowing into ClickHouse from both sources: AIO (Winlure feedback socket) and PV1 (syslog → evidence.db). These events are the ground truth that drives labeling in Phase 7.

## Hosts

| Host | IP | SSH Port | User | Password | Role |
|------|----|----------|------|----------|------|
| PV1 | 192.168.0.100 | 22 | root@pam | CHANGE_ME | Master — evidence.db syslog ingest |
| AIO | 172.16.3.113 | 2222 | colo8gent | CHANGE_ME | Satellite — Winlure feedback socket |

## Reference Files

| File | What to read |
|------|-------------|
| `~/ai-shared/DFI2/DFI2_Dataset_DB_Spec.md` | `evidence_events` table schema (lines 353-382) |
| `~/ai-shared/DFI2/DFI2_XGB_v1_Spec.md` | Labels from evidence.db (lines 17-51): label criteria, evidence_mask bits |
| `~/ai-shared/DFI2/DFI2_Behavioral_Architecture_Spec.md` | Evidence event types (lines 325-356) |
| `~/DFI/Proxmox-V7/Hunter-v7/hunter.py` | push_ip_scores() pattern (evidence.db writes) |
| `~/DFI/Proxmox-V7/Hunter-v7/bridge.py` | Attacker IP logger (lines 1135-1195) |
| `~/DFI2/hunter/writer.py` | DFIWriter.insert_evidence() |

## Output Files

```
~/DFI2/
├── hunter/
│   └── evidence.py          # NEW: AIO Winlure feedback socket → CH evidence_events
├── labeler/
│   ├── __init__.py
│   └── evidence_ingest.py   # NEW: PV1 evidence.db → CH evidence_events
```

---

## Step 1: evidence.py — AIO Winlure Feedback Reader

This runs as part of Hunter on AIO. It reads NDJSON messages from Winlure's feedback socket and writes them to local ClickHouse.

```python
"""evidence.py — Read Winlure feedback socket, write to CH evidence_events.

Winlure emits NDJSON messages on /run/dfi/feedback.sock for each attacker interaction:
    {"src_ip": "1.2.3.4", "dst_port": 22, "proto": "ssh", "username": "root",
     "event_type": "auth_failure", "timestamp": 1708800000.123, "detail": "..."}
"""

import json
import logging
import os
import socket
import threading
import time
import uuid

log = logging.getLogger(__name__)

FEEDBACK_SOCKET = os.environ.get('FEEDBACK_SOCKET', '/run/dfi/feedback.sock')
TARGET_IP = os.environ.get('WINLURE_IP', '216.126.0.206')
TARGET_VLAN = int(os.environ.get('WINLURE_VLAN', '0'))

# evidence_mask bits (from XGB spec)
EVIDENCE_BITS = {
    'auth_failure': 0,
    'auth_success': 1,
    'process_create': 2,
    'service_install': 3,
    'suspicious_command': 4,
    'file_download': 5,
    'privilege_escalation': 6,
    'lateral_movement': 7,
}


class EvidenceReader:
    """Reads Winlure feedback socket and batches evidence events for DFIWriter."""

    def __init__(self, writer, socket_path=FEEDBACK_SOCKET):
        self._writer = writer
        self._socket_path = socket_path
        self._running = False
        self._thread = None

    def start(self):
        """Start background thread reading from feedback socket."""
        self._running = True
        self._thread = threading.Thread(target=self._read_loop, daemon=True)
        self._thread.start()
        log.info(f"EvidenceReader started, socket={self._socket_path}")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _read_loop(self):
        while self._running:
            try:
                self._connect_and_read()
            except Exception as e:
                log.warning(f"Feedback socket error: {e}, retrying in 5s")
                time.sleep(5)

    def _connect_and_read(self):
        """Connect to UNIX socket and read NDJSON lines."""
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(10)

        try:
            sock.connect(self._socket_path)
            log.info(f"Connected to feedback socket: {self._socket_path}")
            buf = b''
            batch = []

            while self._running:
                try:
                    data = sock.recv(65536)
                    if not data:
                        break  # Socket closed
                    buf += data

                    # Process complete NDJSON lines
                    while b'\n' in buf:
                        line, buf = buf.split(b'\n', 1)
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            msg = json.loads(line)
                            event = self._parse_event(msg)
                            if event:
                                batch.append(event)
                        except json.JSONDecodeError as e:
                            log.debug(f"Invalid JSON from feedback: {e}")

                    # Flush batch every 50 events or every second
                    if batch and (len(batch) >= 50):
                        self._writer.insert_evidence(batch)
                        log.info(f"Flushed {len(batch)} evidence events from Winlure")
                        batch = []

                except socket.timeout:
                    # Flush on timeout (no data for 10s)
                    if batch:
                        self._writer.insert_evidence(batch)
                        log.info(f"Flushed {len(batch)} evidence events (timeout)")
                        batch = []
        finally:
            sock.close()

    def _parse_event(self, msg: dict) -> dict:
        """Parse NDJSON message to evidence_events row dict."""
        event_type = msg.get('event_type', 'unknown')
        return {
            'event_id': str(uuid.uuid4()),
            'ts': msg.get('timestamp', time.time()),
            'src_ip': msg.get('src_ip', '0.0.0.0'),
            'target_ip': TARGET_IP,
            'target_vlan': TARGET_VLAN,
            'event_type': event_type,
            'event_detail': json.dumps({
                k: v for k, v in msg.items()
                if k not in ('src_ip', 'timestamp', 'event_type')
            }),
            'evidence_mask_bit': EVIDENCE_BITS.get(event_type, 0),
            'source_program': msg.get('proto', 'winlure'),
            'source_log': json.dumps(msg),
        }
```

### Integration with Hunter (AIO)

In `hunter.py` main setup, after creating DFIWriter:

```python
from .evidence import EvidenceReader

# Only on AIO (where Winlure runs)
if os.path.exists(FEEDBACK_SOCKET):
    evidence_reader = EvidenceReader(writer)
    evidence_reader.start()
```

---

## Step 2: evidence_ingest.py — PV1 evidence.db Tail Daemon

This runs on PV1 as a standalone daemon. It tails the existing `evidence.db` SQLite database (populated by the syslog pipeline) and writes new entries to ClickHouse.

```python
#!/usr/bin/env python3
"""evidence_ingest.py — Tail PV1 evidence.db → ClickHouse evidence_events.

Runs as a daemon on PV1. Polls evidence.db for new rows every 10 seconds.
Parses Windows EventIDs and Linux sshd patterns into structured evidence events.
"""

import json
import logging
import os
import re
import sqlite3
import sys
import time
import uuid

from clickhouse_driver import Client

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(name)s %(levelname)s %(message)s'
)
log = logging.getLogger('evidence_ingest')

# Configuration
EVIDENCE_DB = os.environ.get('EVIDENCE_DB', '/opt/dfi_edge/evidence.db')
CH_HOST = os.environ.get('CH_HOST', 'localhost')
CH_PORT = int(os.environ.get('CH_PORT', '9000'))
POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', '10'))
WATERMARK_FILE = os.environ.get('WATERMARK_FILE', '/opt/dfi2/evidence_watermark.txt')

# evidence_mask bits
EVIDENCE_BITS = {
    'auth_failure': 0,
    'auth_success': 1,
    'process_create': 2,
    'service_install': 3,
    'suspicious_command': 4,
    'file_download': 5,
    'privilege_escalation': 6,
    'lateral_movement': 7,
}


# --- Windows Event ID Parsing ---

WINDOWS_EVENT_MAP = {
    # Authentication
    4625: ('auth_failure', 0),       # Failed logon
    4624: ('auth_success', 1),       # Successful logon
    4648: ('auth_success', 1),       # Logon using explicit credentials
    4672: ('privilege_escalation', 6), # Special privileges assigned

    # Process/Service
    4688: ('process_create', 2),     # New process created
    7045: ('service_install', 3),    # Service installed
    4697: ('service_install', 3),    # Service installed (Security log)

    # Suspicious activity
    1: ('process_create', 2),        # Sysmon process create
    3: ('process_create', 2),        # Sysmon network connection
    11: ('file_download', 5),        # Sysmon file create
}

# Suspicious command patterns (for Windows EventID 4688 / Sysmon 1)
SUSPICIOUS_COMMANDS = re.compile(
    r'(powershell|cmd\.exe.*(/c|/k)|certutil|bitsadmin|mshta|wscript|cscript|'
    r'rundll32|regsvr32|wget|curl|nc\.exe|ncat|netcat|python|perl|'
    r'whoami|net\s+(user|localgroup|group)|systeminfo|tasklist|ipconfig\s*/all|'
    r'mimikatz|lazagne|procdump|psexec)',
    re.IGNORECASE
)


def parse_windows_event(row: dict) -> dict:
    """Parse a Windows event log entry from evidence.db."""
    event_id = row.get('event_id', 0)
    source_ip = extract_ip(row.get('message', ''))
    target_ip = row.get('host_ip', '0.0.0.0')
    message = row.get('message', '')

    event_type, mask_bit = WINDOWS_EVENT_MAP.get(event_id, ('unknown', 0))

    # Check for suspicious commands in process creation events
    if event_id in (4688, 1) and SUSPICIOUS_COMMANDS.search(message):
        event_type = 'suspicious_command'
        mask_bit = 4

    # Extract username for auth events
    detail = {}
    if event_id in (4625, 4624, 4648):
        username = extract_username(message)
        if username:
            detail['username'] = username
    detail['event_id'] = event_id

    return {
        'event_id': str(uuid.uuid4()),
        'ts': row.get('timestamp', time.time()),
        'src_ip': source_ip or '0.0.0.0',
        'target_ip': target_ip,
        'target_vlan': 0,
        'event_type': event_type,
        'event_detail': json.dumps(detail),
        'evidence_mask_bit': mask_bit,
        'source_program': f'windows_{event_id}',
        'source_log': message[:4096],  # truncate long messages
    }


# --- Linux sshd Parsing ---

SSHD_PATTERNS = [
    (re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+)'),
     'auth_failure', 0),
    (re.compile(r'Accepted (?:password|publickey) for (\S+) from (\S+)'),
     'auth_success', 1),
    (re.compile(r'Invalid user (\S+) from (\S+)'),
     'auth_failure', 0),
    (re.compile(r'Connection closed by authenticating user (\S+) (\S+)'),
     'auth_failure', 0),
    (re.compile(r'Disconnected from authenticating user (\S+) (\S+)'),
     'auth_failure', 0),
]


def parse_sshd_event(row: dict) -> dict:
    """Parse an sshd log entry from evidence.db."""
    message = row.get('message', '')
    target_ip = row.get('host_ip', '0.0.0.0')

    for pattern, event_type, mask_bit in SSHD_PATTERNS:
        m = pattern.search(message)
        if m:
            groups = m.groups()
            username = groups[0] if len(groups) >= 1 else None
            src_ip = groups[1] if len(groups) >= 2 else extract_ip(message)

            detail = {}
            if username:
                detail['username'] = username
            detail['program'] = 'sshd'

            return {
                'event_id': str(uuid.uuid4()),
                'ts': row.get('timestamp', time.time()),
                'src_ip': src_ip or '0.0.0.0',
                'target_ip': target_ip,
                'target_vlan': 0,
                'event_type': event_type,
                'event_detail': json.dumps(detail),
                'evidence_mask_bit': mask_bit,
                'source_program': 'sshd',
                'source_log': message[:4096],
            }

    return None


# --- Utility ---

IP_RE = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')


def extract_ip(text: str) -> str:
    """Extract first IP address from text."""
    m = IP_RE.search(text)
    return m.group(1) if m else None


def extract_username(text: str) -> str:
    """Extract username from Windows auth event message."""
    # Common patterns: "Account Name: admin" or "User: admin"
    for pattern in [r'Account Name:\s*(\S+)', r'User(?:name)?:\s*(\S+)',
                    r'TargetUserName["\s:]+(\S+)']:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


# --- Main Loop ---

def get_watermark() -> int:
    """Read last-processed rowid from watermark file."""
    try:
        with open(WATERMARK_FILE, 'r') as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return 0


def set_watermark(rowid: int):
    """Write last-processed rowid to watermark file."""
    os.makedirs(os.path.dirname(WATERMARK_FILE), exist_ok=True)
    with open(WATERMARK_FILE, 'w') as f:
        f.write(str(rowid))


def main():
    ch = Client(CH_HOST, port=CH_PORT)
    log.info(f"evidence_ingest started: db={EVIDENCE_DB}, ch={CH_HOST}:{CH_PORT}")

    while True:
        try:
            watermark = get_watermark()

            conn = sqlite3.connect(EVIDENCE_DB, timeout=10)
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT rowid, * FROM log_events WHERE rowid > ? ORDER BY rowid LIMIT 10000",
                (watermark,)
            )
            rows = cursor.fetchall()
            conn.close()

            if not rows:
                time.sleep(POLL_INTERVAL)
                continue

            events = []
            max_rowid = watermark

            for row in rows:
                row_dict = dict(row)
                max_rowid = max(max_rowid, row_dict.get('rowid', 0))

                # Route by source
                program = row_dict.get('program', '').lower()
                event_id = row_dict.get('event_id', 0)

                if isinstance(event_id, int) and event_id > 0:
                    # Windows event
                    ev = parse_windows_event(row_dict)
                    if ev:
                        events.append(ev)
                elif 'sshd' in program:
                    ev = parse_sshd_event(row_dict)
                    if ev:
                        events.append(ev)
                # Add more parsers here: mysqld, httpd, etc.

            if events:
                ch.execute(
                    "INSERT INTO dfi.evidence_events_buffer VALUES",
                    events
                )
                log.info(f"Inserted {len(events)} evidence events (rowid {watermark}→{max_rowid})")

            set_watermark(max_rowid)

        except Exception as e:
            log.error(f"Error in evidence_ingest loop: {e}", exc_info=True)
            time.sleep(POLL_INTERVAL)

        time.sleep(POLL_INTERVAL)


if __name__ == '__main__':
    main()
```

---

## Step 3: Systemd Unit for evidence_ingest (PV1)

Deploy as a daemon on PV1:

```ini
# /etc/systemd/system/dfi-evidence-ingest.service
[Unit]
Description=DFI2 Evidence Ingest — evidence.db → ClickHouse
After=network-online.target clickhouse-server.service
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/dfi2/labeler/evidence_ingest.py
Environment=EVIDENCE_DB=/opt/dfi_edge/evidence.db
Environment=CH_HOST=localhost
Environment=CH_PORT=9000
Environment=WATERMARK_FILE=/opt/dfi2/evidence_watermark.txt
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now dfi-evidence-ingest
```

---

## Step 4: DFIWriter.insert_evidence() Verification

Confirm the DFIWriter (from Phase 2) correctly handles evidence event insertion:

```python
# In writer.py:
def insert_evidence(self, events: list):
    """Batch insert evidence events to CH evidence_events_buffer."""
    with self._lock:
        self._evidence_buf.extend(events)
```

The flusher thread writes `_evidence_buf` to `dfi.evidence_events_buffer`. Verify the column mapping matches the table schema:

```
event_id, ts, src_ip, target_ip, target_vlan, event_type, event_detail,
evidence_mask_bit, source_program, source_log
```

---

## Verification

1. **AIO evidence (Winlure feedback):**
   ```bash
   # On AIO — check if feedback socket exists
   ls -la /run/dfi/feedback.sock

   # Check evidence events in AIO ClickHouse
   ssh -p 2222 colo8gent@172.16.3.113 \
       "clickhouse-client --query 'SELECT count() FROM dfi.evidence_events'"

   # Sample events
   ssh -p 2222 colo8gent@172.16.3.113 \
       "clickhouse-client --query 'SELECT ts, src_ip, event_type, source_program FROM dfi.evidence_events ORDER BY ts DESC LIMIT 10'"
   ```

2. **PV1 evidence (evidence.db ingest):**
   ```bash
   # Check service running
   systemctl status dfi-evidence-ingest

   # Check evidence events in PV1 ClickHouse
   clickhouse-client --query "SELECT count() FROM dfi.evidence_events"

   # Sample by type
   clickhouse-client --query "
       SELECT event_type, count() as cnt
       FROM dfi.evidence_events
       GROUP BY event_type
       ORDER BY cnt DESC
   "
   ```

3. **Evidence from both sources on PV1 (after pull):**
   ```bash
   # Run pull to get AIO evidence
   python3 /opt/dfi2/sync/pull_aio.py

   # Check combined evidence
   clickhouse-client --query "
       SELECT source_program, count() as cnt
       FROM dfi.evidence_events
       GROUP BY source_program
       ORDER BY cnt DESC
   "
   # Should show both 'winlure' (from AIO) and 'sshd'/'windows_*' (from PV1)
   ```

4. **SSH brute-force test:**
   ```bash
   # Trigger multiple failed SSH logins to a honeypot
   # Then check evidence
   clickhouse-client --query "
       SELECT ts, src_ip, event_type, event_detail
       FROM dfi.evidence_events
       WHERE event_type = 'auth_failure'
       ORDER BY ts DESC
       LIMIT 10
   "
   ```

5. **Watermark tracking:**
   ```bash
   cat /opt/dfi2/evidence_watermark.txt
   # Should show a rowid > 0 and increasing
   ```

---

## Acceptance Criteria

- [ ] AIO: EvidenceReader connects to Winlure feedback socket
- [ ] AIO: Credential events from Winlure appear in `dfi.evidence_events`
- [ ] PV1: evidence_ingest daemon running and tailing evidence.db
- [ ] PV1: Windows EventID parsing works (4625, 4624, 4688, etc.)
- [ ] PV1: Linux sshd parsing works (Failed/Accepted password patterns)
- [ ] PV1: Suspicious command detection works (powershell, certutil, etc.)
- [ ] evidence_mask_bit correctly set per event type
- [ ] Watermark file tracks progress — no duplicate ingestion on restart
- [ ] PV1 pull picks up AIO evidence_events
- [ ] Combined evidence on PV1 shows events from both sources
- [ ] No crashes on malformed log entries (graceful skip + log warning)

## Important Notes

- **Feedback socket path:** Winlure creates `/run/dfi/feedback.sock` when `dfi-winlure` service starts. If the socket doesn't exist, `EvidenceReader` retries every 5 seconds. This is normal on first boot before Winlure starts.
- **evidence.db schema may vary.** The `evidence_ingest.py` uses `log_events` as the table name and `rowid` for watermarking. Verify the actual table name in the existing evidence.db on PV1. Adjust if needed.
- **Timestamps:** Winlure provides epoch timestamps with millisecond precision. evidence.db may use epoch seconds or ISO format — handle both in the parser.
- **IP extraction:** Windows event logs embed attacker IPs in different fields depending on the EventID. The regex extraction is a fallback — improve with EventID-specific parsing for better accuracy.
- **Rate:** Evidence events are low-volume compared to flows (hundreds per minute vs hundreds of thousands). No performance concern here.
