# Labeler

The labeler correlates honeypot evidence with network flows to produce labeled training data for ML models. It is the bridge between "something suspicious happened on a honeypot" and "this network flow is malicious."

## How It Works

1. Honeypot VMs (Linux and Windows) forward their syslog to a central UDP listener.
2. The evidence ingest service parses those logs, classifies events (auth failures, credential captures, suspicious commands, etc.), and writes them to ClickHouse.
3. The labeler queries unlabeled network flows, finds evidence events from the same source IP within a time window, and assigns a label: RECON (0), KNOCK (1), BRUTEFORCE (2), EXPLOIT (3), or COMPROMISE (4).

Labels are written to the `dfi.labels` table and also inlined into `dfi.flows` for JOIN-free ML export.

## Key Files

### `evidence_ingest.py`

The primary evidence pipeline. Runs as a long-lived service with two threads:

- **UDP receiver (main thread):** Listens on UDP 1514 for JSON-formatted rsyslog messages from honeypot VMs. Parses each message, classifies it using event maps, and writes to both SQLite (crash safety) and a queue for ClickHouse.
- **ClickHouse writer (daemon thread):** Drains the queue and batch-inserts into `dfi.evidence_events_buffer`. On startup, replays any un-ingested SQLite rows via a watermark file.

Supports a wide range of log sources:
- **Windows events:** 60+ Event IDs mapped to evidence types (4625=auth_failure, 4688=process_create, 7045=service_install, etc.), with channel gating for Sysmon and Defender events to avoid ID collisions.
- **SSH (sshd):** Failed/accepted password, invalid user, disconnected patterns.
- **Service-specific:** Postfix SASL, Dovecot, Apache, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, Asterisk SIP, OpenLDAP, vsftpd, Fail2ban, and trap service logs (FTP, Telnet, SMTP, POP3, IMAP, SIP).
- **Post-auth attribution:** When a post-exploitation event (suspicious command, service install, etc.) lacks an attacker IP, the writer attributes it to the last known attacker who authenticated to that target host.

A suspicious-command regex (`SUSP`) upgrades process-creation events to `suspicious_command` when the command line matches known attack tools (mimikatz, psexec, certutil, encoded PowerShell, lolbins, etc.).

### `labeler.py`

Long-running service that labels network flows. Runs on a configurable interval (default: 30 seconds).

- **`correlate_and_label()`:** Finds flows in `dfi.flows` that have no entry in `dfi.labels`, queries `dfi.evidence_events` for matching source IPs within a correlation window (default: 120 seconds), and assigns labels using `_assign()`.
- **`relabel_recent()`:** Re-examines flows previously labeled RECON or KNOCK when new evidence arrives for the same IP, upgrading labels if warranted.
- **IP reputation:** If no evidence falls within the per-flow correlation window, the labeler checks aggregate IP reputation across the full lookback period and upgrades accordingly.
- **Confidence scoring:** RECON=0.5 (no host evidence), BRUTEFORCE 3-4 failures=0.85, BRUTEFORCE 5+ failures=1.0, EXPLOIT/COMPROMISE=1.0 (any honeypot interaction is confirmed hostile).

### `winlure_evidence_ingest.py`

Reads from a local Winlure SQLite `credentials.db` and writes evidence events to ClickHouse. Handles two tables:

- **`credentials`:** Captured usernames/passwords across SSH, RDP, MSSQL, SMB, LDAP, HTTP, WinRM. A captured password upgrades the event from `auth_failure` to `credential_capture`.
- **`connections`:** Raw TCP connections to auth-related ports (22, 445, 1433, 3389, 5985, 389, 80). On a honeypot, any connection to these ports is treated as an attack attempt.

Uses watermark files to track processing position. Filters out internal IPs.

### `dfi_log_bridge.py`

A simpler predecessor to `evidence_ingest.py`. Listens on UDP 1514 for rsyslog JSON, writes to SQLite only (no ClickHouse). Maintained for reference. The merged `evidence_ingest.py` replaces this in production.

## Pipeline Position

```
Honeypot VMs (rsyslog) --> evidence_ingest.py --> dfi.evidence_events
                                                         |
Network flows (capture) --> dfi.flows                    |
                               |                         |
                               +--- labeler.py ----------+
                               |
                               v
                          dfi.labels (+ dfi.flows inline update)
                               |
                               v
                     ML training data export
```

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `CH_HOST` | `localhost` | ClickHouse host |
| `CH_PORT` | `9000` | ClickHouse native port |
| `LABEL_INTERVAL` | `30` | Seconds between labeling runs |
| `CORRELATION_WINDOW` | `120` | Seconds around flow timestamp to search for evidence |
| `LABEL_BATCH` | `50000` | Max flows to label per cycle |
| `LABEL_LOOKBACK` | `4` | Hours to look back for unlabeled flows |
| `EVIDENCE_DB` | `/mnt/dfi-data/evidence/evidence.db` | SQLite crash-safety database |
| `BRIDGE_HOST` | `127.0.0.1` | UDP listener bind address |
| `BRIDGE_PORT` | `1514` | UDP listener port |
| `WATERMARK_FILE` | `/opt/dfi2/evidence_watermark.txt` | Tracks last processed SQLite row |

## Dependencies

- `clickhouse-driver` -- ClickHouse native protocol client
- Python standard library (`socket`, `sqlite3`, `json`, `re`, `threading`, `queue`, `uuid`)
