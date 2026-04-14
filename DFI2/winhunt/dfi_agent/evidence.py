"""Windows Event Log evidence collector per spec Module 3.

Subscribes to Event Log channels, extracts source IPs, normalizes events,
and writes to buffer. Includes LogonId chaining and IIS W3C tailing.

StringInserts index reference (from Microsoft Learn docs):
  4624: 5=TargetUserName, 7=TargetLogonId, 8=LogonType, 18=IpAddress
  4625: 5=TargetUserName, 7=Status, 8=FailureReason, 9=SubStatus, 10=LogonType, 19=IpAddress
  4648: 5=TargetUserName, 8=TargetServerName, 12=IpAddress
  4672: 3=SubjectLogonId
  4688: 3=SubjectLogonId, 5=NewProcessName, 8=CommandLine, 13=ParentProcessName
  4697: 3=SubjectLogonId, 4=ServiceName, 5=ServiceFileName
  4720-4726: 6=SubjectLogonId (Target-first layout)
  4717/4718: 3=SubjectLogonId (Subject-first layout)
  4728/4732/4733/4756: 8=SubjectLogonId
  4768: 9=IpAddress
  4769: 6=IpAddress
  4778: 5=ClientAddress
  5140: 5=IpAddress
  1149: 0=User, 1=Domain, 2=SourceNetworkAddress
"""
from __future__ import annotations

import collections
import glob
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any

from . import evidence_bits as EB

log = logging.getLogger("winhunt.evidence")

# Logon Type -> service mapping per spec
_LOGON_TYPE_MAP = {
    "10": "rdp",
    "3": "smb",
    "2": "console",
}

# IP regex for events that embed IP in message text
_IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
_MSSQL_IP_RE = re.compile(r"\[CLIENT:\s*(\d+\.\d+\.\d+\.\d+)\]")

# NTSTATUS substatus codes for 4625 detail enrichment
_SUBSTATUS_MAP = {
    "0xc0000064": "USER_NOT_FOUND",
    "0xc000006a": "WRONG_PASSWORD",
    "0xc0000234": "ACCOUNT_LOCKED",
    "0xc0000072": "ACCOUNT_DISABLED",
    "0xc000006f": "OUTSIDE_HOURS",
    "0xc0000070": "WRONG_WORKSTATION",
    "0xc0000071": "PASSWORD_EXPIRED",
    "0xc0000193": "ACCOUNT_EXPIRED",
    "0xc0000224": "MUST_CHANGE_PASSWORD",
    "0xc0000022": "ACCESS_DENIED",
}

# Maximum seen-set size per channel (bounded OrderedDict avoids clear() race)
_SEEN_MAX = 5000


class EvidenceCollector(threading.Thread):
    """Evidence collector thread per spec."""

    def __init__(self, config, buffer, stop_event: threading.Event):
        super().__init__(name="dfi-evidence", daemon=True)
        self.config = config
        self.buffer = buffer
        self.stop_event = stop_event
        self.events_processed = 0
        self.ip_extraction_failures = 0
        self._attacker_ips: dict[str, dict] = {}  # {ip: {count, first_seen, last_seen, reasons}}

        # Compile patterns
        self._suspicious_re = [re.compile(p, re.IGNORECASE) for p in config.evidence.suspicious_patterns]
        self._download_re = [re.compile(p, re.IGNORECASE) for p in config.evidence.download_patterns]

        # IIS state
        state_dir = Path(self.config.log_dir)
        state_dir.mkdir(parents=True, exist_ok=True)
        self._iis_offsets: dict[str, int] = {}

    def run(self) -> None:
        if not self.config.evidence.enabled:
            log.info("evidence collection disabled")
            return
        if os.name != "nt":
            log.info("not on Windows -- evidence collector idle")
            self._idle_loop()
            return
        self._windows_event_loop()

    def _idle_loop(self) -> None:
        while not self.stop_event.is_set():
            self.stop_event.wait(30)

    def _windows_event_loop(self) -> None:
        try:
            import win32evtlog  # type: ignore
            import win32evtlogutil  # type: ignore
        except ImportError:
            log.warning("pywin32 not installed -- evidence collector idle")
            self._idle_loop()
            return

        bookmarks: dict[str, Any] = {}

        while not self.stop_event.is_set():
            for channel in self.config.evidence.channels:
                try:
                    self._read_channel(channel, win32evtlog, bookmarks)
                except Exception as exc:
                    log.debug("error reading channel %s: %s", channel, exc)

            self._tail_iis()
            self.stop_event.wait(10)

    def _read_channel(self, channel: str, win32evtlog: Any, bookmarks: dict) -> None:
        """Read recent events from a channel using pull-based reading."""
        try:
            hand = win32evtlog.OpenEventLog(None, channel)
        except Exception:
            return

        try:
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
        except Exception:
            win32evtlog.CloseEventLog(hand)
            return

        # Per-channel dedup using bounded OrderedDict (FIFO eviction)
        seen_key = f"_seen_{channel}"
        if not hasattr(self, seen_key):
            setattr(self, seen_key, collections.OrderedDict())
        seen: collections.OrderedDict = getattr(self, seen_key)

        for ev in (events or [])[:200]:
            rec_num = getattr(ev, "RecordNumber", None)
            if rec_num in seen:
                continue
            seen[rec_num] = True
            while len(seen) > _SEEN_MAX:
                seen.popitem(last=False)

            event_id = int(getattr(ev, "EventID", 0) & 0xFFFF)
            inserts = getattr(ev, "StringInserts", None) or ()
            msg = " ".join(str(s) for s in inserts) if inserts else ""

            self._dispatch_event(channel, event_id, inserts, msg, time.time())

        win32evtlog.CloseEventLog(hand)

    # ────────────────────────────────────────────────────────────────
    #  Dispatch — every event ID from WIN-EVENT-C master list
    # ────────────────────────────────────────────────────────────────

    def _dispatch_event(self, channel: str, event_id: int,
                        inserts: tuple, msg: str, ts: float) -> None:
        source_ip: str | None = None
        service = "system"
        event_type = "windows_event"
        evidence_bits = 0
        detail: dict[str, Any] = {"message": msg[:1000]}

        # ── §4.1  Authentication / Session ──────────────────────────

        if event_id == 4624:
            # Logon success — IpAddress[18], LogonType[8], TargetLogonId[7]
            source_ip = self._extract_field(inserts, 18)
            logon_type = self._extract_field(inserts, 8)
            logon_id = self._extract_field(inserts, 7)
            service = _LOGON_TYPE_MAP.get(str(logon_type), "system")
            event_type = "auth_success"
            evidence_bits = EB.AUTH_SUCCESS
            detail.update({"logon_type": logon_type,
                           "target_user": self._extract_field(inserts, 5)})
            if logon_id and source_ip and source_ip != "-":
                self.buffer.upsert_logon(logon_id, source_ip, service)

        elif event_id == 4625:
            # Logon failure — IpAddress[19], LogonType[10], Status[7], SubStatus[9]
            source_ip = self._extract_field(inserts, 19)
            logon_type = self._extract_field(inserts, 10)
            service = _LOGON_TYPE_MAP.get(str(logon_type), "system")
            event_type = "auth_failure"
            evidence_bits = EB.AUTH_FAILURE
            status = self._extract_field(inserts, 7)
            sub_status = self._extract_field(inserts, 9)
            detail.update({
                "logon_type": logon_type,
                "target_user": self._extract_field(inserts, 5),
                "status": status,
                "sub_status": sub_status,
                "failure_reason": _SUBSTATUS_MAP.get((sub_status or "").lower()),
            })

        elif event_id == 4648:
            # Explicit-credentials logon — IpAddress[12]
            source_ip = self._extract_field(inserts, 12)
            event_type = "auth_success"
            evidence_bits = EB.AUTH_SUCCESS
            detail.update({"target_user": self._extract_field(inserts, 5),
                           "target_server": self._extract_field(inserts, 8)})

        elif event_id == 4672:
            # Special logon (privilege escalation) — SubjectLogonId[3]
            logon_id = self._extract_field(inserts, 3)
            resolved = self.buffer.lookup_logon(logon_id or "")
            if resolved:
                source_ip, service = resolved
            event_type = "priv_escalation"
            evidence_bits = EB.PRIVILEGE_ESCALATION

        elif event_id in (4634, 4647):
            # Logoff / user-initiated logoff — context for session tracking
            logon_id = self._extract_field(inserts, 3)
            resolved = self.buffer.lookup_logon(logon_id or "")
            if resolved:
                source_ip, service = resolved
            event_type = "connection"
            evidence_bits = 0

        elif event_id == 4740:
            # Account locked out
            m = _IP_RE.search(msg)
            if m:
                source_ip = m.group(1)
            event_type = "auth_failure"
            evidence_bits = EB.AUTH_FAILURE
            detail["target_user"] = self._extract_field(inserts, 0)

        elif event_id == 4768:
            # Kerberos TGT request — IpAddress[9]
            source_ip = self._extract_field(inserts, 9)
            event_type = "auth_failure"
            evidence_bits = EB.AUTH_FAILURE

        elif event_id == 4769:
            # Kerberos service ticket request — IpAddress[6]
            source_ip = self._extract_field(inserts, 6)
            event_type = "auth_failure"
            evidence_bits = EB.AUTH_FAILURE

        elif event_id in (4771, 4776, 4777):
            # Kerberos pre-auth / NTLM validation failure
            m = _IP_RE.search(msg)
            if m:
                source_ip = m.group(1)
            event_type = "auth_failure"
            evidence_bits = EB.AUTH_FAILURE

        elif event_id == 4778:
            # RDP session reconnected — ClientAddress[5]
            source_ip = self._extract_field(inserts, 5)
            service = "rdp"
            event_type = "auth_success"
            evidence_bits = EB.AUTH_SUCCESS
            detail["target_user"] = self._extract_field(inserts, 0)

        elif event_id == 4779:
            # Session disconnected — context
            source_ip = self._extract_field(inserts, 5)
            service = "rdp"
            event_type = "connection"
            evidence_bits = 0

        # ── §4.2  RDP / Terminal Services ───────────────────────────

        elif event_id == 1149 and "RemoteConnectionManager" in (channel or ""):
            # NLA authentication succeeded — User[0], Domain[1], IP[2]
            source_ip = self._extract_field(inserts, 2)
            service = "rdp"
            event_type = "auth_success"
            evidence_bits = EB.AUTH_SUCCESS
            detail.update({
                "target_user": self._extract_field(inserts, 0),
                "domain": self._extract_field(inserts, 1),
            })

        elif event_id in (131, 261) and "RdpCoreTS" in (channel or ""):
            # RDP pre-auth connection / listener received connection
            source_ip = self._extract_field(inserts, 0)
            service = "rdp"
            event_type = "connection"
            evidence_bits = 0

        elif event_id in (21, 24, 25) and "LocalSessionManager" in (channel or ""):
            # Terminal Services session events
            m = _IP_RE.search(msg)
            if m:
                source_ip = m.group(1)
            service = "rdp"
            event_type = "session_event"
            evidence_bits = 0

        # ── §4.3  SMB / Share / Network ─────────────────────────────

        elif event_id in (5140, 5145):
            # Share access — IpAddress[5]
            source_ip = self._extract_field(inserts, 5)
            service = "smb"
            event_type = "share_access"
            evidence_bits = 0

        elif event_id == 551:
            # SMB session setup failed
            m = _IP_RE.search(msg)
            if m:
                source_ip = m.group(1)
            service = "smb"
            event_type = "auth_failure"
            evidence_bits = EB.AUTH_FAILURE

        elif event_id == 1006 and "SmbClient" in (channel or ""):
            # SmbClient share denied (distinct from Defender 1006)
            m = _IP_RE.search(msg)
            if m:
                source_ip = m.group(1)
            service = "smb"
            event_type = "share_access"
            evidence_bits = 0

        # ── §4.4  MSSQL / Application Auth ──────────────────────────

        elif event_id in (18456, 18452, 33205):
            # MSSQL login failure
            m = _MSSQL_IP_RE.search(msg)
            if m:
                source_ip = m.group(1)
            service = "mssql"
            event_type = "auth_failure"
            evidence_bits = EB.AUTH_FAILURE

        elif event_id in (18454, 18453):
            # MSSQL login success (accept both per WIN-EVENT-C §8)
            m = _MSSQL_IP_RE.search(msg)
            if m:
                source_ip = m.group(1)
            service = "mssql"
            event_type = "auth_success"
            evidence_bits = EB.AUTH_SUCCESS

        # ── §4.5  Process / Command / Execution ─────────────────────

        elif event_id == 4688:
            # Process creation — SubjectLogonId[3], CommandLine[8]
            logon_id = self._extract_field(inserts, 3)
            cmd_line = self._extract_field(inserts, 8) or msg
            resolved = self.buffer.lookup_logon(logon_id or "")
            if resolved:
                source_ip, service = resolved
            event_type, evidence_bits = self._classify_command(cmd_line)
            detail.update({
                "command_line": cmd_line[:500],
                "process_name": self._extract_field(inserts, 5),
                "parent_process": self._extract_field(inserts, 13),
            })
            # AIO hooks: honeypot detection + shell profiler
            if hasattr(self, '_honeypot_detector') and self._honeypot_detector:
                self._honeypot_detector.check_event(event_id, cmd_line, ts)
            if hasattr(self, '_shell_profiler') and self._shell_profiler and logon_id:
                self._shell_profiler.process_command(logon_id, cmd_line, ts)

        elif event_id == 4689:
            # Process exit — context event
            logon_id = self._extract_field(inserts, 3)
            resolved = self.buffer.lookup_logon(logon_id or "")
            if resolved:
                source_ip, service = resolved
            event_type = "process_create"
            evidence_bits = EB.PROCESS_CREATE
            detail["process_name"] = self._extract_field(inserts, 5)

        elif event_id == 4104 and "PowerShell" in (channel or ""):
            # PowerShell script block — ScriptBlockText[2]
            script = self._extract_field(inserts, 2) or msg
            m = _IP_RE.search(msg)
            if m:
                source_ip = m.group(1)
            event_type, evidence_bits = self._classify_command(script)
            detail["script_block"] = script[:1000]
            # AIO hook: honeypot detection
            if hasattr(self, '_honeypot_detector') and self._honeypot_detector:
                self._honeypot_detector.check_event(event_id, script, ts)

        elif event_id == 4103 and "PowerShell" in (channel or ""):
            # PowerShell module logging — ContextInfo[0], Payload[2]
            payload = self._extract_field(inserts, 2) or msg
            event_type, evidence_bits = self._classify_command(payload)
            detail["payload"] = payload[:1000]

        elif event_id == 53504 and "PowerShell" in (channel or ""):
            # PowerShell remoting IPC listener started
            event_type = "suspicious_cmd"
            evidence_bits = EB.SUSPICIOUS_COMMAND

        # ── §4.6  Service / Task Persistence ────────────────────────

        elif event_id == 4697:
            # Service install — SubjectLogonId[3], ServiceName[4], ServiceFileName[5]
            logon_id = self._extract_field(inserts, 3)
            resolved = self.buffer.lookup_logon(logon_id or "")
            if resolved:
                source_ip, service = resolved
            event_type = "service_install"
            evidence_bits = EB.SERVICE_INSTALL
            detail.update({
                "service_name": self._extract_field(inserts, 4),
                "service_file": self._extract_field(inserts, 5),
            })

        elif event_id == 7045:
            # Service installed (System channel)
            event_type = "service_install"
            evidence_bits = EB.SERVICE_INSTALL
            detail.update({
                "service_name": self._extract_field(inserts, 0),
                "service_file": self._extract_field(inserts, 1),
            })

        elif event_id == 7040:
            # Service start type changed — param1=display, param2=new, param3=old
            event_type = "suspicious_cmd"
            evidence_bits = EB.SUSPICIOUS_COMMAND
            detail.update({
                "service_name": self._extract_field(inserts, 0),
                "new_start_type": self._extract_field(inserts, 1),
                "old_start_type": self._extract_field(inserts, 2),
            })

        elif event_id == 7034:
            # Service terminated unexpectedly — context
            event_type = "connection"
            evidence_bits = 0
            detail["service_name"] = self._extract_field(inserts, 0)

        elif event_id == 4698:
            # Scheduled task created — SubjectLogonId[3]
            logon_id = self._extract_field(inserts, 3)
            resolved = self.buffer.lookup_logon(logon_id or "")
            if resolved:
                source_ip, service = resolved
            event_type = "service_install"
            evidence_bits = EB.SERVICE_INSTALL

        elif event_id == 4700:
            # Scheduled task enabled — SubjectLogonId[3]
            logon_id = self._extract_field(inserts, 3)
            resolved = self.buffer.lookup_logon(logon_id or "")
            if resolved:
                source_ip, service = resolved
            event_type = "service_install"
            evidence_bits = EB.SERVICE_INSTALL

        elif event_id in (4699, 4702):
            # Scheduled task deleted / updated — SubjectLogonId[3]
            logon_id = self._extract_field(inserts, 3)
            resolved = self.buffer.lookup_logon(logon_id or "")
            if resolved:
                source_ip, service = resolved
            event_type = "suspicious_cmd"
            evidence_bits = EB.SUSPICIOUS_COMMAND

        # ── §4.7  Account / Group / Privilege ───────────────────────

        elif event_id in (4728, 4732, 4756):
            # Member added to security group — SubjectLogonId[8]
            logon_id = self._extract_field(inserts, 8)
            resolved = self.buffer.lookup_logon(logon_id or "")
            if resolved:
                source_ip, service = resolved
            event_type = "priv_escalation"
            evidence_bits = EB.PRIVILEGE_ESCALATION
            detail["group_name"] = self._extract_field(inserts, 2)

        elif event_id == 4733:
            # Member removed from local group — SubjectLogonId[8]
            logon_id = self._extract_field(inserts, 8)
            resolved = self.buffer.lookup_logon(logon_id or "")
            if resolved:
                source_ip, service = resolved
            event_type = "suspicious_cmd"
            evidence_bits = EB.SUSPICIOUS_COMMAND
            detail["group_name"] = self._extract_field(inserts, 2)

        elif event_id in (4720, 4722, 4723, 4724, 4725):
            # Account created/enabled/password change/reset/disabled
            # Target-first layout: SubjectLogonId[6]
            logon_id = self._extract_field(inserts, 6)
            resolved = self.buffer.lookup_logon(logon_id or "")
            if resolved:
                source_ip, service = resolved
            event_type = "priv_escalation"
            evidence_bits = EB.PRIVILEGE_ESCALATION
            detail["target_user"] = self._extract_field(inserts, 0)

        elif event_id == 4726:
            # User account deleted — SubjectLogonId[6]
            logon_id = self._extract_field(inserts, 6)
            resolved = self.buffer.lookup_logon(logon_id or "")
            if resolved:
                source_ip, service = resolved
            event_type = "suspicious_cmd"
            evidence_bits = EB.SUSPICIOUS_COMMAND
            detail["target_user"] = self._extract_field(inserts, 0)

        elif event_id in (4717, 4718):
            # System security access granted/removed — SubjectLogonId[3]
            logon_id = self._extract_field(inserts, 3)
            resolved = self.buffer.lookup_logon(logon_id or "")
            if resolved:
                source_ip, service = resolved
            event_type = "priv_escalation"
            evidence_bits = EB.PRIVILEGE_ESCALATION

        elif event_id == 4670:
            # Permissions changed on object
            logon_id = self._extract_field(inserts, 3)
            resolved = self.buffer.lookup_logon(logon_id or "")
            if resolved:
                source_ip, service = resolved
            event_type = "priv_escalation"
            evidence_bits = EB.PRIVILEGE_ESCALATION

        elif event_id == 4798:
            # Local group membership enumerated — context/recon
            # SubjectLogonId[3] (Subject-first: Sid[0],User[1],Domain[2],LogonId[3])
            logon_id = self._extract_field(inserts, 3)
            resolved = self.buffer.lookup_logon(logon_id or "")
            if resolved:
                source_ip, service = resolved
            event_type = "connection"
            evidence_bits = 0

        # ── §4.8  Object Access / Tamper / Evasion ──────────────────

        elif event_id in (4656, 4663):
            # Object handle requested / access attempt — SubjectLogonId[3]
            logon_id = self._extract_field(inserts, 3)
            resolved = self.buffer.lookup_logon(logon_id or "")
            if resolved:
                source_ip, service = resolved
            event_type = "suspicious_cmd"
            evidence_bits = EB.SUSPICIOUS_COMMAND

        elif event_id == 4657:
            # Registry value modified — SubjectLogonId[3]
            logon_id = self._extract_field(inserts, 3)
            resolved = self.buffer.lookup_logon(logon_id or "")
            if resolved:
                source_ip, service = resolved
            event_type = "suspicious_cmd"
            evidence_bits = EB.SUSPICIOUS_COMMAND

        elif event_id == 4660:
            # Object deleted — SubjectLogonId[3]
            logon_id = self._extract_field(inserts, 3)
            resolved = self.buffer.lookup_logon(logon_id or "")
            if resolved:
                source_ip, service = resolved
            event_type = "suspicious_cmd"
            evidence_bits = EB.SUSPICIOUS_COMMAND

        elif event_id == 1102:
            # Audit log cleared — critical tamper
            event_type = "suspicious_cmd"
            evidence_bits = EB.SUSPICIOUS_COMMAND

        elif event_id == 4719:
            # Audit policy changed
            logon_id = self._extract_field(inserts, 3)
            resolved = self.buffer.lookup_logon(logon_id or "")
            if resolved:
                source_ip, service = resolved
            event_type = "suspicious_cmd"
            evidence_bits = EB.SUSPICIOUS_COMMAND

        elif event_id == 4907:
            # Object audit settings changed
            logon_id = self._extract_field(inserts, 3)
            resolved = self.buffer.lookup_logon(logon_id or "")
            if resolved:
                source_ip, service = resolved
            event_type = "suspicious_cmd"
            evidence_bits = EB.SUSPICIOUS_COMMAND

        # ── §4.9  Firewall / Network Control ────────────────────────

        elif event_id in (4946, 4947, 4948, 4950):
            # Firewall rule added/modified/deleted/setting changed
            event_type = "suspicious_cmd"
            evidence_bits = EB.SUSPICIOUS_COMMAND

        elif event_id in (5025, 5030):
            # Firewall service stopped / failed start
            event_type = "suspicious_cmd"
            evidence_bits = EB.SUSPICIOUS_COMMAND

        # ── §4.10  Windows Defender ─────────────────────────────────

        elif event_id in (1006, 1007, 1008, 1116, 1117) and "Defender" in (channel or ""):
            # Malware detected / action taken / action failed / threat
            event_type = "suspicious_cmd"
            evidence_bits = EB.SUSPICIOUS_COMMAND

        elif event_id in (5001, 5004, 5007, 5010, 5012, 5013) and "Defender" in (channel or ""):
            # RTP disabled / config changed / scanning disabled / tamper-protection
            event_type = "suspicious_cmd"
            evidence_bits = EB.SUSPICIOUS_COMMAND

        # ── §4.10b  DNS Client (AIO expansion) ──────────────────────

        elif event_id == 3006 and "DNS-Client" in (channel or ""):
            # DNS query event — dispatched to DnsMonitor if available
            if hasattr(self, '_dns_monitor') and self._dns_monitor:
                self._dns_monitor.process_dns_event(event_id, inserts, msg, ts)
            return  # dns_monitor handles its own inserts

        # ── §4.11  Sysmon (Phase C — channel-gated) ────────────────

        elif "Sysmon" in (channel or ""):
            self._dispatch_sysmon(event_id, inserts, msg, ts, channel, detail)
            return  # sysmon handler does its own insert

        else:
            return  # Unhandled event ID

        # Filter out local/empty IPs
        if source_ip in (None, "", "-", "::1", "127.0.0.1"):
            source_ip = None
            self.ip_extraction_failures += 1
        elif source_ip and not source_ip.startswith(("10.", "172.16.", "192.168.", "127.")):
            # Track external attacker IPs on the fly
            now = time.time()
            if source_ip not in self._attacker_ips:
                self._attacker_ips[source_ip] = {
                    "count": 0, "first_seen": now, "last_seen": now,
                    "reasons": set(), "top_port": 0,
                }
            entry = self._attacker_ips[source_ip]
            entry["count"] += 1
            entry["last_seen"] = now
            entry["reasons"].add(event_type or "unknown")

        self.buffer.insert_event(
            ts=ts,
            vm_id=self.config.vm_id,
            source_ip=source_ip,
            source_port=0,
            service=service,
            event_type=event_type,
            evidence_bits=evidence_bits,
            raw_event_id=event_id,
            raw_channel=channel,
            detail=detail,
        )
        self.events_processed += 1

    # ────────────────────────────────────────────────────────────────
    #  Sysmon dispatch (channel-gated to avoid event ID collisions)
    # ────────────────────────────────────────────────────────────────

    def _dispatch_sysmon(self, event_id: int, inserts: tuple,
                         msg: str, ts: float, channel: str,
                         detail: dict[str, Any]) -> None:
        source_ip: str | None = None
        service = "system"
        event_type = "windows_event"
        evidence_bits = 0

        if event_id == 1:
            # Process creation — Image[4], CommandLine[10], ParentImage[20], User[12]
            cmd = self._extract_field(inserts, 10) or msg
            event_type, evidence_bits = self._classify_command(cmd)
            detail.update({
                "command_line": cmd[:500],
                "process_name": self._extract_field(inserts, 4),
                "parent_process": self._extract_field(inserts, 20),
            })

        elif event_id == 3:
            # Network connection — SourceIp[9], DestinationIp[14], DestinationPort[15]
            source_ip = self._extract_field(inserts, 9)
            event_type = "connection"
            evidence_bits = 0
            detail.update({
                "dst_ip": self._extract_field(inserts, 14),
                "dst_port": self._extract_field(inserts, 15),
            })

        elif event_id == 8:
            # CreateRemoteThread — SourceImage[4], TargetImage[7]
            event_type = "suspicious_cmd"
            evidence_bits = EB.SUSPICIOUS_COMMAND
            detail.update({
                "source_image": self._extract_field(inserts, 4),
                "target_image": self._extract_field(inserts, 7),
            })

        elif event_id == 10:
            # ProcessAccess — SourceImage[4], TargetImage[7] (LSASS detection)
            target = self._extract_field(inserts, 7) or ""
            event_type = "suspicious_cmd"
            evidence_bits = EB.SUSPICIOUS_COMMAND
            detail.update({
                "source_image": self._extract_field(inserts, 4),
                "target_image": target,
            })

        elif event_id == 11:
            # FileCreate — TargetFilename[5], Image[4]
            fname = self._extract_field(inserts, 5) or ""
            event_type = "file_download"
            evidence_bits = EB.FILE_DOWNLOAD
            detail.update({
                "target_filename": fname[:300],
                "image": self._extract_field(inserts, 4),
            })

        elif event_id in (19, 20, 21):
            # WMI event filter/consumer/binding — persistence
            event_type = "service_install"
            evidence_bits = EB.SERVICE_INSTALL

        elif event_id in (2, 6, 7, 9, 12, 13, 15, 17, 18, 22,
                          23, 25, 26, 27, 28, 29):
            # Bulk tamper/evasion signals
            event_type = "suspicious_cmd"
            evidence_bits = EB.SUSPICIOUS_COMMAND

        elif event_id == 5:
            # Process terminated — context
            event_type = "process_create"
            evidence_bits = EB.PROCESS_CREATE

        else:
            return

        if source_ip in (None, "", "-", "::1", "127.0.0.1"):
            source_ip = None
            self.ip_extraction_failures += 1

        self.buffer.insert_event(
            ts=ts,
            vm_id=self.config.vm_id,
            source_ip=source_ip,
            source_port=0,
            service=service,
            event_type=event_type,
            evidence_bits=evidence_bits,
            raw_event_id=event_id,
            raw_channel=channel,
            detail=detail,
        )
        self.events_processed += 1

    # ────────────────────────────────────────────────────────────────
    #  Helpers
    # ────────────────────────────────────────────────────────────────

    def _classify_command(self, cmd: str) -> tuple[str, int]:
        """Classify command as suspicious_cmd/file_download/process_create.

        Also detects TOOL_DEPLOYMENT (download + execute combos) and
        EVASION_ATTEMPT (audit clearing, Defender tampering).
        """
        if not cmd:
            return ("process_create", EB.PROCESS_CREATE)

        cmd_lower = cmd.lower()

        # Evasion: audit log clearing, Defender disabling
        evasion_patterns = [
            "wevtutil cl", "clear-eventlog", "remove-eventlog",
            "set-mppreference -disablerealtimemonitoring",
            "set-mppreference -disableioavprotection",
            "stop-service windefend", "sc stop windefend",
            "auditpol /set /subcategory", "wevtutil sl",
        ]
        for pat in evasion_patterns:
            if pat in cmd_lower:
                return ("suspicious_cmd", EB.EVASION_ATTEMPT)

        # Tool deployment: download + execute combos
        has_download = any(pat.search(cmd) for pat in self._download_re)
        has_execute = bool(re.search(
            r"(start-process|invoke-expression|iex|\.exe\s|& |cmd\s*/c)",
            cmd, re.IGNORECASE,
        ))
        if has_download and has_execute:
            return ("file_download", EB.FILE_DOWNLOAD | EB.TOOL_DEPLOYMENT)

        for pat in self._download_re:
            if pat.search(cmd):
                return ("file_download", EB.FILE_DOWNLOAD | EB.SUSPICIOUS_COMMAND)

        for pat in self._suspicious_re:
            if pat.search(cmd):
                return ("suspicious_cmd", EB.SUSPICIOUS_COMMAND)

        return ("process_create", EB.PROCESS_CREATE)

    @staticmethod
    def _extract_field(inserts: tuple | list | None, idx: int) -> str | None:
        if not inserts or idx >= len(inserts):
            return None
        val = inserts[idx]
        return str(val) if val is not None else None

    # ────────────────────────────────────────────────────────────────
    #  IIS W3C log tailing
    # ────────────────────────────────────────────────────────────────

    def _tail_iis(self) -> None:
        """Tail IIS W3C logs per spec."""
        log_dir = self.config.evidence.iis_log_dir
        paths = sorted(glob.glob(os.path.join(log_dir, "*.log")))
        if not paths:
            return

        path = paths[-1]
        try:
            size = os.path.getsize(path)
        except OSError:
            return

        offset = self._iis_offsets.get(path, 0)
        if offset > size:
            offset = 0

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(offset)
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    self._parse_iis_line(line)
                self._iis_offsets[path] = f.tell()
        except OSError:
            return

    def _parse_iis_line(self, line: str) -> None:
        """Parse IIS W3C log line: parts[2]=IP, parts[4]=method, parts[5]=URI, parts[7]=status."""
        parts = line.split()
        if len(parts) < 8:
            return

        client_ip = parts[2] if len(parts) > 2 else None
        method = parts[4] if len(parts) > 4 else ""
        uri = parts[5] if len(parts) > 5 else ""
        try:
            status = int(parts[7]) if len(parts) > 7 else 0
        except ValueError:
            status = 0

        event_type = "connection"
        evidence_bits = 0
        if status == 401:
            event_type = "auth_failure"
            evidence_bits = EB.AUTH_FAILURE
        elif status == 200:
            event_type = "auth_success"
            evidence_bits = EB.AUTH_SUCCESS

        for pat in self._suspicious_re:
            if pat.search(uri):
                event_type = "suspicious_cmd"
                evidence_bits = EB.SUSPICIOUS_COMMAND
                break

        self.buffer.insert_event(
            ts=time.time(),
            vm_id=self.config.vm_id,
            source_ip=client_ip,
            source_port=0,
            service="iis",
            event_type=event_type,
            evidence_bits=evidence_bits,
            raw_event_id=None,
            raw_channel="IIS",
            detail={"method": method, "uri": uri, "status": status},
        )
        self.events_processed += 1
