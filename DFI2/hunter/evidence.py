#!/usr/bin/env python3
import json
import logging
import os
import socket
import threading
import time
import uuid
from datetime import datetime, timezone


log = logging.getLogger('hunter.evidence')

FEEDBACK_SOCKET = os.environ.get('FEEDBACK_SOCKET', '/run/dfi/feedback.sock')
TARGET_IP = os.environ.get('WINLURE_IP', '216.126.0.206')
TARGET_VLAN = int(os.environ.get('WINLURE_VLAN', '0'))

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
    def __init__(self, writer, socket_path=FEEDBACK_SOCKET):
        self._writer = writer
        self._socket_path = socket_path
        self._running = False
        self._thread = None

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._read_loop, daemon=True, name='evidence-reader')
        self._thread.start()
        log.info('EvidenceReader started socket=%s', self._socket_path)

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _read_loop(self):
        while self._running:
            try:
                self._connect_and_read()
            except Exception as exc:
                log.warning('feedback_socket_error err=%s', exc)
                time.sleep(5)

    def _connect_and_read(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(10)
        try:
            sock.connect(self._socket_path)
            buf = b''
            batch = []
            while self._running:
                try:
                    data = sock.recv(65536)
                    if not data:
                        break
                    buf += data
                    while b'\n' in buf:
                        line, buf = buf.split(b'\n', 1)
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            msg = json.loads(line)
                            row = self._parse_event(msg)
                            if row:
                                batch.append(row)
                        except json.JSONDecodeError:
                            continue

                    if len(batch) >= 50:
                        self._writer.insert_evidence(batch)
                        batch = []
                except socket.timeout:
                    if batch:
                        self._writer.insert_evidence(batch)
                        batch = []
            if batch:
                self._writer.insert_evidence(batch)
        finally:
            sock.close()

    def _parse_event(self, msg: dict) -> dict:
        ts = msg.get('timestamp', time.time())
        try:
            ts = float(ts)
        except Exception:
            ts = time.time()

        event_type = msg.get('event_type', 'unknown')
        ts_dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return {
            'event_id': str(uuid.uuid4()),
            'ts': ts_dt,
            'src_ip': msg.get('src_ip', '0.0.0.0'),
            'target_ip': msg.get('target_ip', TARGET_IP),
            'target_vlan': int(msg.get('target_vlan', TARGET_VLAN)),
            'event_type': event_type,
            'event_detail': json.dumps({k: v for k, v in msg.items() if k not in ('src_ip', 'timestamp', 'event_type')}),
            'evidence_mask_bit': EVIDENCE_BITS.get(event_type, 0),
            'source_program': msg.get('proto', 'winlure'),
            'source_log': json.dumps(msg),
        }
