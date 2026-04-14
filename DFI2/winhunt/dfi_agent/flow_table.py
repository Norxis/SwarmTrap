"""Flow table — core of the agent per spec Module 2.

Maintains one FlowState per bidirectional TCP/UDP flow. Packets enter via
process_packet(), completed flows emit via _emit_flow() which computes all
XGB features, CNN tokens, and fingerprints.
"""
from __future__ import annotations

import hashlib
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from . import features, fingerprints, tokenizer
from .buffer import AgentBuffer, _ts_to_iso
from .config import AgentConfig
from .fingerprints import FingerprintState

log = logging.getLogger("winhunt.flow_table")

# Port → app_proto code map per spec
_PORT_PROTO: dict[int, int] = {
    22: 1, 80: 2, 443: 3, 53: 4, 25: 5, 21: 6, 23: 7,
    3389: 8, 5900: 9, 445: 10, 3306: 11, 1433: 12, 5432: 13,
    6379: 14, 27017: 15, 5985: 2, 5986: 2,
}


@dataclass
class EventPacket:
    seq_idx: int
    ts: float
    direction: int          # 1=fwd, -1=rev
    payload_len: int
    pkt_len: int
    tcp_flags: int
    tcp_window: int
    payload_bytes: bytes    # first snap_len bytes


@dataclass
class FlowState:
    # ── Identity ──
    flow_id: str
    session_key: str
    src_ip: str             # attacker (external)
    dst_ip: str             # honeypot (local)
    src_port: int
    dst_port: int
    ip_proto: int           # 6=TCP, 17=UDP, 1=ICMP
    app_proto: int          # DPI or port heuristic
    first_ts: float
    last_ts: float
    state: str = "ACTIVE"   # ACTIVE | FIN_WAIT | CLOSING

    # ── Volume ──
    pkts_fwd: int = 0
    pkts_rev: int = 0
    bytes_fwd: int = 0
    bytes_rev: int = 0

    # ── Timing ──
    syn_ts: float | None = None
    syn_ack_ts: float | None = None
    first_fwd_ts: float | None = None
    first_rev_ts: float | None = None
    prev_fwd_ts: float | None = None
    fwd_iats: list[float] = field(default_factory=list)  # seconds, max 512

    # ── TCP ──
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_only_count: int = 0
    first_rst_pkt_num: int = 0
    total_pkts: int = 0
    syn_to_data_count: int = 0
    _seen_data: bool = False
    current_psh_run: int = 0
    max_psh_run: int = 0
    window_size_init: int = 0
    retransmit_set: set = field(default_factory=set)

    # ── Event Packets (CNN) ──
    event_packets: list[EventPacket] = field(default_factory=list)

    # ── Payload Analysis ──
    first_fwd_payload: bytes | None = None
    fwd_entropy_sum: float = 0.0
    fwd_entropy_count: int = 0
    rev_entropy_sum: float = 0.0
    rev_entropy_count: int = 0
    fwd_high_entropy: int = 0
    fwd_payload_sizes: list[int] = field(default_factory=list)  # max 512
    rev_payload_sizes: list[int] = field(default_factory=list)  # max 512
    n_payload_pkts: int = 0

    # ── Size Histogram ──
    hist_tiny: int = 0       # 1-63
    hist_small: int = 0      # 64-255
    hist_medium: int = 0     # 256-1023
    hist_large: int = 0      # 1024-1499
    hist_full: int = 0       # >= 1500

    # ── L2 (pcapy/Npcap only) ──
    src_mac: str = ""     # attacker MAC (first fwd packet)
    dst_mac: str = ""     # honeypot MAC (first fwd packet)
    vlan_id: int = 0      # 802.1Q VLAN ID (0 = untagged)

    # ── Fingerprints ──
    fp: FingerprintState = field(default_factory=FingerprintState)

    # ── Drain Timer ──
    drain_until: float | None = None


class FlowTable:
    def __init__(self, config: AgentConfig, buffer: AgentBuffer, pipeline=None):
        self.config = config
        self.buffer = buffer
        self.pipeline = pipeline  # InferencePipeline (Phase 5), set after init
        self._lock = threading.Lock()
        self._flows: dict[str, FlowState] = {}
        self.flows_emitted = 0

    @staticmethod
    def _session_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: int) -> str:
        endpoints = sorted([(src_ip, src_port), (dst_ip, dst_port)])
        raw = f"{endpoints[0][0]}:{endpoints[0][1]}-{endpoints[1][0]}:{endpoints[1][1]}/{proto}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def _direction(self, src_ip: str, dst_ip: str) -> int:
        """Returns 1=fwd (attacker→honeypot), -1=rev, 0=discard."""
        local = self.config.local_ips
        if dst_ip in local:
            return 1   # fwd: destination is us
        if src_ip in local:
            return -1  # rev: source is us
        return 0       # neither — discard

    @staticmethod
    def _detect_app_proto(payload: bytes, dst_port: int, src_port: int) -> int:
        """DPI first, port-heuristic fallback per spec."""
        if payload:
            # TLS ClientHello
            if len(payload) > 5 and payload[0] == 0x16 and payload[5] == 0x01:
                return 3  # tls
            # HTTP methods
            for method in (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH "):
                if payload.startswith(method):
                    return 2  # http
        return _PORT_PROTO.get(dst_port, _PORT_PROTO.get(src_port, 0))

    def process_packet(self, pkt: dict[str, Any], ts: float) -> None:
        src_ip = pkt["src_ip"]
        dst_ip = pkt["dst_ip"]
        src_port = int(pkt["src_port"])
        dst_port = int(pkt["dst_port"])
        proto = int(pkt["proto"])
        flags = int(pkt.get("tcp_flags", 0))
        payload = (pkt.get("payload") or b"")[:self.config.pcap.snap_len]
        payload_len = len(payload)
        pkt_len = int(pkt.get("pkt_len", 0))
        tcp_window = int(pkt.get("tcp_window", 0))

        direction = self._direction(src_ip, dst_ip)
        if direction == 0:
            return

        session_key = self._session_key(src_ip, src_port, dst_ip, dst_port, proto)
        emit_flow: FlowState | None = None
        evict_flow: FlowState | None = None

        with self._lock:
            flow = self._flows.get(session_key)

            if flow is None:
                # Evict oldest if at capacity
                if len(self._flows) >= self.config.pcap.max_active_flows:
                    evict_key = min(self._flows, key=lambda k: self._flows[k].last_ts)
                    evict_flow = self._flows.pop(evict_key)

                app_proto = self._detect_app_proto(payload, dst_port, src_port)

                # Normalize: src_ip is always the attacker (external)
                if direction == 1:
                    attacker_ip, honeypot_ip = src_ip, dst_ip
                    attacker_port, honeypot_port = src_port, dst_port
                else:
                    attacker_ip, honeypot_ip = dst_ip, src_ip
                    attacker_port, honeypot_port = dst_port, src_port

                flow = FlowState(
                    flow_id=str(uuid.uuid4()),
                    session_key=session_key,
                    src_ip=attacker_ip,
                    dst_ip=honeypot_ip,
                    src_port=attacker_port,
                    dst_port=honeypot_port,
                    ip_proto=proto,
                    app_proto=app_proto,
                    first_ts=ts,
                    last_ts=ts,
                )
                self._flows[session_key] = flow

            # ── Update common ──
            flow.last_ts = ts
            flow.total_pkts += 1

            # ── L2 fields (from first fwd packet) ──
            if direction == 1 and not flow.src_mac:
                flow.src_mac = pkt.get("src_mac", "")
                flow.dst_mac = pkt.get("dst_mac", "")
                flow.vlan_id = int(pkt.get("vlan_id", 0))

            # ── Volume ──
            if direction == 1:
                flow.pkts_fwd += 1
                flow.bytes_fwd += pkt_len
                if flow.first_fwd_ts is None:
                    flow.first_fwd_ts = ts
            else:
                flow.pkts_rev += 1
                flow.bytes_rev += pkt_len
                if flow.first_rev_ts is None:
                    flow.first_rev_ts = ts

            # ── TCP Flags ──
            is_syn = bool(flags & 0x02)
            is_fin = bool(flags & 0x01)
            is_rst = bool(flags & 0x04)
            is_psh = bool(flags & 0x08)
            is_ack = bool(flags & 0x10)

            if is_syn:
                flow.syn_count += 1
                if direction == 1 and flow.syn_ts is None:
                    flow.syn_ts = ts
                    if tcp_window:
                        flow.window_size_init = tcp_window
                if direction == -1 and flow.syn_ack_ts is None and is_ack:
                    flow.syn_ack_ts = ts

            if is_fin:
                flow.fin_count += 1
                if flow.state == "ACTIVE":
                    flow.state = "FIN_WAIT"
                    flow.drain_until = ts + self.config.pcap.flow_drain_fin_s

            if is_rst:
                flow.rst_count += 1
                if flow.first_rst_pkt_num == 0:
                    flow.first_rst_pkt_num = flow.total_pkts
                flow.state = "CLOSING"
                flow.drain_until = ts + self.config.pcap.flow_drain_rst_s

            if is_psh:
                flow.psh_count += 1
                flow.current_psh_run += 1
                flow.max_psh_run = max(flow.max_psh_run, flow.current_psh_run)
            else:
                flow.current_psh_run = 0

            if is_ack and not (is_syn or is_fin or is_rst or is_psh) and payload_len == 0:
                flow.ack_only_count += 1

            # syn_to_data tracking
            if not flow._seen_data and payload_len > 0:
                flow._seen_data = True
                flow.syn_to_data_count = flow.total_pkts - 1

            # ── Forward IAT ──
            if direction == 1:
                if flow.prev_fwd_ts is not None and len(flow.fwd_iats) < 512:
                    flow.fwd_iats.append(ts - flow.prev_fwd_ts)
                flow.prev_fwd_ts = ts

            # ── Event Packet Collection (CNN) ──
            is_event = payload_len > 0 or is_syn or is_fin or is_rst
            if is_event and len(flow.event_packets) < self.config.pcap.max_event_pkts:
                flow.event_packets.append(EventPacket(
                    seq_idx=len(flow.event_packets),
                    ts=ts,
                    direction=direction,
                    payload_len=payload_len,
                    pkt_len=pkt_len,
                    tcp_flags=flags,
                    tcp_window=tcp_window,
                    payload_bytes=payload,
                ))

            # ── Payload Analysis ──
            if payload_len > 0:
                flow.n_payload_pkts += 1
                entropy = features.shannon_entropy(payload)

                if direction == 1:
                    if flow.first_fwd_payload is None:
                        flow.first_fwd_payload = payload
                    flow.fwd_entropy_sum += entropy
                    flow.fwd_entropy_count += 1
                    if entropy >= 7.0:
                        flow.fwd_high_entropy += 1
                    if len(flow.fwd_payload_sizes) < 512:
                        flow.fwd_payload_sizes.append(payload_len)
                else:
                    flow.rev_entropy_sum += entropy
                    flow.rev_entropy_count += 1
                    if len(flow.rev_payload_sizes) < 512:
                        flow.rev_payload_sizes.append(payload_len)

                # Size histogram (per spec: payload size bins)
                if 1 <= payload_len <= 63:
                    flow.hist_tiny += 1
                elif 64 <= payload_len <= 255:
                    flow.hist_small += 1
                elif 256 <= payload_len <= 1023:
                    flow.hist_medium += 1
                elif 1024 <= payload_len <= 1499:
                    flow.hist_large += 1
                elif payload_len >= 1500:
                    flow.hist_full += 1

                # Retransmit estimation
                flow.retransmit_set.add((payload_len, direction))

            # ── Fingerprint Extraction ──
            if payload_len > 0:
                fingerprints.update_fingerprint(
                    fp=flow.fp,
                    dst_port=flow.dst_port,
                    src_port=flow.src_port,
                    payload=payload,
                    direction=direction,
                )

            # ── Inference Pipeline Hook ──
            if self.pipeline and flow.total_pkts in (5, 20, 50):
                try:
                    self.pipeline.on_flow_update(flow, flow.total_pkts)
                except Exception as exc:
                    log.debug("inference pipeline error at pkt %d: %s", flow.total_pkts, exc)

            # ── Force-Emit ──
            if flow.total_pkts >= self.config.pcap.max_flow_pkts:
                emit_flow = self._flows.pop(session_key, None)

        # Outside lock: emit evicted and force-emitted flows
        if evict_flow:
            self._emit_flow(evict_flow)
        if emit_flow:
            self._emit_flow(emit_flow)

    def sweep(self) -> None:
        """Periodic timeout check — called every 1s by sweep thread."""
        now = time.time()
        to_emit: list[FlowState] = []
        with self._lock:
            stale_keys: list[str] = []
            for key, flow in self._flows.items():
                if flow.drain_until is not None and now >= flow.drain_until:
                    stale_keys.append(key)
                elif now - flow.last_ts >= self.config.pcap.flow_timeout_s:
                    stale_keys.append(key)
            for key in stale_keys:
                f = self._flows.pop(key, None)
                if f:
                    to_emit.append(f)
        for flow in to_emit:
            self._emit_flow(flow)

    def emit_all(self) -> None:
        """Flush all active flows on shutdown."""
        with self._lock:
            flows = list(self._flows.values())
            self._flows.clear()
        for flow in flows:
            self._emit_flow(flow)

    @property
    def active_flow_count(self) -> int:
        return len(self._flows)

    def _emit_flow(self, flow: FlowState) -> None:
        """Compute features, tokens, fingerprints and write to buffer."""
        # Build flow state dict for feature extraction
        flow_data: dict[str, Any] = {
            "flow_id": flow.flow_id,
            "session_key": flow.session_key,
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "ip_proto": flow.ip_proto,
            "app_proto": flow.app_proto,
            "first_ts": flow.first_ts,
            "last_ts": flow.last_ts,
            "pkts_fwd": flow.pkts_fwd,
            "pkts_rev": flow.pkts_rev,
            "bytes_fwd": flow.bytes_fwd,
            "bytes_rev": flow.bytes_rev,
            "syn_ts": flow.syn_ts,
            "syn_ack_ts": flow.syn_ack_ts,
            "first_fwd_ts": flow.first_fwd_ts,
            "first_rev_ts": flow.first_rev_ts,
            "fwd_iats": flow.fwd_iats,
            "total_pkts": flow.total_pkts,
            "n_payload_pkts": flow.n_payload_pkts,
            "syn_count": flow.syn_count,
            "fin_count": flow.fin_count,
            "rst_count": flow.rst_count,
            "psh_count": flow.psh_count,
            "ack_only_count": flow.ack_only_count,
            "first_rst_pkt_num": flow.first_rst_pkt_num,
            "syn_to_data_count": flow.syn_to_data_count,
            "max_psh_run": flow.max_psh_run,
            "window_size_init": flow.window_size_init,
            "retransmit_set_size": len(flow.retransmit_set),
            "n_events": len(flow.event_packets),
            "fwd_payload_sizes": flow.fwd_payload_sizes,
            "rev_payload_sizes": flow.rev_payload_sizes,
            "hist_tiny": flow.hist_tiny,
            "hist_small": flow.hist_small,
            "hist_medium": flow.hist_medium,
            "hist_large": flow.hist_large,
            "hist_full": flow.hist_full,
            "first_fwd_payload": flow.first_fwd_payload,
            "fwd_entropy_sum": flow.fwd_entropy_sum,
            "fwd_entropy_count": flow.fwd_entropy_count,
            "rev_entropy_sum": flow.rev_entropy_sum,
            "rev_entropy_count": flow.rev_entropy_count,
            "fwd_high_entropy": flow.fwd_high_entropy,
        }

        # Compute XGB features
        xgb = features.compute_xgb_features(flow_data)

        # Build buffer row (identity + features + metadata)
        row: dict[str, Any] = {
            "flow_id": flow.flow_id,
            "session_key": flow.session_key,
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "ip_proto": flow.ip_proto,
            "app_proto": flow.app_proto,
            "first_ts": _ts_to_iso(flow.first_ts),
            "last_ts": _ts_to_iso(flow.last_ts),
            "src_mac": flow.src_mac,
            "dst_mac": flow.dst_mac,
            "vlan_id": flow.vlan_id,
            "capture_source": self.config.pcap.capture_source,
        }
        row.update(xgb)
        self.buffer.insert_flow(row)

        # Compute CNN token rows
        event_dicts = [
            {
                "seq_idx": e.seq_idx,
                "ts": e.ts,
                "direction": e.direction,
                "payload_len": e.payload_len,
                "pkt_len": e.pkt_len,
                "tcp_flags": e.tcp_flags,
                "tcp_window": e.tcp_window,
                "payload_bytes": e.payload_bytes,
            }
            for e in flow.event_packets
        ]
        token_rows = tokenizer.compute_token_rows(
            event_dicts, flow.flow_id, xgb.get("rtt_ms"),
            max_len=self.config.pcap.max_event_pkts,
        )
        # Convert ts to ISO for storage
        for tr in token_rows:
            tr["ts"] = _ts_to_iso(tr["ts"])
        self.buffer.insert_packets(token_rows)

        # Fingerprints
        fp_dict = flow.fp.to_dict()
        fp_dict["flow_id"] = flow.flow_id
        self.buffer.insert_fingerprint(fp_dict)

        # Source stats
        self.buffer.upsert_source_stats(
            flow.src_ip, flow.dst_port, flow.app_proto,
            flow.dst_ip, xgb["pps"], flow.first_ts,
        )

        # Inference pipeline: final prediction at flow end
        if self.pipeline:
            try:
                self.pipeline.on_flow_end(flow)
            except Exception as exc:
                log.debug("inference pipeline error at flow end: %s", exc)

        self.flows_emitted += 1
