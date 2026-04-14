"""Dual-mode packet capture thread: pcapy/Npcap (L2) or native raw sockets.

pcapy path (preferred): captures full Ethernet frames including MAC addresses
and VLAN tags.  Requires Npcap driver + pcapy-ng pip package.

Raw-socket path (fallback): uses SIO_RCVALL on a raw IP socket.  No Ethernet
header — src_mac/dst_mac/vlan_id will be empty/0.

Capture mode is controlled by config.pcap.capture_mode:
  "auto"       — try pcapy first, fall back to raw socket
  "npcap"      — pcapy only, fail hard if unavailable
  "raw_socket" — skip pcapy entirely
"""
from __future__ import annotations

import logging
import socket
import struct
import threading
import time
from typing import Any


log = logging.getLogger("winhunt.capture")

# Windows ioctl: receive ALL packets on the interface
SIO_RCVALL = 0x98000001
RCVALL_ON = 1
RCVALL_OFF = 0

# Try importing pcapy-ng at module level
try:
    import pcapy
    HAS_PCAPY = True
except ImportError:
    HAS_PCAPY = False


def _format_mac(raw: bytes) -> str:
    """Format 6 raw bytes as colon-separated MAC address."""
    return ":".join(f"{b:02x}" for b in raw)


class PacketParser:
    """IPv4/TCP/UDP parser with optional Ethernet frame support."""

    @staticmethod
    def parse_ethernet(raw: bytes) -> dict[str, Any] | None:
        """Parse full Ethernet frame (pcapy path).  Returns L2+L3+L4 fields."""
        if len(raw) < 14:
            return None

        dst_mac = _format_mac(raw[0:6])
        src_mac = _format_mac(raw[6:12])
        ethertype = struct.unpack("!H", raw[12:14])[0]
        offset = 14
        vlan_id = 0

        # 802.1Q VLAN tag (ethertype 0x8100)
        if ethertype == 0x8100:
            if len(raw) < 18:
                return None
            tci = struct.unpack("!H", raw[14:16])[0]
            vlan_id = tci & 0x0FFF
            ethertype = struct.unpack("!H", raw[16:18])[0]
            offset = 18

        # Only handle IPv4 (0x0800)
        if ethertype != 0x0800:
            return None

        pkt = PacketParser._parse_ip(raw, offset)
        if pkt is None:
            return None

        pkt["src_mac"] = src_mac
        pkt["dst_mac"] = dst_mac
        pkt["vlan_id"] = vlan_id
        return pkt

    @staticmethod
    def parse(raw: bytes) -> dict[str, Any] | None:
        """Parse raw IP packet (SIO_RCVALL fallback).  No L2 fields."""
        pkt = PacketParser._parse_ip(raw, 0)
        if pkt is not None:
            pkt["src_mac"] = ""
            pkt["dst_mac"] = ""
            pkt["vlan_id"] = 0
        return pkt

    @staticmethod
    def _parse_ip(raw: bytes, offset: int) -> dict[str, Any] | None:
        """Parse IPv4 + TCP/UDP/ICMP starting at *offset* into *raw*."""
        if len(raw) < offset + 20:
            return None

        version = (raw[offset] >> 4) & 0x0F
        if version != 4:
            return None
        ihl = (raw[offset] & 0x0F) * 4
        if ihl < 20 or len(raw) < offset + ihl:
            return None
        total_len = struct.unpack("!H", raw[offset + 2:offset + 4])[0]
        proto = raw[offset + 9]
        src_ip = socket.inet_ntoa(raw[offset + 12:offset + 16])
        dst_ip = socket.inet_ntoa(raw[offset + 16:offset + 20])
        l4 = offset + ihl

        pkt: dict[str, Any] = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": 0,
            "dst_port": 0,
            "proto": int(proto),
            "tcp_flags": 0,
            "tcp_window": 0,
            "pkt_len": int(total_len),
            "payload": b"",
        }

        end = min(len(raw), offset + total_len)

        if proto == 6 and len(raw) >= l4 + 20:  # TCP
            pkt["src_port"], pkt["dst_port"] = struct.unpack("!HH", raw[l4:l4 + 4])
            data_off = ((raw[l4 + 12] >> 4) & 0x0F) * 4
            if data_off < 20:
                return None
            pkt["tcp_flags"] = int(raw[l4 + 13])
            pkt["tcp_window"] = struct.unpack("!H", raw[l4 + 14:l4 + 16])[0]
            payload_start = l4 + data_off
            pkt["payload"] = raw[payload_start:end] if payload_start < end else b""
        elif proto == 17 and len(raw) >= l4 + 8:  # UDP
            pkt["src_port"], pkt["dst_port"] = struct.unpack("!HH", raw[l4:l4 + 4])
            pkt["payload"] = raw[l4 + 8:end] if l4 + 8 < end else b""
        elif proto == 1:  # ICMP
            pkt["payload"] = raw[l4:end] if l4 < end else b""

        return pkt


def _resolve_bind_ip(interface_hint: str) -> str:
    """Resolve an interface name or IP to a bindable IPv4 address."""
    try:
        socket.inet_aton(interface_hint)
        return interface_hint
    except OSError:
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "0.0.0.0"


class CaptureThread(threading.Thread):
    """Background capture thread with pcapy/Npcap + raw-socket fallback."""

    def __init__(self, config, flow_table, stop_event: threading.Event):
        super().__init__(name="dfi-capture", daemon=True)
        self.config = config
        self.flow_table = flow_table
        self.stop_event = stop_event
        self.capture_running = False
        self.capture_mode = ""  # set at runtime: "pcapy" or "raw_socket"
        self.packets_received = 0
        self.packets_dropped = 0
        self.packets_non_ipv4_skipped = 0

    def run(self) -> None:
        if not self.config.pcap.enabled:
            log.info("pcap disabled in config")
            return

        mode = self.config.pcap.capture_mode

        if mode == "auto":
            if HAS_PCAPY:
                self._run_pcapy()
            else:
                log.info("pcapy not available — falling back to raw socket")
                self._run_raw_socket()
        elif mode == "npcap":
            if not HAS_PCAPY:
                log.error("capture_mode=npcap but pcapy-ng is not installed")
                return
            self._run_pcapy()
        elif mode == "raw_socket":
            self._run_raw_socket()
        else:
            log.error("unknown capture_mode=%s", mode)

    # ── pcapy / Npcap path ──────────────────────────────────

    def _find_pcapy_device(self) -> str | None:
        """Find the pcapy device name matching config.pcap.interface."""
        devs = pcapy.findalldevs()
        log.debug("pcapy devices: %s", devs)
        hint = self.config.pcap.interface

        # Exact match
        if hint in devs:
            return hint

        # If hint is an IP, find the device whose address list contains it
        try:
            socket.inet_aton(hint)
            for dev in devs:
                try:
                    addrs = pcapy.open_live(dev, 68, 0, 0)
                    # pcapy doesn't expose per-device address easily;
                    # use socket getaddrinfo as fallback
                except Exception:
                    continue
        except OSError:
            pass

        # Substring match (e.g. "Ethernet" matches NPF device description)
        for dev in devs:
            if hint.lower() in dev.lower():
                return dev

        # Default: first device
        if devs:
            log.warning("interface=%s not found, using first device: %s", hint, devs[0])
            return devs[0]

        return None

    def _run_pcapy(self) -> None:
        snap = self.config.pcap.snap_len or 65535
        dev = self._find_pcapy_device()
        if dev is None:
            log.error("no pcapy capture device found (findalldevs empty)")
            return

        try:
            cap = pcapy.open_live(dev, snap, 1, 100)  # promisc=1, timeout_ms=100
        except Exception as exc:
            log.error("pcapy.open_live(%s) failed: %s", dev, exc)
            return

        bpf = self.config.pcap.bpf_filter
        if bpf:
            try:
                cap.setfilter(bpf)
                log.info("BPF filter set: %s", bpf)
            except Exception as exc:
                log.warning("BPF filter failed (%s), capturing unfiltered: %s", bpf, exc)

        self.capture_running = True
        self.capture_mode = "pcapy"
        log.info("capture started on %s (pcapy/Npcap, snap=%d)", dev, snap)

        try:
            while not self.stop_event.is_set():
                try:
                    header, raw = cap.next()
                except Exception as exc:
                    # pcapy.next() raises on timeout with some drivers
                    if self.stop_event.is_set():
                        break
                    log.debug("pcapy.next error: %s", exc)
                    continue

                if header is None or not raw:
                    continue

                ts_sec, ts_usec = header.getts()
                ts = ts_sec + ts_usec / 1_000_000.0

                pkt = PacketParser.parse_ethernet(raw)
                if pkt is None:
                    self.packets_non_ipv4_skipped += 1
                    continue

                self.packets_received += 1
                self.flow_table.process_packet(pkt, ts)
        finally:
            self.capture_running = False
            log.info("capture stopped (pcapy) — received=%d errors=%d",
                     self.packets_received, self.packets_non_ipv4_skipped)

    # ── Raw-socket path (unchanged from original) ───────────

    def _run_raw_socket(self) -> None:
        bind_ip = self.config.mgmt_nic_ip
        if not bind_ip or bind_ip == "0.0.0.0":
            bind_ip = _resolve_bind_ip(self.config.pcap.interface)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((bind_ip, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(SIO_RCVALL, RCVALL_ON)
        except OSError as exc:
            log.error("raw socket failed on %s: %s", bind_ip, exc)
            return

        sock.settimeout(0.5)
        buf_size = self.config.pcap.snap_len or 65535

        self.capture_running = True
        self.capture_mode = "raw_socket"
        log.info("capture started on %s (raw socket, buf=%d)", bind_ip, buf_size)

        try:
            while not self.stop_event.is_set():
                try:
                    raw = sock.recv(buf_size)
                except socket.timeout:
                    continue
                except OSError as exc:
                    log.debug("recv error: %s", exc)
                    time.sleep(0.01)
                    continue

                if not raw:
                    continue

                ts = time.time()
                pkt = PacketParser.parse(raw)
                if pkt is None:
                    self.packets_non_ipv4_skipped += 1
                    continue

                self.packets_received += 1
                self.flow_table.process_packet(pkt, ts)
        finally:
            try:
                sock.ioctl(SIO_RCVALL, RCVALL_OFF)
            except Exception:
                pass
            sock.close()
            self.capture_running = False
            log.info("capture stopped (raw socket) — received=%d errors=%d",
                     self.packets_received, self.packets_non_ipv4_skipped)
