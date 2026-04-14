"""
afpacket.py — AF_PACKET TPACKET_V3 + PACKET_FANOUT capture engine
==================================================================
Designed for 10G+ line-rate capture with near-zero kernel↔userspace copies.

Architecture — zero IPC on all data paths
------------------------------------------
  PACKET_FANOUT_HASH distributes flows across N worker processes by 5-tuple hash.
  Each worker owns its own TPACKET_V3 mmap ring, its own SessionTracker, and its
  own SQLite connection.  Workers call ingest() directly — no packet queue.
  Completed sessions are written to SQLite directly by each worker's flush thread
  — no session queue.  The only multiprocessing.Queue is stats_queue, which
  carries ~4 tiny dicts per 30 seconds.

Why eliminating queues matters
-------------------------------
  Any multiprocessing.Queue adds: pickle() on the producer, OS pipe write,
  OS pipe read, unpickle() on the consumer.  At 14.8 Mpps (10G / 64B frames)
  that is 14.8M pickle round-trips per second regardless of maxsize.
  maxsize only controls when put() blocks — it converts OOM into stall/drop,
  it does not remove the per-item overhead.

  New design: zero serialisation on the hot path.  Session writes go directly
  to SQLite (WAL mode, 4 writers, ~500 sessions/batch/10s — negligible contention).

Why TPACKET_V3 over V1/V2
--------------------------
  V3 batches hundreds of packets into one block before waking userspace.
  One poll() syscall retires an entire block → 10,000–100,000× fewer syscalls.

Ring buffer defaults for 10G
------------------------------
  block_size  = 2 MB  (power-of-2, >= page size)
  block_count = 128   (256 MB per worker ring)
  block_timeout_ms = 100
  num_workers = 4     (match to NIC RX queues)

Public API
----------
  from afpacket import FanoutCapture, ParsedPacket

  # worker_factory is called ONCE per worker process to set up local state.
  # Must be a top-level (picklable) function.
  # Opens its own SQLite connection, starts local flush thread,
  # returns tracker.ingest as the per-packet callback.

  def my_factory(worker_idx, stop_event):
      tracker = MyTracker()          # local, no shared state
      tracker.start_flush_thread()   # writes directly to SQLite
      return tracker.ingest

  cap = FanoutCapture(iface="ens20", num_workers=4, worker_factory=my_factory)
  cap.start()   # blocks until KeyboardInterrupt
  cap.stop()
"""

import os
import mmap
import struct
import socket
import ctypes
import ctypes.util
import threading
import multiprocessing
import logging
import time
import signal
from pathlib import Path
from dataclasses import dataclass
from typing import Callable, List, Optional


log = logging.getLogger("hunter.afpacket")

BPF_VLAN_AWARE = os.getenv("BPF_VLAN_AWARE", "0") == "1"

# ── Linux socket constants ────────────────────────────────────────────────
AF_PACKET          = 17
SOCK_RAW           = 3
ETH_P_ALL          = 0x0003
ETH_P_IP           = 0x0800
SOL_PACKET         = 263

PACKET_RX_RING     = 5
PACKET_VERSION     = 10
PACKET_FANOUT      = 18
PACKET_STATISTICS  = 6

TPACKET_V3         = 2

PACKET_FANOUT_HASH = 0   # same 5-tuple → same worker (session-affine)
PACKET_FANOUT_LB   = 1   # round-robin
PACKET_FANOUT_CPU  = 2   # by arrival CPU
PACKET_FANOUT_FLAG_ROLLOVER = 0x1000  # overflow to next worker if socket is full

TP_STATUS_KERNEL   = 0x00000000
TP_STATUS_USER     = 0x00000001
TP_STATUS_LOSING   = 0x00000004   # kernel ring was full; packets dropped

ETH_HLEN     = 14
IPPROTO_TCP  = 6
IPPROTO_UDP  = 17
IPPROTO_ICMP = 1

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


# ── CPU affinity helpers ──────────────────────────────────────────────────

def _parse_cpu_list(s: str) -> List[int]:
    """
    Parse a CPU list string in Linux range notation into a sorted list of ints.
    Examples:  "2"  →  [2]
               "0,2,4"  →  [0, 2, 4]
               "0-3"  →  [0, 1, 2, 3]
               "0-3,8-11"  →  [0, 1, 2, 3, 8, 9, 10, 11]
    """
    cpus: List[int] = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            cpus.extend(range(int(lo), int(hi) + 1))
        else:
            cpus.append(int(part))
    return sorted(set(cpus))


def _get_online_cpus() -> List[int]:
    """
    Return the list of currently online CPU cores.

    Primary source: /sys/devices/system/cpu/online
      Kernel-authoritative; reflects hot-plug state and isolated cores.
      Absent on some VMs and containers — fall through to sched_getaffinity.

    Fallback: os.sched_getaffinity(0)
      Returns the parent process's allowed set. Under cgroups / cpuset this
      may be a subset of online CPUs, which is exactly what we want.
    """
    try:
        raw = Path("/sys/devices/system/cpu/online").read_text().strip()
        return _parse_cpu_list(raw)
    except Exception:
        pass
    try:
        return sorted(os.sched_getaffinity(0))
    except Exception:
        pass
    # Last resort: assume a single CPU (pinning will be no-op effectively)
    return [0]


def _pin_to_cpu(cpu: int, wlog) -> bool:
    """
    Pin the calling process to a single CPU core.
    Must be called from inside the worker process (pid 0 = self).
    Returns True on success, False if the OS rejects the affinity (e.g. in a
    restricted container) — caller logs a warning and continues unpinned.
    """
    try:
        os.sched_setaffinity(0, {cpu})
        wlog.info(f"Pinned to CPU {cpu}")
        return True
    except OSError as e:
        wlog.warning(f"CPU pinning to core {cpu} failed ({e}) — running unpinned")
        return False


# ── Kernel ABI structures ─────────────────────────────────────────────────

class TpacketReq3(ctypes.Structure):
    _fields_ = [
        ("tp_block_size",       ctypes.c_uint),
        ("tp_block_nr",         ctypes.c_uint),
        ("tp_frame_size",       ctypes.c_uint),
        ("tp_frame_nr",         ctypes.c_uint),
        ("tp_retire_blk_tov",   ctypes.c_uint),
        ("tp_sizeof_priv",      ctypes.c_uint),
        ("tp_feature_req_word", ctypes.c_uint),
    ]


class SockFprog(ctypes.Structure):
    class SockFilter(ctypes.Structure):
        _fields_ = [
            ("code", ctypes.c_uint16),
            ("jt",   ctypes.c_uint8),
            ("jf",   ctypes.c_uint8),
            ("k",    ctypes.c_uint32),
        ]
    _fields_ = [
        ("len",    ctypes.c_uint16),
        ("filter", ctypes.POINTER(SockFilter)),
    ]


# ── BPF filter builders ───────────────────────────────────────────────────
#
# Filters run in the kernel packet path BEFORE data hits the TPACKET_V3 ring.
# Rejected packets never consume ring buffer space, never wake userspace.
# On a SPAN port where <10% of traffic is relevant, this is the single
# biggest lever against ring drops.

# Accept IPv4 TCP/UDP/ICMP only, drop everything else (ARP, IPv6, broadcast,
# OSPF, IGMP, GRE, etc). Protocol filtering in kernel BPF = fewer ring wakeups.
_BPF_IP_ONLY = [
    (0x28, 0, 0, 0x0000000c),  # 0: ldh [12] — EtherType
    (0x15, 0, 5, 0x00000800),  # 1: jeq #0x0800 -> 2, else -> 7 (drop)
    (0x30, 0, 0, 0x00000017),  # 2: ldb [23] — IP protocol
    (0x15, 2, 0, 0x00000006),  # 3: jeq #6 (TCP) -> 6 (accept)
    (0x15, 1, 0, 0x00000011),  # 4: jeq #17 (UDP) -> 6 (accept)
    (0x15, 0, 1, 0x00000001),  # 5: jeq #1 (ICMP) -> 6 (accept), else -> 7
    (0x06, 0, 0, 0x0000ffff),  # 6: ret accept
    (0x06, 0, 0, 0x00000000),  # 7: ret drop
]

# Accept IPv4 TCP/UDP/ICMP, plain or 802.1Q VLAN-tagged
_BPF_IP_AND_VLAN = [
    (0x28, 0, 0, 0x0000000c),  # 0: ldh [12] — EtherType
    # If 0x0800 (IPv4), check protocol; else check VLAN
    (0x15, 0, 4, 0x00000800),  # 1: jeq #0x0800 -> 2, else -> 6 (VLAN?)
    # --- Plain IPv4 path: protocol at offset 23 ---
    (0x30, 0, 0, 0x00000017),  # 2: ldb [23] — IP protocol
    (0x15, 9, 0, 0x00000006),  # 3: jeq TCP -> 13 (accept)
    (0x15, 8, 0, 0x00000011),  # 4: jeq UDP -> 13 (accept)
    (0x15, 7, 8, 0x00000001),  # 5: jeq ICMP -> 13 (accept), else -> 14 (drop)
    # --- VLAN check ---
    (0x15, 0, 7, 0x00008100),  # 6: jeq #0x8100 -> 7, else -> 14 (drop)
    (0x28, 0, 0, 0x00000010),  # 7: ldh [16] — inner EtherType
    (0x15, 0, 5, 0x00000800),  # 8: jeq #0x0800 -> 9, else -> 14 (drop)
    # --- VLAN IPv4 path: protocol at offset 27 (14+4+9) ---
    (0x30, 0, 0, 0x0000001b),  # 9: ldb [27] — IP protocol
    (0x15, 2, 0, 0x00000006),  # 10: jeq TCP -> 13 (accept)
    (0x15, 1, 0, 0x00000011),  # 11: jeq UDP -> 13 (accept)
    (0x15, 0, 1, 0x00000001),  # 12: jeq ICMP -> 13 (accept), else -> 14
    (0x06, 0, 0, 0x0000ffff),  # 13: ret accept
    (0x06, 0, 0, 0x00000000),  # 14: ret drop
]


def _attach_bpf(fd: int, bpf_insns: List[tuple]):
    """Attach a cBPF filter to a raw socket."""
    FilterArr = SockFprog.SockFilter * len(bpf_insns)
    filters   = FilterArr(*[SockFprog.SockFilter(c, jt, jf, k)
                             for c, jt, jf, k in bpf_insns])
    prog = SockFprog(len=len(bpf_insns),
                     filter=ctypes.cast(filters, ctypes.POINTER(SockFprog.SockFilter)))
    SO_ATTACH_FILTER = 26
    ret = libc.setsockopt(fd, socket.SOL_SOCKET, SO_ATTACH_FILTER,
                          ctypes.byref(prog), ctypes.sizeof(prog))
    if ret != 0:
        raise OSError(ctypes.get_errno(), "SO_ATTACH_FILTER failed")


# ── Ring socket creation ──────────────────────────────────────────────────

def _htons(x): return socket.htons(x)


def _create_ring_socket(iface, block_size, block_count, block_timeout,
                        fanout_id, fanout_mode, worker_idx):
    sock = socket.socket(AF_PACKET, SOCK_RAW, _htons(ETH_P_ALL))
    fd   = sock.fileno()

    bpf_filter = _BPF_IP_AND_VLAN if BPF_VLAN_AWARE else _BPF_IP_ONLY
    try:
        _attach_bpf(fd, bpf_filter)
    except OSError as e:
        log.warning(f"W{worker_idx}: BPF attach failed ({e}), accepting all ethertype")

    ver = ctypes.c_int(TPACKET_V3)
    if libc.setsockopt(fd, SOL_PACKET, PACKET_VERSION,
                       ctypes.byref(ver), ctypes.sizeof(ver)) != 0:
        raise OSError(ctypes.get_errno(), "PACKET_VERSION=V3 failed")

    req3 = TpacketReq3(
        tp_block_size       = block_size,
        tp_block_nr         = block_count,
        tp_frame_size       = block_size,   # ignored in V3 but must be set
        tp_frame_nr         = block_count,  # ignored in V3 but must be set
        tp_retire_blk_tov   = block_timeout,
        tp_sizeof_priv      = 0,
        tp_feature_req_word = 0,
    )
    if libc.setsockopt(fd, SOL_PACKET, PACKET_RX_RING,
                       ctypes.byref(req3), ctypes.sizeof(req3)) != 0:
        raise OSError(ctypes.get_errno(),
                      f"PACKET_RX_RING failed (bs={block_size} bc={block_count})")

    ring_size = block_size * block_count
    ring      = mmap.mmap(fd, ring_size, mmap.MAP_SHARED,
                          mmap.PROT_READ | mmap.PROT_WRITE)
    sock.bind((iface, ETH_P_ALL))

    fanout_val = ctypes.c_int(((fanout_mode | PACKET_FANOUT_FLAG_ROLLOVER) << 16) | (fanout_id & 0xFFFF))
    if libc.setsockopt(fd, SOL_PACKET, PACKET_FANOUT,
                       ctypes.byref(fanout_val), ctypes.sizeof(fanout_val)) != 0:
        raise OSError(ctypes.get_errno(), "PACKET_FANOUT failed")

    log.info(f"W{worker_idx}: ring {block_count}×{block_size//1024//1024}MB"
             f"={ring_size//1024//1024}MB  iface={iface}  fanout_id={fanout_id:#x}")
    return sock, ring, ring_size


# ── Packet parser ─────────────────────────────────────────────────────────

@dataclass
class ParsedPacket:
    """
    Parsed fields from one network packet.
    Lives entirely within one worker process — never pickled or queued.
    """
    ts:          float
    src_ip:      str
    dst_ip:      str
    src_port:    int
    dst_port:    int
    l4_proto:    str      # "tcp" | "udp" | "icmp" | "other"
    tcp_flags:   int      # raw TCP flags byte (0 for non-TCP)
    tcp_window:  int      # TCP window size (0 for non-TCP)
    vlan_id:     int      # 802.1Q VLAN ID (0 if untagged)
    payload_len: int      # application-layer payload bytes
    pkt_len:     int      # total wire length from tp_len
    raw_payload: bytes    # first 256 bytes of payload for entropy; b"" if none


_ETH  = struct.Struct("!6s6sH")
_IP   = struct.Struct("!BBHHHBBH4s4s")
_TCP  = struct.Struct("!HHIIBBHHH")
_UDP  = struct.Struct("!HHHH")
_ICMP = struct.Struct("!BBH")


def _parse_packet(data: memoryview, ts: float, pkt_len: int) -> Optional[ParsedPacket]:
    """
    Parse raw Ethernet frame from mmap ring.  Access via memoryview throughout
    — no copy until the 256-byte payload slice at the end.
    """
    if len(data) < ETH_HLEN:
        return None

    _, _, ethertype = _ETH.unpack_from(data, 0)
    vlan_id = 0
    if ethertype == ETH_P_IP:
        ip_off = ETH_HLEN
    elif ethertype == 0x8100:   # 802.1Q VLAN tag
        # Inner EtherType is at offset ETH_HLEN + 2 (2 bytes TCI, 2 bytes inner type)
        if len(data) < ETH_HLEN + 4:
            return None
        tci = struct.unpack_from("!H", data, ETH_HLEN)[0]
        vlan_id = tci & 0x0FFF
        inner_ethertype = struct.unpack_from("!H", data, ETH_HLEN + 2)[0]
        if inner_ethertype != ETH_P_IP:
            return None
        ip_off = ETH_HLEN + 4   # 14 (eth) + 4 (vlan tag) = 18
    else:
        return None   # BPF should have dropped this already

    if len(data) < ip_off + 20:
        return None

    (ver_ihl, _, total_len, _, _,
     _, proto, _, src_raw, dst_raw) = _IP.unpack_from(data, ip_off)

    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20:
        return None

    src_ip = socket.inet_ntoa(bytes(src_raw))
    dst_ip = socket.inet_ntoa(bytes(dst_raw))

    t_off      = ip_off + ihl
    ip_payload = max(0, total_len - ihl)

    sport = dport = tcp_flags = tcp_window = hdr_extra = 0
    l4_proto = "other"

    if proto == IPPROTO_TCP:
        if len(data) < t_off + 20:
            return None
        sport, dport, _, _, doff_flags, flags, window, _, _ = _TCP.unpack_from(data, t_off)
        tcp_flags  = flags
        tcp_window = window
        hdr_extra  = ((doff_flags >> 4) & 0xF) * 4
        l4_proto   = "tcp"

    elif proto == IPPROTO_UDP:
        if len(data) < t_off + 8:
            return None
        sport, dport, _, _ = _UDP.unpack_from(data, t_off)
        hdr_extra = 8
        l4_proto  = "udp"

    elif proto == IPPROTO_ICMP:
        if len(data) < t_off + 4:
            return None
        icmp_type, _, _ = _ICMP.unpack_from(data, t_off)
        dport     = icmp_type
        hdr_extra = 4
        l4_proto  = "icmp"

    p_off   = t_off + hdr_extra
    p_len   = max(0, ip_payload - hdr_extra)
    p_end   = min(p_off + 256, len(data))
    payload = bytes(data[p_off:p_end]) if p_off < len(data) else b""

    return ParsedPacket(
        ts=ts, src_ip=src_ip, dst_ip=dst_ip,
        src_port=sport, dst_port=dport,
        l4_proto=l4_proto, tcp_flags=tcp_flags,
        tcp_window=tcp_window, vlan_id=vlan_id,
        payload_len=p_len, pkt_len=pkt_len,
        raw_payload=payload,
    )


# ── TPACKET_V3 block drainer (the hot loop) ───────────────────────────────

# Block descriptor field offsets
_BLK_STATUS_OFF    = 8
_BLK_NUM_PKTS_OFF  = 12
_BLK_FIRST_PKT_OFF = 16

# Per-packet header field offsets (struct tpacket3_hdr)
_PKT_NEXT_OFF    = 0
_PKT_SEC_OFF     = 4
_PKT_NSEC_OFF    = 8
_PKT_SNAPLEN_OFF = 12
_PKT_LEN_OFF     = 16
_PKT_MAC_OFF     = 24

_U32 = struct.Struct("=I")   # native (host) byte order — kernel uses host order
_U16 = struct.Struct("=H")

def _u32(buf, off): return _U32.unpack_from(buf, off)[0]
def _u16(buf, off): return _U16.unpack_from(buf, off)[0]


def _drain_block(ring: mmap.mmap, block_offset: int, block_size: int,
                 callback: Callable, stats: dict) -> int:
    """
    Drain all packets from one ready block.  callback is called synchronously
    for each parsed packet — it runs in the worker process, not through any queue.
    """
    num_pkts        = _u32(ring, block_offset + _BLK_NUM_PKTS_OFF)
    offset_to_first = _u32(ring, block_offset + _BLK_FIRST_PKT_OFF)
    pkt_hdr_abs     = block_offset + offset_to_first
    block_end       = block_offset + block_size

    for _ in range(num_pkts):
        if pkt_hdr_abs >= block_end:
            break

        tp_next    = _u32(ring, pkt_hdr_abs + _PKT_NEXT_OFF)
        tp_sec     = _u32(ring, pkt_hdr_abs + _PKT_SEC_OFF)
        tp_nsec    = _u32(ring, pkt_hdr_abs + _PKT_NSEC_OFF)
        tp_snaplen = _u32(ring, pkt_hdr_abs + _PKT_SNAPLEN_OFF)
        tp_len     = _u32(ring, pkt_hdr_abs + _PKT_LEN_OFF)
        tp_mac     = _u16(ring, pkt_hdr_abs + _PKT_MAC_OFF)

        ts          = tp_sec + tp_nsec * 1e-9
        frame_start = pkt_hdr_abs + tp_mac
        frame_end   = frame_start + tp_snaplen

        if frame_end <= block_end:
            ring.seek(frame_start)
            frame_mv = memoryview(ring.read(tp_snaplen))
            pkt = _parse_packet(frame_mv, ts, tp_len)
            if pkt is not None:
                try:
                    callback(pkt)       # ← direct call, zero serialisation
                    stats["packets"] += 1
                except Exception as e:
                    stats["cb_errors"] += 1
                    if stats["cb_errors"] < 10:
                        log.warning(f"Callback error: {e}")

        if tp_next == 0:
            break
        pkt_hdr_abs += tp_next

    return num_pkts


# ── Worker process ────────────────────────────────────────────────────────

def _worker_process(iface:          str,
                    worker_idx:     int,
                    fanout_id:      int,
                    fanout_mode:    int,
                    block_size:     int,
                    block_count:    int,
                    block_timeout:  int,
                    worker_factory: Callable,
                    stats_queue:    multiprocessing.Queue,
                    stop_event:     multiprocessing.Event,
                    cpu:            Optional[int] = None):
    """
    One worker process.

    cpu — if not None, this process is pinned to that core immediately after
    fork (before ring socket creation, before worker_factory, before any thread
    is spawned).  The flush thread spawned inside worker_factory inherits the
    process affinity automatically.
    """
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    logging.basicConfig(
        level=logging.INFO,
        format=f"%(asctime)s [W{worker_idx}] %(name)s — %(message)s",
    )
    wlog = logging.getLogger(f"hunter.worker{worker_idx}")

    # ── CPU pinning — first thing after fork, before any other work ──────
    # Pinning here means:
    #   - The ring socket's poll() loop runs on a predictable core
    #   - The NIC IRQ handler and the ring drainer share L3 cache
    #   - The flush thread (spawned inside worker_factory) inherits affinity
    if cpu is not None:
        _pin_to_cpu(cpu, wlog)

    # ── Create worker-local state (in this process — no pickle of threading.Lock)
    try:
        pkt_callback = worker_factory(worker_idx, stop_event)
    except Exception as e:
        wlog.critical(f"worker_factory failed: {e}", exc_info=True)
        return

    # ── Create ring socket ────────────────────────────────────────────────
    try:
        sock, ring, ring_size = _create_ring_socket(
            iface, block_size, block_count, block_timeout,
            fanout_id, fanout_mode, worker_idx,
        )
    except Exception as e:
        wlog.critical(f"Ring socket creation failed: {e}")
        return

    fd = sock.fileno()

    class PollFdStruct(ctypes.Structure):
        _fields_ = [("fd", ctypes.c_int),
                    ("events", ctypes.c_short),
                    ("revents", ctypes.c_short)]

    pfd   = PollFdStruct(fd=fd, events=0x0001, revents=0)  # POLLIN
    stats = {"packets": 0, "blocks": 0, "drops": 0, "losing": False, "cb_errors": 0}
    last_stats    = time.time()
    current_block = 0

    wlog.info(f"Capture loop started — {ring_size//1024//1024}MB ring")

    while not stop_event.is_set():
        block_offset = current_block * block_size
        block_status = _u32(ring, block_offset + _BLK_STATUS_OFF)

        if block_status & TP_STATUS_USER:
            _drain_block(ring, block_offset, block_size, pkt_callback, stats)
            stats["blocks"] += 1

            if block_status & TP_STATUS_LOSING:
                # TP_STATUS_LOSING is a STICKY flag: once tp_drops > 0
                # (cumulative since socket creation), every retired block
                # has this bit set forever. Log once, don't count per-block.
                if stats["drops"] == 0:
                    wlog.warning(
                        "TP_STATUS_LOSING detected — ring had drops at some point. "
                        "Check socket stats for actual drop count."
                    )
                stats["drops"] += 1

            # Return block to kernel (no ring.flush() — AF_PACKET mmaps are not file-backed)
            _U32.pack_into(ring, block_offset + _BLK_STATUS_OFF, TP_STATUS_KERNEL)
            current_block = (current_block + 1) % block_count

        else:
            # Block not ready — wait up to block_timeout ms
            libc.poll(ctypes.byref(pfd), 1, block_timeout)

        # Emit per-worker stats every 30 seconds
        now = time.time()
        if now - last_stats >= 30:
            # Read actual kernel drop count via getsockopt(PACKET_STATISTICS)
            # struct tpacket_stats_v3 { tp_packets, tp_drops, tp_freeze_q_cnt }
            # NOTE: PACKET_STATISTICS resets counters on read — value IS the delta
            sock_drops = 0
            try:
                pkt_stats = sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 12)
                _, tp_drops, _ = struct.unpack("=III", pkt_stats)
                sock_drops = tp_drops
            except Exception:
                pass
            try:
                stats_queue.put_nowait({
                    "worker":  worker_idx,
                    "cpu":     cpu,
                    "packets": stats["packets"],
                    "blocks":  stats["blocks"],
                    "drops":   sock_drops,
                    "ts":      now,
                })
            except Exception:
                pass
            stats      = {"packets": 0, "blocks": 0, "drops": 0, "losing": False, "cb_errors": 0}
            last_stats = now

    ring.close()
    sock.close()
    wlog.info("Worker stopped.")


# ── FanoutCapture — public API ────────────────────────────────────────────

class FanoutCapture:
    """
    AF_PACKET TPACKET_V3 + PACKET_FANOUT high-throughput capture.

    Zero IPC on any data path:
      - No packet queue   (workers call ingest() directly in-process)
      - No session queue  (workers write completed sessions to SQLite directly)
    The only multiprocessing.Queue is stats_queue: ~4 tiny dicts per 30 seconds.

    CPU pinning
    -----------
    Pass cpu_list to bind each worker to a specific core.  When set:
      - Worker i is pinned to cpu_list[i % len(cpu_list)]
      - Pinning happens inside the worker process immediately after fork,
        before the ring socket is created and before worker_factory runs
      - The flush thread spawned by worker_factory inherits the affinity
      - If the OS rejects the affinity (restricted container, bad CPU number)
        the worker logs a warning and continues unpinned

    cpu_list=None  (default): no pinning, OS scheduler decides placement.
    cpu_list="auto": detect online CPUs from /sys/devices/system/cpu/online
                     and assign workers sequentially starting from CPU 0.
    cpu_list=[2,3,4,5]: pin worker 0→CPU2, worker 1→CPU3, etc.

    Ideal alignment: set cpu_list to match the CPUs handling the NIC's RX IRQs.
    Check: cat /proc/interrupts | grep <iface>
    Set IRQ affinity: echo <cpu_mask> > /proc/irq/<N>/smp_affinity

    Parameters
    ----------
    iface           : SPAN/mirror port interface name
    num_workers     : Worker count (match to NIC RX queues)
    worker_factory  : Callable[[worker_idx, stop_event], pkt_callback]
    cpu_list        : None | "auto" | List[int]  (see above)
    fanout_mode     : PACKET_FANOUT_HASH (default, session-affine)
    block_size_mb   : Ring block size in MB (power-of-2, default 2)
    block_count     : Blocks per worker ring (default 128)
    block_timeout   : ms to wait for partial block (default 100)
    """

    def __init__(self,
                 iface:           str,
                 num_workers:     int            = 4,
                 worker_factory:  Callable       = None,
                 cpu_list                        = None,   # None | "auto" | List[int]
                 fanout_mode:     int            = PACKET_FANOUT_HASH,
                 block_size_mb:   int            = 2,
                 block_count:     int            = 128,
                 block_timeout:   int            = 100):

        if worker_factory is None:
            raise ValueError("worker_factory is required")

        self.iface          = iface
        self.num_workers    = num_workers
        self.worker_factory = worker_factory
        self.cpu_list_raw   = cpu_list
        self.fanout_mode    = fanout_mode
        self.block_size     = block_size_mb * 1024 * 1024
        self.block_count    = block_count
        self.block_timeout  = block_timeout
        self.fanout_id      = os.getpid() & 0xFFFF

        self._stats_queue   = multiprocessing.Queue(maxsize=num_workers * 20)
        self._stop          = multiprocessing.Event()
        self._workers       = []
        self._stats_thread  = None
        self._total_drops   = 0

    def _resolve_cpu_assignments(self) -> List[Optional[int]]:
        """
        Compute the per-worker CPU assignment list.

        Returns a list of length num_workers where each element is either
        an int (CPU to pin to) or None (no pinning for that worker).
        """
        raw = self.cpu_list_raw

        if raw is None:
            return [None] * self.num_workers

        if raw == "auto":
            online = _get_online_cpus()
            log.info(f"CPU auto-detect: online cores = {online}")
            resolved = online
        elif isinstance(raw, str):
            resolved = _parse_cpu_list(raw)
        else:
            resolved = list(raw)

        if not resolved:
            log.warning("cpu_list resolved to empty — running unpinned")
            return [None] * self.num_workers

        # Assign worker i → resolved[i % len(resolved)]
        assignments = [resolved[i % len(resolved)] for i in range(self.num_workers)]
        return assignments

    def start(self):
        """Spawn workers and block until stop() or KeyboardInterrupt."""
        cpu_assignments = self._resolve_cpu_assignments()

        bpf_label = "IPv4+VLAN-802.1Q" if BPF_VLAN_AWARE else "IPv4-only"
        log.info(f"BPF filter: {bpf_label}  FANOUT_FLAG_ROLLOVER: enabled")

        pinned = [c for c in cpu_assignments if c is not None]
        if pinned:
            mapping = {i: c for i, c in enumerate(cpu_assignments)}
            log.info(
                f"FanoutCapture starting: iface={self.iface} "
                f"workers={self.num_workers} "
                f"ring={self.block_count}×{self.block_size//1024//1024}MB "
                f"fanout_id={self.fanout_id:#x} "
                f"cpu_pins={mapping}"
            )
        else:
            log.info(
                f"FanoutCapture starting: iface={self.iface} "
                f"workers={self.num_workers} "
                f"ring={self.block_count}×{self.block_size//1024//1024}MB "
                f"fanout_id={self.fanout_id:#x} "
                f"cpu_pinning=disabled"
            )

        for i in range(self.num_workers):
            p = multiprocessing.Process(
                target=_worker_process,
                args=(
                    self.iface, i, self.fanout_id, self.fanout_mode,
                    self.block_size, self.block_count, self.block_timeout,
                    self.worker_factory,
                    self._stats_queue,
                    self._stop,
                    cpu_assignments[i],   # None or int — pinning done inside worker
                ),
                name=f"dfi-w{i}",
                daemon=True,
            )
            p.start()
            self._workers.append(p)
            cpu_str = f" cpu={cpu_assignments[i]}" if cpu_assignments[i] is not None else ""
            log.info(f"  Worker {i} PID={p.pid}{cpu_str}")

        self._stats_thread = threading.Thread(
            target=self._stats_loop, daemon=True, name="afp-stats"
        )
        self._stats_thread.start()

        try:
            for p in self._workers:
                p.join()
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        log.info("FanoutCapture stopping...")
        self._stop.set()
        for p in self._workers:
            p.join(timeout=3)
            if p.is_alive():
                p.terminate()
        log.info(f"Stopped. Cumulative ring drops: {self._total_drops:,}")

    def _stats_loop(self):
        worker_stats = {}
        while not self._stop.is_set():
            try:
                s = self._stats_queue.get(timeout=1)
                worker_stats[s["worker"]] = s
                if len(worker_stats) == self.num_workers:
                    pkt   = sum(x["packets"] for x in worker_stats.values())
                    drops = sum(x["drops"]   for x in worker_stats.values())
                    blks  = sum(x["blocks"]  for x in worker_stats.values())
                    self._total_drops += drops
                    # Show per-worker cpu alongside packet counts
                    per_w = "  ".join(
                        f"W{x['worker']}(cpu={x.get('cpu','?')}): {x['packets']:,}pkt"
                        for x in sorted(worker_stats.values(), key=lambda x: x["worker"])
                    )
                    log.info(
                        f"[30s] pkts={pkt:,} blocks={blks:,} "
                        f"ring_drops={drops:,} | {per_w}"
                    )
                    worker_stats.clear()
            except Exception:
                pass
