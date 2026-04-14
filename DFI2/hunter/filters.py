#!/usr/bin/env python3
import ipaddress
import threading


class HoneypotFilter:
    _BUILTIN_EXCLUDE_NETS = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),
    ]

    _BUILTIN_EXCLUDE_IPS = {
        '0.0.0.0',
        '255.255.255.255',
        '8.8.8.8',
        '8.8.4.4',
        '1.1.1.1',
        '1.0.0.1',
    }

    def __init__(self, honeypot_ips, exclude_entries=None):
        self._honeypot = set()
        for entry in honeypot_ips:
            entry = entry.strip() if entry else ''
            if not entry:
                continue
            if '/' in entry:
                try:
                    for addr in ipaddress.ip_network(entry, strict=False).hosts():
                        self._honeypot.add(str(addr))
                except ValueError:
                    continue
            else:
                self._honeypot.add(entry)
        self._known_bad = set()
        self._lock = threading.Lock()

        self._exclude_ips = set(self._BUILTIN_EXCLUDE_IPS)
        self._exclude_nets = list(self._BUILTIN_EXCLUDE_NETS)
        self._exclude_cache = set()

        for entry in exclude_entries or []:
            entry = entry.strip()
            if not entry:
                continue
            if '/' in entry:
                try:
                    self._exclude_nets.append(ipaddress.ip_network(entry, strict=False))
                except ValueError:
                    continue
            else:
                self._exclude_ips.add(entry)

    def _is_excluded(self, ip: str) -> bool:
        if ip in self._exclude_ips or ip in self._exclude_cache:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            for net in self._exclude_nets:
                if addr in net:
                    self._exclude_cache.add(ip)
                    return True
        except ValueError:
            return True
        return False

    def check_packet(self, src_ip: str, dst_ip: str):
        src_hp = src_ip in self._honeypot
        dst_hp = dst_ip in self._honeypot

        if src_hp and dst_hp:
            return None

        if src_hp or dst_hp:
            if src_hp:
                bad_ip, peer_ip, direction = dst_ip, src_ip, -1
            else:
                bad_ip, peer_ip, direction = src_ip, dst_ip, 1

            if self._is_excluded(bad_ip):
                return None

            with self._lock:
                self._known_bad.add(bad_ip)

            return bad_ip, peer_ip, direction, True

        with self._lock:
            src_bad = src_ip in self._known_bad
            dst_bad = dst_ip in self._known_bad

        if not src_bad and not dst_bad:
            return None

        if src_bad:
            bad_ip, peer_ip, direction = src_ip, dst_ip, 1
        else:
            bad_ip, peer_ip, direction = dst_ip, src_ip, -1

        if self._is_excluded(peer_ip):
            return None

        return bad_ip, peer_ip, direction, True


class AllTrafficFilter:
    """Capture ALL SPAN traffic. Honeypot/known-bad → is_attack=True, everything else → is_attack=False."""

    _RFC1918_NETS = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
    ]

    _BUILTIN_EXCLUDE_IPS = {
        '0.0.0.0',
        '255.255.255.255',
    }

    def __init__(self, honeypot_ips, exclude_entries=None):
        self._honeypot = set()
        for entry in honeypot_ips:
            entry = entry.strip() if entry else ''
            if not entry:
                continue
            if '/' in entry:
                try:
                    for addr in ipaddress.ip_network(entry, strict=False).hosts():
                        self._honeypot.add(str(addr))
                except ValueError:
                    continue
            else:
                self._honeypot.add(entry)
        self._known_bad = set()
        self._lock = threading.Lock()

        self._exclude_ips = set(self._BUILTIN_EXCLUDE_IPS)
        for entry in exclude_entries or []:
            entry = entry.strip()
            if not entry:
                continue
            if '/' not in entry:
                self._exclude_ips.add(entry)

        self._rfc1918_cache = set()

    def _is_rfc1918(self, ip: str) -> bool:
        if ip in self._rfc1918_cache:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            for net in self._RFC1918_NETS:
                if addr in net:
                    self._rfc1918_cache.add(ip)
                    return True
        except ValueError:
            return False
        return False

    def check_packet(self, src_ip: str, dst_ip: str):
        if src_ip in self._exclude_ips or dst_ip in self._exclude_ips:
            return None

        src_hp = src_ip in self._honeypot
        dst_hp = dst_ip in self._honeypot

        # Both honeypot → skip
        if src_hp and dst_hp:
            return None

        # Honeypot-related traffic → attack
        if src_hp or dst_hp:
            if src_hp:
                bad_ip, peer_ip, direction = dst_ip, src_ip, -1
            else:
                bad_ip, peer_ip, direction = src_ip, dst_ip, 1
            with self._lock:
                self._known_bad.add(bad_ip)
            return bad_ip, peer_ip, direction, True

        # Known-bad IP traffic → attack
        with self._lock:
            src_bad = src_ip in self._known_bad
            dst_bad = dst_ip in self._known_bad

        if src_bad or dst_bad:
            if src_bad:
                return src_ip, dst_ip, 1, True
            return dst_ip, src_ip, -1, True

        # Both RFC1918 → skip (internal-only noise)
        if self._is_rfc1918(src_ip) and self._is_rfc1918(dst_ip):
            return None

        # Normal traffic → capture as non-attack
        # Canonicalize: lower IP is always "src" so both directions
        # of a conversation map to the same session key.
        if src_ip <= dst_ip:
            return src_ip, dst_ip, 1, False
        return dst_ip, src_ip, -1, False


class SpanWatchlistFilter:
    def __init__(self, watchlist_reader):
        self._wl = watchlist_reader

    def check_packet(self, src_ip: str, dst_ip: str):
        src_w = self._wl.lookup(src_ip)
        dst_w = self._wl.lookup(dst_ip)

        if not src_w and not dst_w:
            return None

        if src_w:
            return src_ip, dst_ip, 1, True
        return dst_ip, src_ip, -1, True


class DirtyTrafficFilter:
    """Capture ONLY dirty traffic: watchlist IPs only. Honeypot IPs excluded."""

    _BUILTIN_EXCLUDE_IPS = {
        '0.0.0.0',
        '255.255.255.255',
    }

    def __init__(self, watchlist_reader, honeypot_ips=None):
        self._wl = watchlist_reader
        self._honeypot = set()
        for entry in honeypot_ips or []:
            entry = entry.strip() if entry else ''
            if not entry:
                continue
            if '/' in entry:
                try:
                    for addr in ipaddress.ip_network(entry, strict=False).hosts():
                        self._honeypot.add(str(addr))
                except ValueError:
                    continue
            else:
                self._honeypot.add(entry)

    def check_packet(self, src_ip: str, dst_ip: str):
        if src_ip in self._BUILTIN_EXCLUDE_IPS or dst_ip in self._BUILTIN_EXCLUDE_IPS:
            return None
        if src_ip in self._honeypot or dst_ip in self._honeypot:
            return None

        # Watchlist traffic only — watchlist IP is the attacker (src)
        src_w = self._wl.lookup(src_ip)
        dst_w = self._wl.lookup(dst_ip)
        if not src_w and not dst_w:
            return None
        if src_w:
            return src_ip, dst_ip, 1, False
        return dst_ip, src_ip, -1, False


class CleanTrafficFilter:
    """Capture only CLEAN traffic. Drop any flow involving a watchlist or honeypot IP."""

    _BUILTIN_EXCLUDE_IPS = {
        '0.0.0.0',
        '255.255.255.255',
    }

    def __init__(self, watchlist_reader, honeypot_ips=None):
        self._wl = watchlist_reader
        self._honeypot = set()
        for entry in honeypot_ips or []:
            entry = entry.strip() if entry else ''
            if not entry:
                continue
            if '/' in entry:
                try:
                    for addr in ipaddress.ip_network(entry, strict=False).hosts():
                        self._honeypot.add(str(addr))
                except ValueError:
                    continue
            else:
                self._honeypot.add(entry)

    def check_packet(self, src_ip: str, dst_ip: str):
        if src_ip in self._BUILTIN_EXCLUDE_IPS or dst_ip in self._BUILTIN_EXCLUDE_IPS:
            return None
        if src_ip in self._honeypot or dst_ip in self._honeypot:
            return None
        if self._wl.lookup(src_ip) or self._wl.lookup(dst_ip):
            return None
        # Canonicalize: lower IP is always "src" so both directions
        # of a conversation map to the same session key.
        if src_ip <= dst_ip:
            return src_ip, dst_ip, 1, False
        return dst_ip, src_ip, -1, False
