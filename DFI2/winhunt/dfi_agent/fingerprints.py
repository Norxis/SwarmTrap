"""Protocol fingerprint extraction — TLS, HTTP, SMB, DNS.

Extracted from first qualifying packet of each type per flow.
Once extracted, internal flags prevent re-extraction from later packets.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Any


@dataclass
class FingerprintState:
    # TLS (from ClientHello)
    ja3_hash: str | None = None
    tls_version: int = 0          # 0/10/11/12/13
    tls_cipher_count: int = 0
    tls_ext_count: int = 0
    tls_has_sni: int = 0          # 0/1
    # SSH (always None/0 on Windows honeypots)
    hassh_hash: str | None = None
    ssh_kex_count: int = 0
    # HTTP
    http_method: int = 0          # 0=none, 1=GET, 2=POST, 3=HEAD, 4=PUT, 5=other
    http_uri_len: int = 0
    http_header_count: int = 0
    http_ua_hash: str | None = None
    http_has_body: int = 0        # 0/1
    http_status: int = 0          # First response status code
    # DNS
    dns_qtype: int = 0
    dns_qname_len: int = 0
    # Internal flags (not serialized)
    _tls_extracted: bool = field(default=False, repr=False)
    _http_req_extracted: bool = field(default=False, repr=False)
    _http_resp_extracted: bool = field(default=False, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ja3_hash": self.ja3_hash,
            "tls_version": self.tls_version,
            "tls_cipher_count": self.tls_cipher_count,
            "tls_ext_count": self.tls_ext_count,
            "tls_has_sni": self.tls_has_sni,
            "hassh_hash": self.hassh_hash,
            "ssh_kex_count": self.ssh_kex_count,
            "http_method": self.http_method,
            "http_uri_len": self.http_uri_len,
            "http_header_count": self.http_header_count,
            "http_ua_hash": self.http_ua_hash,
            "http_has_body": self.http_has_body,
            "http_status": self.http_status,
            "dns_qtype": self.dns_qtype,
            "dns_qname_len": self.dns_qname_len,
        }


_HTTP_METHODS = {
    b"GET": 1, b"POST": 2, b"HEAD": 3, b"PUT": 4,
    b"DELETE": 5, b"OPTIONS": 5, b"PATCH": 5,
}

_IS_GREASE = lambda v: (v & 0x0F0F) == 0x0A0A


def extract_tls_fingerprint(payload: bytes, fp: FingerprintState) -> None:
    """Parse TLS ClientHello from forward payload."""
    if fp._tls_extracted:
        return
    p = payload
    if len(p) < 6 or p[0] != 0x16:
        return
    # Record version at offset 1-2
    rec_version = struct.unpack("!H", p[1:3])[0]
    # Offset 5: handshake type must be 0x01 (ClientHello)
    if p[5] != 0x01:
        return

    fp._tls_extracted = True
    try:
        # Client version at offset 9-10
        if len(p) < 11:
            return
        client_version = struct.unpack("!H", p[9:11])[0]

        # Map version number
        ver_map = {0x0300: 10, 0x0301: 11, 0x0302: 11, 0x0303: 12}
        tls_ver = ver_map.get(client_version, 0)

        # Skip random (32 bytes) at offset 11-42
        off = 43
        if off >= len(p):
            fp.tls_version = tls_ver
            return

        # Session ID
        sid_len = p[off]
        off += 1 + sid_len
        if off + 2 > len(p):
            fp.tls_version = tls_ver
            return

        # Cipher suites
        cs_len = struct.unpack("!H", p[off:off + 2])[0]
        off += 2
        cs_end = off + cs_len
        cipher_ids: list[int] = []
        while off + 1 < cs_end and off + 1 < len(p):
            cid = struct.unpack("!H", p[off:off + 2])[0]
            off += 2
            if not _IS_GREASE(cid):
                cipher_ids.append(cid)
        off = min(cs_end, len(p))
        fp.tls_cipher_count = len(cipher_ids)

        # Compression methods
        if off >= len(p):
            fp.tls_version = tls_ver
            fp.ja3_hash = hashlib.md5(f"{client_version},{','.join(str(c) for c in cipher_ids)}".encode()).hexdigest()
            return
        comp_len = p[off]
        off += 1 + comp_len

        # Extensions
        ext_count = 0
        has_sni = 0
        if off + 2 <= len(p):
            ext_total_len = struct.unpack("!H", p[off:off + 2])[0]
            off += 2
            ext_end = off + ext_total_len
            while off + 4 <= min(ext_end, len(p)):
                ext_type = struct.unpack("!H", p[off:off + 2])[0]
                ext_len = struct.unpack("!H", p[off + 2:off + 4])[0]
                off += 4
                if not _IS_GREASE(ext_type):
                    ext_count += 1
                # SNI extension
                if ext_type == 0:
                    has_sni = 1
                # supported_versions extension — check for TLS 1.3
                if ext_type == 43 and off + ext_len <= len(p) and ext_len >= 3:
                    sv_len = p[off]
                    sv_off = off + 1
                    while sv_off + 1 < off + ext_len and sv_off + 1 < len(p):
                        sv = struct.unpack("!H", p[sv_off:sv_off + 2])[0]
                        if sv == 0x0304:
                            tls_ver = 13
                            break
                        sv_off += 2
                off += ext_len

        fp.tls_version = tls_ver
        fp.tls_ext_count = ext_count
        fp.tls_has_sni = has_sni
        fp.ja3_hash = hashlib.md5(
            f"{client_version},{','.join(str(c) for c in cipher_ids)}".encode()
        ).hexdigest()

    except (struct.error, IndexError):
        fp.tls_version = fp.tls_version or 0


def extract_http_request(payload: bytes, fp: FingerprintState) -> None:
    """Parse HTTP request from forward payload."""
    if fp._http_req_extracted:
        return
    p = payload
    if len(p) < 4:
        return

    # Find first space to get method
    sp = p.find(b" ")
    if sp < 0 or sp > 10:
        return
    method_bytes = p[:sp]
    method_code = _HTTP_METHODS.get(method_bytes, 0)
    if method_code == 0 and method_bytes not in (b"CONNECT", b"TRACE"):
        return

    fp._http_req_extracted = True
    fp.http_method = method_code if method_code > 0 else 5

    # Extract URI length
    rest = p[sp + 1:]
    uri_end = rest.find(b" ")
    if uri_end < 0:
        uri_end = rest.find(b"\r\n")
    fp.http_uri_len = uri_end if uri_end > 0 else len(rest)

    # Count headers (number of \r\n in header block)
    header_end = p.find(b"\r\n\r\n")
    first_line_end = p.find(b"\r\n")
    if first_line_end >= 0 and header_end > first_line_end:
        header_block = p[first_line_end + 2:header_end]
        fp.http_header_count = header_block.count(b"\r\n") + 1
    elif first_line_end >= 0:
        header_block = p[first_line_end + 2:]
        fp.http_header_count = max(1, header_block.count(b"\r\n"))

    # User-Agent hash
    ua_lower = p.lower()
    ua_idx = ua_lower.find(b"user-agent:")
    if ua_idx >= 0:
        ua_start = ua_idx + len(b"user-agent:")
        ua_end = p.find(b"\r\n", ua_start)
        if ua_end < 0:
            ua_end = len(p)
        ua_val = p[ua_start:ua_end].strip()
        fp.http_ua_hash = hashlib.md5(ua_val).hexdigest()

    # Body detection
    cl_idx = ua_lower.find(b"content-length:")
    te_idx = ua_lower.find(b"transfer-encoding:")
    if cl_idx >= 0:
        cl_start = cl_idx + len(b"content-length:")
        cl_end = p.find(b"\r\n", cl_start)
        if cl_end < 0:
            cl_end = len(p)
        try:
            cl_val = int(p[cl_start:cl_end].strip())
            if cl_val > 0:
                fp.http_has_body = 1
        except ValueError:
            pass
    if te_idx >= 0:
        fp.http_has_body = 1


def extract_http_response(payload: bytes, fp: FingerprintState) -> None:
    """Parse HTTP response status from reverse payload."""
    if fp._http_resp_extracted:
        return
    p = payload
    if len(p) < 12 or not p.startswith(b"HTTP/"):
        return
    fp._http_resp_extracted = True
    try:
        status = int(p[9:12])
        fp.http_status = status
    except (ValueError, IndexError):
        pass


def update_fingerprint(fp: FingerprintState, dst_port: int, src_port: int,
                       payload: bytes, direction: int) -> None:
    """Extract fingerprints from a packet payload."""
    if not payload:
        return

    if direction == 1:  # Forward (attacker → honeypot)
        # TLS on port 443
        if dst_port == 443 and payload[0] == 0x16:
            extract_tls_fingerprint(payload, fp)
        # HTTP on ports 80, 443, 5985, 5986
        if dst_port in {80, 443, 5985, 5986, 8080}:
            extract_http_request(payload, fp)
    elif direction == -1:  # Reverse (honeypot → attacker)
        if dst_port in {80, 443, 5985, 5986, 8080}:
            extract_http_response(payload, fp)

    # SMB detection on port 445
    if dst_port == 445 and len(payload) >= 4:
        if payload[:4] in (b"\xffSMB", b"\xfeSMB"):
            pass  # app_proto detection handled in flow_table


def to_dict(fp: FingerprintState) -> dict[str, Any]:
    return fp.to_dict()
