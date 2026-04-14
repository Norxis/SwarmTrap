#!/usr/bin/env python3
import hashlib
import struct
from datetime import datetime, timezone
from typing import Optional


def _is_grease(v: int) -> bool:
    return (v & 0x0F0F) == 0x0A0A


def parse_tls_client_hello(payload: bytes) -> Optional[dict]:
    if len(payload) < 11:
        return None
    if payload[0] != 0x16:
        return None
    if payload[5] != 0x01:
        return None

    pos = 9
    if pos + 2 > len(payload):
        return None

    client_version = struct.unpack('!H', payload[pos:pos + 2])[0]
    pos += 2

    version_map = {0x0300: 10, 0x0301: 11, 0x0302: 11, 0x0303: 12}
    tls_version = version_map.get(client_version, 0)

    pos += 32
    if pos >= len(payload):
        return None

    sid_len = payload[pos]
    pos += 1 + sid_len
    if pos + 2 > len(payload):
        return None

    cs_len = struct.unpack('!H', payload[pos:pos + 2])[0]
    pos += 2
    if pos + cs_len > len(payload):
        return None

    cipher_suites = []
    for i in range(0, cs_len, 2):
        if pos + i + 2 > len(payload):
            break
        cs = struct.unpack('!H', payload[pos + i:pos + i + 2])[0]
        if not _is_grease(cs):
            cipher_suites.append(cs)
    pos += cs_len

    if pos >= len(payload):
        return None

    comp_len = payload[pos]
    pos += 1 + comp_len

    extensions = []
    elliptic_curves = []
    ec_point_formats = []
    supported_versions = []
    sni = None

    if pos + 2 <= len(payload):
        ext_total_len = struct.unpack('!H', payload[pos:pos + 2])[0]
        pos += 2
        ext_end = min(pos + ext_total_len, len(payload))

        while pos + 4 <= ext_end:
            ext_type = struct.unpack('!H', payload[pos:pos + 2])[0]
            ext_len = struct.unpack('!H', payload[pos + 2:pos + 4])[0]
            pos += 4
            if pos + ext_len > ext_end:
                break
            ext_data = payload[pos:pos + ext_len]
            pos += ext_len

            if not _is_grease(ext_type):
                extensions.append(ext_type)

            if ext_type == 0x0000 and len(ext_data) >= 5:
                if ext_data[2] == 0x00:
                    name_len = struct.unpack('!H', ext_data[3:5])[0]
                    if 5 + name_len <= len(ext_data):
                        sni = ext_data[5:5 + name_len].decode('ascii', errors='ignore')

            if ext_type == 0x002B and len(ext_data) >= 1:
                sv_len = ext_data[0]
                i = 1
                end = min(1 + sv_len, len(ext_data))
                while i + 1 < end:
                    v = struct.unpack('!H', ext_data[i:i + 2])[0]
                    if not _is_grease(v):
                        supported_versions.append(v)
                    i += 2

            if ext_type == 0x000A and len(ext_data) >= 2:
                sg_len = struct.unpack('!H', ext_data[0:2])[0]
                i = 2
                end = min(2 + sg_len, len(ext_data))
                while i + 1 < end:
                    g = struct.unpack('!H', ext_data[i:i + 2])[0]
                    if not _is_grease(g):
                        elliptic_curves.append(g)
                    i += 2

            if ext_type == 0x000B and len(ext_data) >= 1:
                epf_len = ext_data[0]
                for b in ext_data[1:1 + epf_len]:
                    ec_point_formats.append(int(b))

    ja3_str = (
        f"{client_version},"
        f"{'-'.join(str(c) for c in cipher_suites)},"
        f"{'-'.join(str(e) for e in extensions)},"
        f"{'-'.join(str(c) for c in elliptic_curves)},"
        f"{'-'.join(str(p) for p in ec_point_formats)}"
    )
    ja3_hash = hashlib.md5(ja3_str.encode('ascii', errors='ignore')).hexdigest()

    if 0x0304 in supported_versions:
        tls_version = 13

    return {
        'ja3_hash': ja3_hash,
        'tls_version': int(tls_version),
        'tls_cipher_count': int(len(cipher_suites)),
        'tls_ext_count': int(len(extensions)),
        'tls_has_sni': 1 if sni else 0,
    }


def _parse_kexinit(msg_payload: bytes) -> list:
    pos = 17
    name_lists = []
    for _ in range(10):
        if pos + 4 > len(msg_payload):
            break
        nl_len = struct.unpack('!I', msg_payload[pos:pos + 4])[0]
        pos += 4
        if pos + nl_len > len(msg_payload):
            break
        name_lists.append(msg_payload[pos:pos + nl_len].decode('ascii', errors='ignore'))
        pos += nl_len
    return name_lists


def parse_ssh(events: list) -> Optional[dict]:
    banner_found = False
    kex_lists = []

    for e in events:
        if e.payload_len <= 0:
            continue
        data = (e.payload_head or b'')[:e.payload_len]
        if not data:
            continue

        if data.startswith(b'SSH-'):
            banner_found = True
            continue

        if e.direction == 1 and len(data) >= 6:
            try:
                if data[5] == 20:
                    kex_lists = _parse_kexinit(data[5:])
            except Exception:
                pass

    if not banner_found:
        return None

    hassh_hash = None
    ssh_kex_count = 0
    if kex_lists:
        while len(kex_lists) < 4:
            kex_lists.append('')
        hassh_str = ';'.join(kex_lists[:4])
        hassh_hash = hashlib.md5(hassh_str.encode('ascii', errors='ignore')).hexdigest()
        ssh_kex_count = len([x for x in kex_lists[0].split(',') if x])

    return {
        'hassh_hash': hassh_hash,
        'ssh_kex_count': int(ssh_kex_count),
    }


def parse_http_request(payload: bytes) -> Optional[dict]:
    methods = {
        b'GET': 1,
        b'POST': 2,
        b'HEAD': 3,
        b'PUT': 4,
        b'DELETE': 5,
        b'OPTIONS': 5,
        b'PATCH': 5,
        b'CONNECT': 5,
    }

    method_code = 0
    for method, code in methods.items():
        if payload.startswith(method + b' '):
            method_code = code
            break
    if method_code == 0:
        return None

    try:
        text = payload.decode('ascii', errors='ignore')
        lines = text.split('\r\n')
        if not lines:
            return None

        parts = lines[0].split(' ', 2)
        uri = parts[1] if len(parts) >= 2 else ''

        header_count = 0
        ua_value = None
        has_body = 0

        for line in lines[1:]:
            if line == '':
                body_start = text.find('\r\n\r\n')
                if body_start >= 0 and body_start + 4 < len(text):
                    has_body = 1
                break
            header_count += 1
            lower = line.lower()
            if lower.startswith('user-agent:'):
                ua_value = line.split(':', 1)[1].strip()
            if lower.startswith('content-length:'):
                try:
                    if int(line.split(':', 1)[1].strip()) > 0:
                        has_body = 1
                except ValueError:
                    pass

        return {
            'http_method': int(method_code),
            'http_uri_len': int(len(uri)),
            'http_header_count': int(header_count),
            'http_ua_hash': hashlib.md5(ua_value.encode('utf-8')).hexdigest() if ua_value else None,
            'http_has_body': int(has_body),
        }
    except Exception:
        return None


def parse_http_status(payload: bytes) -> Optional[int]:
    try:
        text = payload[:64].decode('ascii', errors='ignore')
        if text.startswith('HTTP/'):
            parts = text.split(' ', 2)
            if len(parts) >= 2:
                return int(parts[1])
    except Exception:
        return None
    return None


def parse_dns_query(payload: bytes) -> Optional[dict]:
    if len(payload) < 17:
        return None

    flags = struct.unpack('!H', payload[2:4])[0]
    if flags & 0x8000:
        return None

    qdcount = struct.unpack('!H', payload[4:6])[0]
    if qdcount == 0:
        return None

    pos = 12
    qname_parts = []
    while pos < len(payload):
        ln = payload[pos]
        if ln == 0:
            pos += 1
            break
        if ln > 63:
            return None
        pos += 1
        if pos + ln > len(payload):
            return None
        qname_parts.append(payload[pos:pos + ln].decode('ascii', errors='ignore'))
        pos += ln

    if pos + 4 > len(payload):
        return None

    qname = '.'.join(qname_parts)
    qtype = struct.unpack('!H', payload[pos:pos + 2])[0]

    return {
        'dns_qtype': int(min(qtype, 255)),
        'dns_qname_len': int(len(qname)),
    }


def extract_fingerprint(session) -> Optional[dict]:
    fp = {
        'flow_id': session.flow_id,
        'src_ip': session.src_ip,
        'dst_ip': session.dst_ip,
        'dst_port': int(session.dst_port),
        'first_ts': datetime.fromtimestamp(session.first_ts, tz=timezone.utc),

        'ja3_hash': None,
        'tls_version': 0,
        'tls_cipher_count': 0,
        'tls_ext_count': 0,
        'tls_has_sni': 0,

        'hassh_hash': None,
        'ssh_kex_count': 0,

        'http_method': 0,
        'http_uri_len': 0,
        'http_header_count': 0,
        'http_ua_hash': None,
        'http_has_body': 0,
        'http_status': 0,

        'dns_qtype': 0,
        'dns_qname_len': 0,
    }

    first_fwd_payload = None
    first_rev_payload = None
    for e in session.events:
        if e.payload_len <= 0:
            continue
        p = (e.payload_head or b'')[:e.payload_len]
        if e.direction == 1 and first_fwd_payload is None:
            first_fwd_payload = p
        elif e.direction == -1 and first_rev_payload is None:
            first_rev_payload = p
        if first_fwd_payload is not None and first_rev_payload is not None:
            break

    if first_fwd_payload is None and first_rev_payload is None:
        return None

    parsed = False

    if first_fwd_payload:
        tls = parse_tls_client_hello(first_fwd_payload)
        if tls:
            fp.update(tls)
            parsed = True

        http = parse_http_request(first_fwd_payload)
        if http:
            fp.update(http)
            parsed = True

        if int(session.ip_proto) == 17:
            dns = parse_dns_query(first_fwd_payload)
            if dns:
                fp.update(dns)
                parsed = True

    ssh = parse_ssh(session.events)
    if ssh:
        fp.update(ssh)
        parsed = True

    if first_rev_payload:
        status = parse_http_status(first_rev_payload)
        if status is not None:
            fp['http_status'] = int(status)
            parsed = True

    return fp if parsed else None
