# Phase 4: Fingerprint Extraction

> **Executor:** Codex
> **Reviewer:** Claude Code
> **Status:** Not started
> **Depends on:** Phase 2 (Hunter core running, data flowing to CH)

## Objective

Implement protocol-specific handshake parsing for TLS (JA3), SSH (HASSH), HTTP, and DNS — populating the `fingerprints` table in ClickHouse with all 15 F7 features per flow.

## Reference Files

| File | What to read |
|------|-------------|
| `~/ai-shared/DFI2/DFI2_XGB_v1_Spec.md` | F7: Protocol Fingerprints (15 features) — exact columns, types, frequency encoding |
| `~/ai-shared/DFI2/DFI2_Dataset_DB_Spec.md` | `fingerprints` table schema (lines 261-310), `fingerprint_freq` materialized views (lines 664-691) |
| `~/DFI2/hunter/hunter.py` | SessionProfile.events — PacketEvent with payload_head (first 256 bytes) |
| `~/DFI2/hunter/writer.py` | DFIWriter.insert_flow() — fp parameter (dict or None) |

## Output Files

```
~/DFI2/hunter/
├── fingerprints.py    # NEW: TLS/SSH/HTTP/DNS protocol parsing
├── hunter.py          # MODIFY: call fingerprints.extract_fingerprint() on flush
└── writer.py          # VERIFY: fp dict flows through to fingerprints_buffer
```

---

## Step 1: fingerprints.py — Main Entry Point

Single function: `extract_fingerprint(session) -> dict`

Takes a SessionProfile, inspects the first forward payload(s) and first reverse payload, returns a dict matching `dfi.fingerprints` columns. Returns `None` if no payload at all.

```python
import hashlib
import struct
from typing import Optional

def extract_fingerprint(session) -> Optional[dict]:
    """Extract protocol fingerprints from session payloads.

    Returns dict matching dfi.fingerprints columns, or None if no parseable payload.
    """
    fp = {
        'flow_id': session.flow_id,
        'src_ip': session.src_ip,
        'dst_ip': session.dst_ip,
        'dst_port': session.dst_port,
        'first_ts': session.first_ts,
    }

    # Get first forward and reverse payloads from events
    first_fwd_payload = None
    first_rev_payload = None
    for e in session.events:
        if e.direction == 1 and e.payload_len > 0 and first_fwd_payload is None:
            first_fwd_payload = e.payload_head[:e.payload_len]
        elif e.direction == -1 and e.payload_len > 0 and first_rev_payload is None:
            first_rev_payload = e.payload_head[:e.payload_len]
        if first_fwd_payload and first_rev_payload:
            break

    if first_fwd_payload is None and first_rev_payload is None:
        return None  # No payload at all — no fingerprint possible

    # Try each protocol parser
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

        dns = parse_dns_query(first_fwd_payload)
        if dns:
            fp.update(dns)
            parsed = True

    # SSH: check both directions for banner, fwd for KEXINIT
    ssh = parse_ssh(session.events)
    if ssh:
        fp.update(ssh)
        parsed = True

    # HTTP status from first reverse payload
    if first_rev_payload:
        status = parse_http_status(first_rev_payload)
        if status:
            fp['http_status'] = status

    return fp if parsed else None
```

---

## Step 2: TLS ClientHello Parser

Parse raw TLS ClientHello to extract JA3 hash, cipher/extension counts, SNI, and version.

```python
def parse_tls_client_hello(payload: bytes) -> Optional[dict]:
    """Parse TLS ClientHello from raw payload.

    TLS record: content_type=0x16 (handshake), then version, length
    Handshake: type=0x01 (ClientHello), then length, version, random, session_id,
               cipher_suites, compression, extensions
    """
    if len(payload) < 6:
        return None

    # Check for TLS handshake record
    if payload[0] != 0x16:  # content_type = Handshake
        return None

    # Record header: type(1) + version(2) + length(2)
    rec_len = struct.unpack('!H', payload[3:5])[0]

    # Handshake header
    if len(payload) < 9:
        return None
    if payload[5] != 0x01:  # handshake_type = ClientHello
        return None

    # Parse ClientHello body
    pos = 9  # skip record header(5) + handshake header(4)
    if len(payload) < pos + 2:
        return None

    # Client version
    client_version = struct.unpack('!H', payload[pos:pos+2])[0]
    pos += 2

    # Map TLS version
    version_map = {0x0300: 10, 0x0301: 11, 0x0302: 11, 0x0303: 12}
    tls_version = version_map.get(client_version, 0)

    # Random (32 bytes)
    pos += 32
    if pos >= len(payload):
        return None

    # Session ID
    sid_len = payload[pos]
    pos += 1 + sid_len
    if pos + 2 > len(payload):
        return None

    # Cipher suites
    cs_len = struct.unpack('!H', payload[pos:pos+2])[0]
    pos += 2
    if pos + cs_len > len(payload):
        return None
    cipher_suites = []
    for i in range(0, cs_len, 2):
        if pos + i + 2 <= len(payload):
            cs = struct.unpack('!H', payload[pos+i:pos+i+2])[0]
            # Exclude GREASE values (0x0a0a, 0x1a1a, ... 0xfafa)
            if (cs & 0x0f0f) != 0x0a0a:
                cipher_suites.append(cs)
    pos += cs_len

    # Compression methods
    if pos >= len(payload):
        return None
    comp_len = payload[pos]
    pos += 1 + comp_len

    # Extensions
    extensions = []
    sni = None
    supported_versions = []

    if pos + 2 <= len(payload):
        ext_total_len = struct.unpack('!H', payload[pos:pos+2])[0]
        pos += 2
        ext_end = pos + ext_total_len

        while pos + 4 <= min(ext_end, len(payload)):
            ext_type = struct.unpack('!H', payload[pos:pos+2])[0]
            ext_len = struct.unpack('!H', payload[pos+2:pos+4])[0]
            ext_data = payload[pos+4:pos+4+ext_len]

            # Exclude GREASE extension types
            if (ext_type & 0x0f0f) != 0x0a0a:
                extensions.append(ext_type)

            # SNI (type 0x0000)
            if ext_type == 0x0000 and len(ext_data) >= 5:
                sni_list_len = struct.unpack('!H', ext_data[0:2])[0]
                if ext_data[2] == 0x00:  # host_name type
                    name_len = struct.unpack('!H', ext_data[3:5])[0]
                    if 5 + name_len <= len(ext_data):
                        sni = ext_data[5:5+name_len].decode('ascii', errors='ignore')

            # Supported versions (type 0x002b)
            if ext_type == 0x002b and len(ext_data) >= 1:
                sv_len = ext_data[0]
                for i in range(1, min(sv_len + 1, len(ext_data)), 2):
                    if i + 2 <= len(ext_data):
                        v = struct.unpack('!H', ext_data[i:i+2])[0]
                        if (v & 0x0f0f) != 0x0a0a:
                            supported_versions.append(v)

            pos += 4 + ext_len

    # Compute JA3
    # Format: TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
    # We use cipher_suites and extensions lists
    ja3_str = f"{client_version}," \
              f"{'-'.join(str(c) for c in cipher_suites)}," \
              f"{'-'.join(str(e) for e in extensions)}," \
              f"," # elliptic curves + point formats simplified
    ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()

    # Check supported_versions for TLS 1.3
    if 0x0304 in supported_versions:
        tls_version = 13

    return {
        'ja3_hash': ja3_hash,
        'tls_version': tls_version,
        'tls_cipher_count': len(cipher_suites),
        'tls_ext_count': len(extensions),
        'tls_has_sni': 1 if sni else 0,
    }
```

**Note on JA3 completeness:** A production JA3 includes elliptic curves and point format extensions. The parser above extracts them from extension data — extend the KEXINIT parsing to pull `supported_groups` (ext 0x000a) and `ec_point_formats` (ext 0x000b) for the full JA3 string:

```python
# Inside the extension loop, add:
elliptic_curves = []
ec_point_formats = []

if ext_type == 0x000a and len(ext_data) >= 2:  # supported_groups
    sg_len = struct.unpack('!H', ext_data[0:2])[0]
    for i in range(2, min(sg_len + 2, len(ext_data)), 2):
        if i + 2 <= len(ext_data):
            g = struct.unpack('!H', ext_data[i:i+2])[0]
            if (g & 0x0f0f) != 0x0a0a:
                elliptic_curves.append(g)

if ext_type == 0x000b and len(ext_data) >= 1:  # ec_point_formats
    epf_len = ext_data[0]
    for i in range(1, min(epf_len + 1, len(ext_data))):
        ec_point_formats.append(ext_data[i])

# Full JA3 string:
ja3_str = f"{client_version}," \
          f"{'-'.join(str(c) for c in cipher_suites)}," \
          f"{'-'.join(str(e) for e in extensions)}," \
          f"{'-'.join(str(c) for c in elliptic_curves)}," \
          f"{'-'.join(str(f) for f in ec_point_formats)}"
```

---

## Step 3: SSH Parser (Banner + KEXINIT)

```python
def parse_ssh(events: list) -> Optional[dict]:
    """Parse SSH banner and KEXINIT from session events.

    SSH banner: 'SSH-2.0-...' in first payload (either direction)
    KEXINIT: binary packet with msg_type=20 in forward payload
    """
    banner_found = False
    kex_algorithms = []

    for e in events:
        if e.payload_len == 0:
            continue
        data = e.payload_head[:e.payload_len]

        # Check for SSH banner
        if data[:4] == b'SSH-':
            banner_found = True
            continue

        # Check for KEXINIT (msg_type=20)
        # SSH binary packet: packet_length(4) + padding_length(1) + payload
        # KEXINIT payload starts with msg_type=20
        if len(data) >= 6 and e.direction == 1:
            # Try parsing as SSH binary packet
            try:
                pkt_len = struct.unpack('!I', data[0:4])[0]
                pad_len = data[4]
                if 5 + pkt_len <= len(data) + 64 and data[5] == 20:  # SSH_MSG_KEXINIT
                    kex_algorithms = _parse_kexinit(data[5:])
            except (struct.error, IndexError):
                pass

    if not banner_found:
        return None

    # Compute HASSH: MD5(kex_algorithms;encryption_algorithms;mac_algorithms;compression_algorithms)
    # kex_algorithms list from KEXINIT contains 4 name-lists concatenated
    hassh_hash = None
    if kex_algorithms:
        hassh_str = ';'.join(kex_algorithms[:4])  # first 4 algorithm lists
        hassh_hash = hashlib.md5(hassh_str.encode()).hexdigest()

    return {
        'hassh_hash': hassh_hash,
        'ssh_kex_count': len(kex_algorithms[0].split(',')) if kex_algorithms else 0,
    }


def _parse_kexinit(data: bytes) -> list:
    """Parse SSH KEXINIT payload. Returns list of algorithm name-list strings.

    Format after msg_type(1):
      cookie(16 bytes)
      then 10 name-lists, each: length(4) + utf8 string
    We need the first 4: kex_algorithms, server_host_key_algorithms,
      encryption_algorithms_client_to_server, mac_algorithms_client_to_server
    """
    pos = 17  # skip msg_type(1) + cookie(16)
    name_lists = []

    for _ in range(10):
        if pos + 4 > len(data):
            break
        nl_len = struct.unpack('!I', data[pos:pos+4])[0]
        pos += 4
        if pos + nl_len > len(data):
            break
        nl_str = data[pos:pos+nl_len].decode('ascii', errors='ignore')
        name_lists.append(nl_str)
        pos += nl_len

    return name_lists
```

---

## Step 4: HTTP Request Parser

```python
def parse_http_request(payload: bytes) -> Optional[dict]:
    """Parse HTTP request line and headers.

    Detects HTTP by checking first bytes for method keyword.
    """
    METHODS = {
        b'GET': 1, b'POST': 2, b'HEAD': 3, b'PUT': 4,
        b'DELETE': 5, b'OPTIONS': 5, b'PATCH': 5, b'CONNECT': 5,
    }

    # Find method
    method_code = 0
    for method_bytes, code in METHODS.items():
        if payload[:len(method_bytes)] == method_bytes:
            method_code = code
            break

    if method_code == 0:
        return None

    try:
        # Split into lines
        text = payload.decode('ascii', errors='ignore')
        lines = text.split('\r\n')
        if not lines:
            return None

        # Request line: METHOD URI HTTP/1.x
        request_line = lines[0]
        parts = request_line.split(' ', 2)
        uri = parts[1] if len(parts) >= 2 else ''

        # Count headers (lines between request line and empty line)
        header_count = 0
        ua_value = None
        has_body = 0

        for line in lines[1:]:
            if line == '':
                # Check if there's body after headers
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
                    cl = int(line.split(':', 1)[1].strip())
                    if cl > 0:
                        has_body = 1
                except ValueError:
                    pass

        # Hash UA for frequency encoding
        ua_hash = None
        if ua_value:
            ua_hash = hashlib.md5(ua_value.encode()).hexdigest()

        return {
            'http_method': method_code,
            'http_uri_len': len(uri),
            'http_header_count': header_count,
            'http_ua_hash': ua_hash,
            'http_has_body': has_body,
        }
    except Exception:
        return None


def parse_http_status(payload: bytes) -> Optional[int]:
    """Parse HTTP response status code from first reverse payload."""
    try:
        text = payload[:32].decode('ascii', errors='ignore')
        if text.startswith('HTTP/'):
            parts = text.split(' ', 2)
            if len(parts) >= 2:
                return int(parts[1])
    except (ValueError, IndexError):
        pass
    return None
```

---

## Step 5: DNS Query Parser

```python
def parse_dns_query(payload: bytes) -> Optional[dict]:
    """Parse DNS query from UDP payload.

    DNS header: ID(2) + Flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2) = 12 bytes
    Question: QNAME(variable) + QTYPE(2) + QCLASS(2)
    """
    if len(payload) < 17:  # minimum: 12 header + 1 label + 2 qtype + 2 qclass
        return None

    # Check flags: QR bit = 0 (query), OPCODE = 0 (standard query)
    flags = struct.unpack('!H', payload[2:4])[0]
    if flags & 0x8000:  # QR bit set = response, not query
        return None

    qdcount = struct.unpack('!H', payload[4:6])[0]
    if qdcount == 0:
        return None

    # Parse QNAME (sequence of labels)
    pos = 12
    qname_parts = []
    while pos < len(payload):
        label_len = payload[pos]
        if label_len == 0:
            pos += 1
            break
        if label_len > 63:  # compression pointer or invalid
            return None
        pos += 1
        if pos + label_len > len(payload):
            return None
        qname_parts.append(payload[pos:pos+label_len].decode('ascii', errors='ignore'))
        pos += label_len

    qname = '.'.join(qname_parts)

    if pos + 4 > len(payload):
        return None

    qtype = struct.unpack('!H', payload[pos:pos+2])[0]

    return {
        'dns_qtype': min(qtype, 255),  # cap at uint8
        'dns_qname_len': len(qname),
    }
```

---

## Step 6: Integration — Modify hunter.py flush path

In `flush_session()` (or `flush_ready()`), after feature extraction:

```python
from .fingerprints import extract_fingerprint

def flush_session(session):
    features = extract_features(session)
    rtt_ms = features.get('rtt_ms')
    pkt_tokens = tokenize_packets(session.events, rtt_ms)

    # NEW: Extract fingerprint
    fp = extract_fingerprint(session)

    fanout = build_fanout_hop(session, features)
    writer.insert_flow(features, pkt_tokens, fp, fanout, session.capture_depth)
```

The `DFIWriter.insert_flow()` already accepts an `fp` parameter. When `fp` is not None, it writes to `dfi.fingerprints_buffer`. Verify that writer.py handles the dict-to-row mapping:

```python
# In writer.py insert_flow():
if fp is not None and depth >= 1:  # D1 and above get fingerprints
    self._fp_buf.append(fp)
```

---

## Step 7: Frequency Encoding (Query-Time on PV1)

The `ja3_freq`, `hassh_freq`, and `http_ua_freq` columns in the XGBoost/CNN export are NOT stored in the fingerprints table. They are computed at query time from the materialized views already created in Phase 1:

- `dfi.mv_ja3_freq` → counts per `ja3_hash`
- `dfi.mv_hassh_freq` → counts per `hassh_hash`
- `dfi.mv_ua_freq` → counts per `http_ua_hash`

These feed into the `dfi.v_xgb` export view via LEFT JOINs (already defined in `04_views.sql`). No additional code needed for frequency encoding.

---

## Verification

1. **TLS fingerprint:**
   ```bash
   # Generate TLS traffic to honeypot
   # (will happen naturally from attackers, or test with: curl -k https://honeypot_ip)

   clickhouse-client --query "
       SELECT ja3_hash, tls_version, tls_cipher_count, tls_ext_count, tls_has_sni
       FROM dfi.fingerprints
       WHERE ja3_hash IS NOT NULL
       LIMIT 5
   "
   ```

2. **SSH fingerprint:**
   ```bash
   clickhouse-client --query "
       SELECT hassh_hash, ssh_kex_count
       FROM dfi.fingerprints
       WHERE hassh_hash IS NOT NULL
       LIMIT 5
   "
   ```

3. **HTTP fingerprint:**
   ```bash
   clickhouse-client --query "
       SELECT http_method, http_uri_len, http_header_count, http_ua_hash, http_has_body, http_status
       FROM dfi.fingerprints
       WHERE http_method > 0
       LIMIT 5
   "
   ```

4. **DNS fingerprint:**
   ```bash
   clickhouse-client --query "
       SELECT dns_qtype, dns_qname_len
       FROM dfi.fingerprints
       WHERE dns_qtype > 0
       LIMIT 5
   "
   ```

5. **Coverage check:**
   ```bash
   clickhouse-client --query "
       SELECT
           count() AS total_flows,
           countIf(ja3_hash IS NOT NULL) AS tls_flows,
           countIf(hassh_hash IS NOT NULL) AS ssh_flows,
           countIf(http_method > 0) AS http_flows,
           countIf(dns_qtype > 0) AS dns_flows
       FROM dfi.fingerprints
   "
   ```

6. **Frequency encoding:**
   ```bash
   clickhouse-client --query "
       SELECT hash_value, countMerge(freq) as freq
       FROM dfi.fingerprint_freq
       WHERE field = 'ja3'
       GROUP BY hash_value
       ORDER BY freq DESC
       LIMIT 10
   "
   ```

---

## Acceptance Criteria

- [ ] `fingerprints.py` parses TLS ClientHello → ja3_hash, tls_version, tls_cipher_count, tls_ext_count, tls_has_sni
- [ ] `fingerprints.py` parses SSH banner + KEXINIT → hassh_hash, ssh_kex_count
- [ ] `fingerprints.py` parses HTTP request → http_method, http_uri_len, http_header_count, http_ua_hash, http_has_body
- [ ] `fingerprints.py` parses HTTP response → http_status
- [ ] `fingerprints.py` parses DNS query → dns_qtype, dns_qname_len
- [ ] JA3 hash matches known JA3 databases for common tools (curl, Chrome, etc.)
- [ ] HASSH hash matches known HASSH databases for common SSH clients (OpenSSH, Paramiko)
- [ ] fingerprints_buffer populating in ClickHouse
- [ ] Materialized views accumulating frequency counts
- [ ] No performance regression (fingerprint extraction is NOT in the packet hot path — only on session flush)
- [ ] Graceful handling of malformed/truncated payloads (no crashes, returns None)
- [ ] GREASE values excluded from JA3 cipher/extension lists

## Important Notes

- **Fingerprint extraction happens at session flush, NOT per-packet.** It reads from `session.events[].payload_head` which is already captured. Zero impact on ingest hot path.
- **payload_head must be at least 256 bytes.** Verify that PacketEvent captures enough for ClientHello parsing. Most ClientHellos are 200-500 bytes. If truncated, the parser returns partial results (hash may differ from tools that see full payload).
- **GREASE filtering is critical for JA3 stability.** Chrome randomizes GREASE values per connection. Excluding them makes the JA3 hash consistent for the same client version.
- **DNS parsing assumes UDP.** For TCP DNS (rare), the payload has a 2-byte length prefix — handle by checking `ip_proto == 17` before calling `parse_dns_query()`, or strip the 2-byte prefix for TCP.
