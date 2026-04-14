"""Unit tests for fingerprint extraction."""
from __future__ import annotations

import struct
import unittest

from dfi_agent.fingerprints import (
    FingerprintState,
    extract_http_request,
    extract_http_response,
    extract_tls_fingerprint,
    update_fingerprint,
)


def _build_client_hello() -> bytes:
    """Build a minimal TLS ClientHello for testing."""
    # TLS record header
    record = bytearray()
    record.append(0x16)           # Content type: Handshake
    record.extend(b"\x03\x01")    # Record version: TLS 1.0
    record.extend(b"\x00\x00")    # Record length (placeholder)

    # Handshake: ClientHello
    record.append(0x01)           # Handshake type
    record.extend(b"\x00\x00\x00")  # Handshake length (placeholder)
    record.extend(b"\x03\x03")   # Client version: TLS 1.2
    record.extend(b"\x00" * 32)  # Random
    record.append(0)             # Session ID length: 0

    # Cipher suites: 2 ciphers (4 bytes each = 8 bytes total)
    record.extend(struct.pack("!H", 4))  # CS length
    record.extend(struct.pack("!H", 0x1301))  # TLS_AES_128_GCM
    record.extend(struct.pack("!H", 0x1302))  # TLS_AES_256_GCM

    # Compression: 1 method (null)
    record.append(1)
    record.append(0)

    # Extensions
    ext_block = bytearray()
    # SNI extension (type 0)
    sni_data = b"\x00\x07\x00\x00\x04test"
    ext_block.extend(struct.pack("!HH", 0, len(sni_data)))
    ext_block.extend(sni_data)

    record.extend(struct.pack("!H", len(ext_block)))
    record.extend(ext_block)

    # Fix lengths — set 3-byte handshake length at offsets 6-8
    # (byte 5 is handshake type 0x01, must NOT be overwritten)
    hs_len = len(record) - 9  # after handshake header
    record[6] = (hs_len >> 16) & 0xFF
    record[7] = (hs_len >> 8) & 0xFF
    record[8] = hs_len & 0xFF
    rec_len = len(record) - 5
    struct.pack_into("!H", record, 3, rec_len)

    return bytes(record)


class TestTLSFingerprint(unittest.TestCase):
    def test_basic_client_hello(self):
        fp = FingerprintState()
        payload = _build_client_hello()
        extract_tls_fingerprint(payload, fp)
        self.assertTrue(fp._tls_extracted)
        self.assertIsNotNone(fp.ja3_hash)
        self.assertEqual(fp.tls_cipher_count, 2)
        self.assertEqual(fp.tls_has_sni, 1)
        self.assertGreater(fp.tls_ext_count, 0)

    def test_not_tls(self):
        fp = FingerprintState()
        extract_tls_fingerprint(b"GET / HTTP/1.1\r\n", fp)
        self.assertFalse(fp._tls_extracted)

    def test_no_re_extract(self):
        fp = FingerprintState()
        fp._tls_extracted = True
        extract_tls_fingerprint(_build_client_hello(), fp)
        self.assertIsNone(fp.ja3_hash)  # Not overwritten


class TestHTTPFingerprint(unittest.TestCase):
    def test_get_request(self):
        fp = FingerprintState()
        payload = b"GET /login HTTP/1.1\r\nHost: test\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        extract_http_request(payload, fp)
        self.assertTrue(fp._http_req_extracted)
        self.assertEqual(fp.http_method, 1)  # GET
        self.assertGreater(fp.http_uri_len, 0)
        self.assertIsNotNone(fp.http_ua_hash)
        self.assertGreater(fp.http_header_count, 0)

    def test_post_with_body(self):
        fp = FingerprintState()
        payload = b"POST /api HTTP/1.1\r\nContent-Length: 10\r\n\r\n0123456789"
        extract_http_request(payload, fp)
        self.assertEqual(fp.http_method, 2)  # POST
        self.assertEqual(fp.http_has_body, 1)

    def test_response(self):
        fp = FingerprintState()
        payload = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"
        extract_http_response(payload, fp)
        self.assertTrue(fp._http_resp_extracted)
        self.assertEqual(fp.http_status, 401)


class TestUpdateFingerprint(unittest.TestCase):
    def test_forward_tls(self):
        fp = FingerprintState()
        payload = _build_client_hello()
        update_fingerprint(fp, dst_port=443, src_port=12345, payload=payload, direction=1)
        self.assertTrue(fp._tls_extracted)

    def test_forward_http(self):
        fp = FingerprintState()
        update_fingerprint(fp, dst_port=80, src_port=12345,
                           payload=b"GET / HTTP/1.1\r\nHost: test\r\n\r\n", direction=1)
        self.assertEqual(fp.http_method, 1)

    def test_reverse_http_response(self):
        fp = FingerprintState()
        update_fingerprint(fp, dst_port=80, src_port=12345,
                           payload=b"HTTP/1.1 200 OK\r\n\r\n", direction=-1)
        self.assertEqual(fp.http_status, 200)


if __name__ == "__main__":
    unittest.main()
