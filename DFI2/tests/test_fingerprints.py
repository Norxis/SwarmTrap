#!/usr/bin/env python3
import unittest
from types import SimpleNamespace

from hunter.fingerprints import (
    extract_fingerprint,
    parse_dns_query,
    parse_http_request,
    parse_http_status,
    parse_tls_client_hello,
)


def _mk_tls_client_hello():
    # Minimal synthetic TLS ClientHello (not complete real-world, but parser-compatible)
    record = bytearray()
    record += b'\x16\x03\x03\x00\x2f'          # TLS handshake record
    record += b'\x01\x00\x00\x2b'              # ClientHello, len=43
    record += b'\x03\x03'                        # client_version
    record += b'\x00' * 32                        # random
    record += b'\x00'                             # session id len
    record += b'\x00\x04'                        # cipher suites len
    record += b'\x13\x01\x13\x02'              # ciphers
    record += b'\x01\x00'                        # compression len + null
    record += b'\x00\x00'                        # extensions len
    return bytes(record)


class TestFingerprints(unittest.TestCase):
    def test_tls_parse(self):
        tls = parse_tls_client_hello(_mk_tls_client_hello())
        self.assertIsNotNone(tls)
        self.assertEqual(tls['tls_cipher_count'], 2)
        self.assertTrue(tls['ja3_hash'])

    def test_http_parse(self):
        req = (
            b'GET /admin/login HTTP/1.1\r\n'
            b'Host: test\r\n'
            b'User-Agent: curl/8.0\r\n'
            b'\r\n'
        )
        h = parse_http_request(req)
        self.assertIsNotNone(h)
        self.assertEqual(h['http_method'], 1)
        self.assertGreater(h['http_uri_len'], 0)
        self.assertEqual(parse_http_status(b'HTTP/1.1 404 Not Found\r\n'), 404)

    def test_dns_parse(self):
        # Standard query for a.com A
        payload = bytes.fromhex('123401000001000000000000016103636f6d0000010001')
        d = parse_dns_query(payload)
        self.assertIsNotNone(d)
        self.assertEqual(d['dns_qtype'], 1)
        self.assertEqual(d['dns_qname_len'], 5)

    def test_malformed_no_crash(self):
        self.assertIsNone(parse_tls_client_hello(b'\x16\x03'))
        s = SimpleNamespace(
            flow_id='f1',
            src_ip='1.2.3.4',
            dst_ip='5.6.7.8',
            dst_port=443,
            ip_proto=6,
            first_ts=1700000000.0,
            events=[SimpleNamespace(direction=1, payload_len=2, payload_head=b'\x16\x03')],
        )
        self.assertIsNone(extract_fingerprint(s))


if __name__ == '__main__':
    unittest.main()
