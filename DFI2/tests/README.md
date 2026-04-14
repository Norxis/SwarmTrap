# DFI2 Tests

Unit tests for the SwarmTrap DFI2 pipeline components. All tests use Python's built-in `unittest` framework and can run without network access or external services.

## Running Tests

```bash
# Run all tests from the project root
python -m pytest DFI2/tests/

# Or run individual test files
python -m unittest DFI2/tests/test_features.py
python -m unittest DFI2/tests/test_backend_api_service.py
python -m unittest DFI2/tests/test_fingerprints.py
python -m unittest DFI2/tests/test_tokenizer.py
```

## Test Files

### `test_features.py`

Tests the `hunter.features.extract_features()` function, which converts raw flow session objects into the numeric feature vectors used by the XGBoost classifier.

- **`test_udp_no_payload`** -- verifies feature extraction for a minimal UDP flow (no payload, no TCP state). Checks that `ip_proto=17`, `conn_state=7` (UDP default), `rtt_ms=None`, and `payload_len_first=0`.
- **`test_tcp_with_rtt_and_entropy`** -- verifies feature extraction for a TCP flow with a SYN/SYN-ACK handshake and payload data. Checks RTT calculation from handshake timing, IAT-to-RTT ratio, and high-entropy fraction computation from payload entropy values.

### `test_backend_api_service.py`

Tests the `ControlPlaneService` business logic using in-memory fakes for SQLite and ClickHouse adapters. No real database connections are needed.

- **`test_upsert_idempotent_replay`** -- verifies that repeating an upsert with the same request ID and payload returns the cached response without creating duplicate audit log entries.
- **`test_upsert_rejects_changed_payload_on_same_key`** -- verifies that reusing an idempotency key with a different payload raises `ConflictError` (HTTP 409).
- **`test_never_demote_while_active`** -- verifies that attempting to lower capture depth on an IP with recent flow activity raises `PolicyError`, protecting active investigations.
- **`test_bulk_campaign_resolution`** -- verifies that `bulk_action` with a `campaign_id` resolves IPs from the campaign membership table and processes them all.
- **`test_annotate_idempotent`** -- verifies that annotation (analyst notes) follows the same idempotency contract as upserts.

### `test_fingerprints.py`

Tests the `hunter.fingerprints` module, which extracts protocol fingerprints from packet payloads.

- **`test_tls_parse`** -- parses a synthetic TLS ClientHello and verifies cipher count and JA3 hash generation.
- **`test_http_parse`** -- parses an HTTP GET request and verifies method detection, URI length extraction, and HTTP status code parsing.
- **`test_dns_parse`** -- parses a standard DNS A query and verifies query type and name length extraction.
- **`test_malformed_no_crash`** -- verifies that truncated/malformed payloads return `None` instead of raising exceptions, ensuring the pipeline never crashes on bad data.

### `test_tokenizer.py`

Tests the `hunter.tokenizer.tokenize_packets()` function, which converts raw packet event sequences into discrete token sequences for the CNN model.

- **`test_bins_and_ranges`** -- verifies that a 3-packet TCP sequence produces correct token ranges for size-direction tokens (-11 to 11), IAT log-ms bins (1-8), IAT-RTT bins (1-9), and entropy bins (1-6).
- **`test_rtt_unknown_uses_bin1`** -- verifies that when RTT is unknown (e.g., UDP), the IAT-RTT bin defaults to 1 and the flag token is set to 16 (non-TCP default).

## Test Architecture

All tests use `SimpleNamespace` objects to simulate flow sessions and packet events without requiring the full capture engine. The backend API tests use fake adapter classes (`FakeSQLite`, `FakeLedger`) that implement the same protocol interfaces as the real adapters, enabling pure unit testing of business logic.
