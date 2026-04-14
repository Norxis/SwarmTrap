CREATE TABLE IF NOT EXISTS dfi.flows_buffer AS dfi.flows
ENGINE = Buffer(dfi, flows,
    16, 5, 30, 10000, 100000, 10000000, 100000000);

CREATE TABLE IF NOT EXISTS dfi.packets_buffer AS dfi.packets
ENGINE = Buffer(dfi, packets,
    16, 2, 10, 100000, 1000000, 50000000, 500000000);

CREATE TABLE IF NOT EXISTS dfi.fingerprints_buffer AS dfi.fingerprints
ENGINE = Buffer(dfi, fingerprints,
    8, 5, 30, 10000, 100000, 10000000, 100000000);

CREATE TABLE IF NOT EXISTS dfi.evidence_events_buffer AS dfi.evidence_events
ENGINE = Buffer(dfi, evidence_events,
    8, 5, 30, 1000, 50000, 5000000, 50000000);

CREATE TABLE IF NOT EXISTS dfi.fanout_hops_buffer AS dfi.fanout_hops
ENGINE = Buffer(dfi, fanout_hops,
    16, 5, 30, 10000, 100000, 10000000, 100000000);

CREATE TABLE IF NOT EXISTS dfi.model_predictions_buffer AS dfi.model_predictions
ENGINE = Buffer(dfi, model_predictions,
    8, 5, 30, 10000, 100000, 10000000, 100000000);

CREATE TABLE IF NOT EXISTS dfi.payload_bytes_buffer AS dfi.payload_bytes
ENGINE = Buffer(dfi, payload_bytes,
    8, 5, 30, 10000, 100000, 10000000, 100000000);
