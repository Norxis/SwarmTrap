#!/usr/bin/env python3
"""
cnn_server.py — CNN batch inference server for BF2 Pre-Processor.

Receives FlowRecords from ARM via TCP socket, batches them,
runs CNN inference (shared backbone + per-service heads),
returns CNNResults to ARM.

This replaces the inline CNN scorer in hunter2.

Protocol:
  ARM → Host: 4-byte length prefix + FlowRecord (packed struct)
  Host → ARM: 4-byte length prefix + CNNResult (packed struct)

Usage:
    python3 cnn_server.py [--port 9300] [--model /path/to/cnn.pt]
"""

import argparse
import logging
import os
import socket
import struct
import sys
import time
import threading
from collections import deque

import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger('cnn_server')

# FlowRecord struct layout (must match flowrecord.h)
# flow_id[16] + src_ip(u32) + dst_ip(u32) + dst_port(u16) + service_id(u8) + ip_proto(u8)
# + xgb_class(u8) + xgb_confidence(f32) + xgb_probs[6](f32×6)
# + size_dir[128](i8) + flags[128](u8) + iat_log[128](u8) + iat_rtt[128](u8) + entropy[128](u8)
# + static_features[42](f32×42)
# + packets_seen(u16) + flow_duration_ms(u32) + timestamp(u64) + capture_depth(u8)
FLOWRECORD_SIZE = (16 + 4 + 4 + 2 + 1 + 1 +
                    1 + 4 + 6*4 +
                    128*5 +
                    42*4 +
                    2 + 4 + 8 + 1)  # = 893 bytes

# CNNResult struct
# flow_id[16] + cnn_class(u8) + cnn_confidence(f32) + cnn_probs[6](f32×6)
CNNRESULT_SIZE = 16 + 1 + 4 + 6*4  # = 45 bytes

# Batch configuration
BATCH_TIMEOUT_MS = 100  # Max wait before processing partial batch
MAX_BATCH_SIZE = 256


def parse_flowrecord(data):
    """Parse packed FlowRecord bytes into dict."""
    offset = 0
    flow_id = data[offset:offset+16]
    offset += 16

    src_ip, dst_ip = struct.unpack_from('<II', data, offset)
    offset += 8

    dst_port, service_id, ip_proto = struct.unpack_from('<HBB', data, offset)
    offset += 4

    xgb_class = data[offset]; offset += 1
    xgb_confidence = struct.unpack_from('<f', data, offset)[0]; offset += 4
    xgb_probs = struct.unpack_from('<6f', data, offset); offset += 24

    # Token sequences (5 channels × 128)
    size_dir = np.frombuffer(data, dtype=np.int8, count=128, offset=offset)
    offset += 128
    tcp_flags = np.frombuffer(data, dtype=np.uint8, count=128, offset=offset)
    offset += 128
    iat_log = np.frombuffer(data, dtype=np.uint8, count=128, offset=offset)
    offset += 128
    iat_rtt = np.frombuffer(data, dtype=np.uint8, count=128, offset=offset)
    offset += 128
    entropy = np.frombuffer(data, dtype=np.uint8, count=128, offset=offset)
    offset += 128

    # Static features (42 × float32)
    static_feats = np.frombuffer(data, dtype=np.float32, count=42, offset=offset)
    offset += 42 * 4

    packets_seen = struct.unpack_from('<H', data, offset)[0]; offset += 2
    flow_duration_ms = struct.unpack_from('<I', data, offset)[0]; offset += 4
    timestamp = struct.unpack_from('<Q', data, offset)[0]; offset += 8
    capture_depth = data[offset]; offset += 1

    return {
        'flow_id': flow_id,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'dst_port': dst_port,
        'service_id': service_id,
        'xgb_class': xgb_class,
        'xgb_confidence': xgb_confidence,
        'size_dir': size_dir.copy(),
        'tcp_flags': tcp_flags.copy(),
        'iat_log': iat_log.copy(),
        'iat_rtt': iat_rtt.copy(),
        'entropy': entropy.copy(),
        'static_features': static_feats.copy(),
    }


def build_cnn_result(flow_id, cnn_class, cnn_confidence, probs):
    """Pack CNNResult into bytes."""
    result = bytearray(CNNRESULT_SIZE)
    result[0:16] = flow_id
    result[16] = cnn_class
    struct.pack_into('<f', result, 17, cnn_confidence)
    for i, p in enumerate(probs[:6]):
        struct.pack_into('<f', result, 21 + i*4, float(p))
    return bytes(result)


class CNNInferenceServer:
    """TCP server that receives FlowRecords and returns CNN predictions."""

    def __init__(self, port=9300, model_path=None):
        self.port = port
        self.model = None
        self.model_path = model_path
        self.stats = {
            'flows_received': 0,
            'batches_processed': 0,
            'results_sent': 0,
        }

        if model_path and os.path.exists(model_path):
            self._load_model(model_path)
        else:
            log.warning("No CNN model — returning XGB predictions as fallback")

    def _load_model(self, path):
        """Load PyTorch CNN model."""
        try:
            import torch
            self.model = torch.jit.load(path) if path.endswith('.pt') else None
            if self.model:
                self.model.eval()
                log.info("CNN model loaded from %s", path)
        except Exception as e:
            log.warning("Cannot load CNN model: %s", e)
            self.model = None

    def _infer_batch(self, records):
        """Run CNN inference on a batch of FlowRecords."""
        results = []

        if self.model is None:
            # Fallback: echo XGB predictions as CNN results
            for rec in records:
                results.append(build_cnn_result(
                    rec['flow_id'],
                    rec['xgb_class'],
                    rec['xgb_confidence'],
                    [0.0] * 6
                ))
            return results

        # TODO: Batch inference with actual CNN model
        # 1. Stack token sequences into batch tensors
        # 2. Run model forward pass
        # 3. Extract per-flow predictions
        # For now, return XGB fallback
        for rec in records:
            results.append(build_cnn_result(
                rec['flow_id'],
                rec['xgb_class'],
                rec['xgb_confidence'],
                [0.0] * 6
            ))
        return results

    def _handle_client(self, conn, addr):
        """Handle a single ARM connection."""
        log.info("ARM connected from %s", addr)
        batch = []
        last_batch_time = time.time()

        try:
            while True:
                # Read 4-byte length prefix
                len_data = b''
                while len(len_data) < 4:
                    chunk = conn.recv(4 - len(len_data))
                    if not chunk:
                        return  # connection closed
                    len_data += chunk

                msg_len = struct.unpack('<I', len_data)[0]
                if msg_len != FLOWRECORD_SIZE:
                    log.warning("Bad message length: %d (expected %d)", msg_len, FLOWRECORD_SIZE)
                    continue

                # Read FlowRecord
                data = b''
                while len(data) < msg_len:
                    chunk = conn.recv(msg_len - len(data))
                    if not chunk:
                        return
                    data += chunk

                record = parse_flowrecord(data)
                batch.append(record)
                self.stats['flows_received'] += 1

                # Process batch when full or timeout
                now = time.time()
                if len(batch) >= MAX_BATCH_SIZE or \
                   (now - last_batch_time) * 1000 >= BATCH_TIMEOUT_MS:

                    results = self._infer_batch(batch)
                    self.stats['batches_processed'] += 1

                    # Send results back
                    for r in results:
                        conn.sendall(struct.pack('<I', len(r)) + r)
                        self.stats['results_sent'] += 1

                    batch.clear()
                    last_batch_time = now

        except Exception as e:
            log.error("Client error: %s", e)
        finally:
            if batch:
                # Flush remaining
                results = self._infer_batch(batch)
                for r in results:
                    try:
                        conn.sendall(struct.pack('<I', len(r)) + r)
                    except:
                        break
            conn.close()
            log.info("ARM disconnected. Stats: %s", self.stats)

    def run(self):
        """Start TCP server."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('0.0.0.0', self.port))
        srv.listen(4)
        log.info("CNN inference server listening on :%d", self.port)

        while True:
            conn, addr = srv.accept()
            t = threading.Thread(target=self._handle_client, args=(conn, addr),
                                  daemon=True)
            t.start()


def main():
    parser = argparse.ArgumentParser(description='CNN Inference Server')
    parser.add_argument('--port', type=int, default=9300)
    parser.add_argument('--model', default='')
    args = parser.parse_args()

    server = CNNInferenceServer(port=args.port, model_path=args.model)
    server.run()


if __name__ == '__main__':
    main()
