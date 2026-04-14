#!/usr/bin/env python3
"""Capture depth filtering logic."""

D0_DROP = 0
D1_FLOW = 1
D2_SEQUENCE = 2
D3_FULL = 3

DEFAULT_DEPTH = D2_SEQUENCE


def get_capture_depth(watchlist_entry: dict) -> int:
    if watchlist_entry is None:
        return DEFAULT_DEPTH
    try:
        return int(watchlist_entry.get('capture_depth', DEFAULT_DEPTH))
    except Exception:
        return DEFAULT_DEPTH


def check_d0_repromotion(dst_port: int, watchlist_entry: dict) -> bool:
    top_port = watchlist_entry.get('top_port')
    if top_port is None:
        return False
    return int(dst_port) != int(top_port)


def should_write_flow(depth: int) -> bool:
    return depth >= D1_FLOW


def should_write_fingerprint(depth: int) -> bool:
    return depth >= D1_FLOW


def should_write_fanout(depth: int) -> bool:
    return depth >= D1_FLOW


def should_write_packets(depth: int) -> bool:
    return depth >= D2_SEQUENCE


def should_write_payload(depth: int) -> bool:
    return depth >= D3_FULL
