#!/usr/bin/env python3
"""Conversation assembler — groups flows into multi-turn conversations.

Runs on PV1 as cron. Queries dfi.flows, groups by src_ip with 30-minute gap
detection, computes 12-channel turn tokens and 42 static features, applies
4-tier heuristic labels, then writes to 3 tables:
  - dfi.conversations       (one row per conversation, 42 static features)
  - dfi.conversation_turns  (one row per turn, 12 channel tokens)
  - dfi.conversation_labels (one row per conversation, heuristic label)

Usage:
    python3 conversation_assembler.py                    # last 2 hours
    python3 conversation_assembler.py --hours 24         # last 24h
    python3 conversation_assembler.py --backfill         # all data
    python3 conversation_assembler.py --dry-run          # no writes, just stats
"""
import argparse
import hashlib
import logging
import math
import os
import time
from collections import defaultdict
from datetime import datetime, timedelta

from clickhouse_driver import Client

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
)
log = logging.getLogger(__name__)

CH_HOST = os.environ.get('CH_HOST', 'localhost')
CH_PORT = int(os.environ.get('CH_PORT', '9000'))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
GAP_THRESHOLD_MS = 30 * 60 * 1000          # 30 minutes in ms
MIN_FLOWS_PER_CONVERSATION = 2
MAX_TURNS = 256
TRUNCATE_KEEP = 128                         # keep first 128 + last 128
WRITE_BATCH = 10000
STALENESS_MS = 30 * 60 * 1000              # skip conversations still "open"

# ---------------------------------------------------------------------------
# Vocab mappings for 12-channel turn tokens
# ---------------------------------------------------------------------------

# ch_service_target (vocab 13): map (app_proto, dst_port) -> token
_SERVICE_PORT_MAP = {
    22: 1,      # SSH
    80: 2, 8080: 2,    # HTTP
    443: 3, 8443: 3,   # HTTPS
    53: 4,      # DNS
    25: 5,      # SMTP
    21: 6,      # FTP
    23: 7,      # Telnet
    3389: 8,    # RDP
    445: 9,     # SMB
    3306: 10, 1433: 10, 5432: 10, 6379: 10, 27017: 10,  # DB
    5900: 11,   # VNC
}


def _service_token(dst_port):
    """ch_service_target: vocab 13."""
    return _SERVICE_PORT_MAP.get(dst_port, 12)


def _flow_outcome_token(flow, pred):
    """ch_flow_outcome: vocab 11. Returns most specific match."""
    pkts_rev = flow['pkts_rev'] or 0
    conn_state = flow['conn_state'] or 0
    rst_count = flow['rst_count'] or 0
    fin_count = flow['fin_count'] or 0
    n_events = flow['n_events'] or 0
    bytes_total = (flow['bytes_fwd'] or 0) + (flow['bytes_rev'] or 0)

    xgb_label = pred.get('xgb_label')
    xgb_conf = pred.get('xgb_conf', 0)

    # 10: bulk-transfer
    if bytes_total > 100000:
        return 10
    # 9: extended-RST
    if n_events >= 10 and rst_count > 0:
        return 9
    # 8: extended-FIN
    if n_events >= 10 and fin_count > 0:
        return 8
    # 7: auth-success heuristic — extended session after brute prediction
    if (xgb_label in (2, 3) and xgb_conf > 0.7
            and n_events >= 10 and (flow['duration_ms'] or 0) > 30000):
        return 7
    # 6: auth-fail — brute/exploit predicted
    if xgb_label in (2, 3) and xgb_conf > 0.7:
        return 6
    # 5: short-exchange-FIN
    if 3 < n_events < 10 and fin_count > 0:
        return 5
    # 4: short-exchange-RST
    if 3 < n_events < 10 and rst_count > 0:
        return 4
    # 3: handshake-only
    if conn_state >= 1 and n_events <= 3 and bytes_total < 500:
        return 3
    # 2: SYN-RST
    if rst_count > 0 and n_events <= 4:
        return 2
    # 1: SYN-only
    if pkts_rev == 0 and conn_state == 0:
        return 1
    # fallback
    return 3


def _xgb_prediction_token(pred):
    """ch_xgb_prediction: vocab 6. 0=no pred, 1=RECON..5=COMPROMISE."""
    label = pred.get('xgb_label')
    if label is None:
        return 0
    # model_predictions label: 1=RECON,2=KNOCK,3=BRUTEFORCE,4=EXPLOIT,5=COMPROMISE
    return min(max(int(label), 0), 5)


def _confidence_token(conf):
    """Map confidence float to vocab 6 bucket."""
    if conf is None or conf <= 0:
        return 0
    if conf < 0.50:
        return 1
    if conf < 0.70:
        return 2
    if conf < 0.85:
        return 3
    if conf < 0.95:
        return 4
    return 5


def _xgb_confidence_token(pred):
    """ch_xgb_confidence: vocab 6."""
    if pred.get('xgb_label') is None:
        return 0
    return _confidence_token(pred.get('xgb_conf', 0))


def _cnn_prediction_token(pred):
    """ch_cnn_prediction: vocab 6."""
    label = pred.get('cnn_label')
    if label is None:
        return 0
    return min(max(int(label), 0), 5)


def _cnn_confidence_token(pred):
    """ch_cnn_confidence: vocab 6."""
    if pred.get('cnn_label') is None:
        return 0
    return _confidence_token(pred.get('cnn_conf', 0))


def _model_agreement_token(pred):
    """ch_model_agreement: vocab 6."""
    xgb_l = pred.get('xgb_label')
    cnn_l = pred.get('cnn_label')
    xgb_c = pred.get('xgb_conf', 0) or 0
    cnn_c = pred.get('cnn_conf', 0) or 0

    if xgb_l is None and cnn_l is None:
        return 0
    if xgb_l is None or cnn_l is None:
        return 5  # only one model available
    delta = abs(int(xgb_l) - int(cnn_l))
    if delta == 0:
        if xgb_c > 0.85 and cnn_c > 0.85:
            return 1  # agree, both high conf
        return 2      # agree, low conf
    if delta == 1:
        return 3      # disagree by 1 class
    return 4          # disagree by 2+ classes


def _duration_token(duration_ms):
    """ch_turn_duration: vocab 8."""
    if duration_ms is None:
        return 0
    d = duration_ms
    if d < 100:
        return 1
    if d < 1000:
        return 2
    if d < 10000:
        return 3
    if d < 60000:
        return 4
    if d < 300000:
        return 5
    if d < 1800000:
        return 6
    return 7


def _gap_token(gap_ms):
    """ch_inter_turn_gap: vocab 7. 0=first turn."""
    if gap_ms is None:
        return 0
    g = gap_ms
    if g < 100:
        return 1
    if g < 1000:
        return 2
    if g < 10000:
        return 3
    if g < 60000:
        return 4
    if g < 300000:
        return 5
    return 6


def _volume_token(total_bytes):
    """ch_data_volume: vocab 7."""
    if total_bytes is None or total_bytes <= 0:
        return 0
    b = total_bytes
    if b < 500:
        return 1
    if b < 5000:
        return 2
    if b < 50000:
        return 3
    if b < 500000:
        return 4
    if b < 5000000:
        return 5
    return 6


def _direction_token(bytes_fwd, bytes_rev):
    """ch_data_direction: vocab 5."""
    bf = bytes_fwd or 0
    br = bytes_rev or 0
    if bf == 0 and br == 0:
        return 0
    if br == 0:
        return 4  # attacker-only
    ratio = bf / br if br > 0 else float('inf')
    if ratio > 3:
        return 1   # attacker-dominated
    if ratio >= 0.33:
        return 2   # balanced
    return 3        # honeypot-dominated


def _port_novelty_token(dst_port, seen_ports):
    """ch_port_novelty: vocab 3. 1=first occurrence, 2=repeat."""
    if dst_port in seen_ports:
        return 2
    seen_ports.add(dst_port)
    return 1


# ---------------------------------------------------------------------------
# Static feature computation (42 features, C2-C8)
# ---------------------------------------------------------------------------

def _shannon_entropy(values):
    """Shannon entropy of a list of discrete values."""
    if not values:
        return 0.0
    total = len(values)
    freq = defaultdict(int)
    for v in values:
        freq[v] += 1
    ent = 0.0
    for count in freq.values():
        p = count / total
        if p > 0:
            ent -= p * math.log2(p)
    return ent


def _gini_coefficient(values):
    """Gini coefficient of a list of numeric values."""
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    total = sum(sorted_vals)
    if total == 0:
        return 0.0
    cumsum = 0.0
    weighted_sum = 0.0
    for i, v in enumerate(sorted_vals):
        cumsum += v
        weighted_sum += (2 * (i + 1) - n - 1) * v
    return weighted_sum / (n * total)


def _linear_slope(values):
    """Linear regression slope over index. Returns 0 if <2 values."""
    n = len(values)
    if n < 2:
        return 0.0
    x_mean = (n - 1) / 2.0
    y_mean = sum(values) / n
    num = 0.0
    den = 0.0
    for i, y in enumerate(values):
        dx = i - x_mean
        num += dx * (y - y_mean)
        den += dx * dx
    return num / den if den > 0 else 0.0


def _ts_to_epoch_ms(ts):
    """Convert datetime or numeric timestamp to epoch milliseconds."""
    if isinstance(ts, datetime):
        return int(ts.timestamp() * 1000)
    return int(ts)


def compute_static_features(flows, predictions, actor_stats):
    """Compute 42 static features (C2-C8) for a conversation.

    Args:
        flows: list of flow dicts sorted by first_ts
        predictions: dict flow_id -> {xgb_label, xgb_conf, cnn_label, cnn_conf}
        actor_stats: dict with actor-level aggregates for C8

    Returns:
        dict of 42 named features
    """
    n_turns = len(flows)
    feat = {}

    # Timestamps in ms
    ts_list = [_ts_to_epoch_ms(f['first_ts']) for f in flows]
    te_list = [_ts_to_epoch_ms(f['last_ts']) for f in flows]

    # ---- C2: Scale ----
    feat['n_turns'] = n_turns
    duration_total_ms = te_list[-1] - ts_list[0] if n_turns > 1 else 0
    feat['duration_total_min'] = duration_total_ms / 60000.0

    services = set()
    dst_ports = set()
    dst_ips = set()
    for f in flows:
        services.add(_service_token(f['dst_port']))
        dst_ports.add(f['dst_port'])
        dst_ips.add(f['dst_ip'])
    feat['unique_services'] = len(services)
    feat['unique_dst_ports'] = len(dst_ports)
    feat['unique_dst_ips'] = len(dst_ips)

    # concurrent_max: max overlapping flows at any point
    events = []
    for f in flows:
        s_ms = _ts_to_epoch_ms(f['first_ts'])
        e_ms = _ts_to_epoch_ms(f['last_ts'])
        events.append((s_ms, 1))
        events.append((e_ms, -1))
    events.sort(key=lambda x: (x[0], x[1]))
    concurrent = 0
    concurrent_max = 0
    for _, delta in events:
        concurrent += delta
        if concurrent > concurrent_max:
            concurrent_max = concurrent
    feat['concurrent_max'] = concurrent_max

    # ---- C3: Rhythm ----
    gaps_ms = []
    for i in range(1, n_turns):
        gap = ts_list[i] - te_list[i - 1]
        gaps_ms.append(max(gap, 0))
    gaps_s = [g / 1000.0 for g in gaps_ms]

    if gaps_s:
        gap_mean = sum(gaps_s) / len(gaps_s)
        gap_var = sum((g - gap_mean) ** 2 for g in gaps_s) / len(gaps_s)
        gap_std = math.sqrt(gap_var)
        sorted_gaps = sorted(gaps_s)
        mid = len(sorted_gaps) // 2
        gap_median = (sorted_gaps[mid] if len(sorted_gaps) % 2 == 1
                      else (sorted_gaps[mid - 1] + sorted_gaps[mid]) / 2)
    else:
        gap_mean = gap_std = gap_median = 0.0

    feat['gap_mean_s'] = gap_mean
    feat['gap_std_s'] = gap_std
    feat['gap_cv'] = gap_std / gap_mean if gap_mean > 0 else 0.0
    feat['gap_median_s'] = gap_median
    feat['gap_acceleration'] = _linear_slope(gaps_s) if len(gaps_s) >= 2 else 0.0

    # burst_count: gaps<1s followed by >10s
    burst_count = 0
    burst_sizes = []
    current_burst = 0
    for g in gaps_s:
        if g < 1.0:
            current_burst += 1
        else:
            if current_burst > 0 and g > 10.0:
                burst_count += 1
                burst_sizes.append(current_burst)
            current_burst = 0
    feat['burst_count'] = burst_count
    feat['burst_mean_size'] = (sum(burst_sizes) / len(burst_sizes)
                               if burst_sizes else 0.0)

    # pacing_entropy: Shannon entropy of gap duration bins
    gap_bins = [_gap_token(g * 1000) for g in gaps_s] if gaps_s else []
    feat['pacing_entropy'] = _shannon_entropy(gap_bins)

    # ---- C4: Volume ----
    bytes_per_turn = []
    bytes_fwd_total = 0
    bytes_rev_total = 0
    max_single = 0
    for f in flows:
        bf = f['bytes_fwd'] or 0
        br = f['bytes_rev'] or 0
        total = bf + br
        bytes_per_turn.append(total)
        bytes_fwd_total += bf
        bytes_rev_total += br
        if total > max_single:
            max_single = total

    feat['bytes_total'] = bytes_fwd_total + bytes_rev_total
    feat['bytes_fwd_total'] = bytes_fwd_total
    feat['bytes_rev_total'] = bytes_rev_total
    feat['volume_trend'] = _linear_slope(bytes_per_turn) if len(bytes_per_turn) >= 2 else 0.0
    feat['max_single_flow_bytes'] = max_single
    feat['volume_gini'] = _gini_coefficient(bytes_per_turn)

    # ---- C5: Escalation ----
    xgb_classes = []
    cnn_classes = []
    for f in flows:
        pred = predictions.get(f['flow_id'], {})
        xgb_l = pred.get('xgb_label')
        cnn_l = pred.get('cnn_label')
        xgb_classes.append(int(xgb_l) if xgb_l is not None else 0)
        cnn_classes.append(int(cnn_l) if cnn_l is not None else 0)

    feat['max_xgb_class'] = max(xgb_classes) if xgb_classes else 0
    feat['max_cnn_class'] = max(cnn_classes) if cnn_classes else 0

    # escalation_turn: first turn where max class is reached
    max_class = max(max(xgb_classes), max(cnn_classes)) if xgb_classes else 0
    escalation_turn = n_turns - 1
    for i, (xc, cc) in enumerate(zip(xgb_classes, cnn_classes)):
        if xc == max_class or cc == max_class:
            escalation_turn = i
            break
    feat['escalation_turn'] = escalation_turn
    feat['escalation_fraction'] = escalation_turn / n_turns if n_turns > 0 else 0.0

    all_classes = set(xgb_classes) | set(cnn_classes)
    all_classes.discard(0)
    feat['class_diversity'] = len(all_classes)

    # deescalation_count: number of times class drops between consecutive turns
    combined_classes = [max(x, c) for x, c in zip(xgb_classes, cnn_classes)]
    deesc = 0
    for i in range(1, len(combined_classes)):
        if combined_classes[i] < combined_classes[i - 1]:
            deesc += 1
    feat['deescalation_count'] = deesc

    # plateau_length: longest consecutive run of same max class
    if combined_classes:
        max_plateau = 1
        cur_plateau = 1
        for i in range(1, len(combined_classes)):
            if combined_classes[i] == combined_classes[i - 1]:
                cur_plateau += 1
                if cur_plateau > max_plateau:
                    max_plateau = cur_plateau
            else:
                cur_plateau = 1
        feat['plateau_length'] = max_plateau
    else:
        feat['plateau_length'] = 0

    # has_auth_success: extended session after brute prediction
    has_auth = 0
    for f in flows:
        pred = predictions.get(f['flow_id'], {})
        xl = pred.get('xgb_label')
        xc = pred.get('xgb_conf', 0) or 0
        if xl in (2, 3) and xc > 0.7 and (f['n_events'] or 0) >= 10 and (f['duration_ms'] or 0) > 30000:
            has_auth = 1
            break
    feat['has_auth_success'] = has_auth

    # ---- C6: Service ----
    service_tokens = [_service_token(f['dst_port']) for f in flows]
    if service_tokens:
        freq = defaultdict(int)
        for s in service_tokens:
            freq[s] += 1
        dominant_service = max(freq, key=freq.get)
        feat['dominant_service'] = dominant_service
        feat['dominant_service_frac'] = freq[dominant_service] / len(service_tokens)
        feat['service_entropy'] = _shannon_entropy(service_tokens)

        # service_transition_count: how often service changes between turns
        transitions = sum(1 for i in range(1, len(service_tokens))
                         if service_tokens[i] != service_tokens[i - 1])
        feat['service_transition_count'] = transitions

        mid = len(service_tokens) // 2
        feat['service_breadth_first_half'] = len(set(service_tokens[:mid])) if mid > 0 else 0
        feat['service_breadth_second_half'] = len(set(service_tokens[mid:])) if mid < len(service_tokens) else 0
    else:
        feat['dominant_service'] = 0
        feat['dominant_service_frac'] = 0.0
        feat['service_entropy'] = 0.0
        feat['service_transition_count'] = 0
        feat['service_breadth_first_half'] = 0
        feat['service_breadth_second_half'] = 0

    # ---- C7: Consensus ----
    agree_count = 0
    disagree_max_delta = 0
    both_count = 0
    cnn_available = 0
    agreements_over_time = []

    for f in flows:
        pred = predictions.get(f['flow_id'], {})
        xl = pred.get('xgb_label')
        cl = pred.get('cnn_label')
        if cl is not None:
            cnn_available += 1
        if xl is not None and cl is not None:
            both_count += 1
            delta = abs(int(xl) - int(cl))
            if delta == 0:
                agree_count += 1
                agreements_over_time.append(1)
            else:
                agreements_over_time.append(0)
                if delta > disagree_max_delta:
                    disagree_max_delta = delta
        else:
            agreements_over_time.append(0)

    feat['agreement_rate'] = agree_count / both_count if both_count > 0 else 0.0
    feat['disagreement_max_delta'] = disagree_max_delta
    feat['agreement_trend'] = (_linear_slope(agreements_over_time)
                               if len(agreements_over_time) >= 2 else 0.0)
    feat['cnn_available_frac'] = cnn_available / n_turns if n_turns > 0 else 0.0

    # ---- C8: Actor ----
    feat['actor_conversation_count'] = actor_stats.get('conversation_count', 1)
    feat['actor_unique_ips'] = actor_stats.get('unique_ips', 1)
    feat['actor_mean_turns'] = actor_stats.get('mean_turns', float(n_turns))
    feat['actor_max_class'] = actor_stats.get('max_class', 0)

    # ---- C9: Threat scoring ----
    # Count flows with attack predictions from either model
    n_flows_attack = 0
    n_flows_recon = 0
    attack_confs = []
    for i, f in enumerate(flows):
        pred = predictions.get(f['flow_id'], {})
        xgb_l = xgb_classes[i]
        xgb_c = pred.get('xgb_conf', 0) or 0
        cnn_l = cnn_classes[i]
        cnn_c = pred.get('cnn_conf', 0) or 0
        is_attack_flow = ((xgb_l >= 1 and xgb_c >= 0.5)
                          or (cnn_l >= 1 and cnn_c >= 0.5))
        if is_attack_flow:
            n_flows_attack += 1
            attack_confs.append(max(
                xgb_c if xgb_l >= 1 else 0,
                cnn_c if cnn_l >= 1 else 0,
            ))

    feat['n_flows_attack'] = n_flows_attack
    feat['n_flows_recon'] = n_flows_recon
    feat['max_flow_label'] = max(max(xgb_classes), max(cnn_classes)) if xgb_classes else 0
    feat['mean_flow_confidence'] = (sum(attack_confs) / len(attack_confs)
                                    if attack_confs else 0.0)
    feat['threat_score'] = n_flows_attack / n_turns if n_turns > 0 else 0.0

    return feat


# ---------------------------------------------------------------------------
# Conversation labeling (4-tier heuristic)
# ---------------------------------------------------------------------------

def label_conversation(feat, turn_outcomes):
    """Apply 4-tier heuristic labeling. Returns (label, label_name, confidence).

    Labels: 0=COMMODITY_BOT, 1=COORDINATED_CAMPAIGN, 2=HUMAN_OPERATOR,
            3=RESEARCH_BENIGN, 4=UNKNOWN, 5=CLEAN_BASELINE
    """
    n = feat['n_turns']
    dominant_frac = feat['dominant_service_frac']
    has_auth = feat['has_auth_success']
    max_xgb = feat['max_xgb_class']
    max_cnn = feat['max_cnn_class']
    gap_std = feat['gap_std_s']
    unique_services = feat['unique_services']
    gap_mean = feat['gap_mean_s']
    duration_min = feat['duration_total_min']
    threat_score = feat.get('threat_score', 1.0)

    # ---- Clean baseline detection ----
    # Zero attack predictions from any model → definitely clean
    if threat_score == 0 and max_xgb == 0 and max_cnn == 0:
        return 5, 'CLEAN_BASELINE', 0.8

    # <10% attack flows, low model predictions → mostly clean
    if threat_score < 0.1 and max_xgb <= 1 and max_cnn <= 1:
        return 5, 'CLEAN_BASELINE', 0.6

    # Count outcome types
    syn_only_count = sum(1 for o in turn_outcomes if o == 1)
    auth_fail_count = sum(1 for o in turn_outcomes if o == 6)

    # Contains EXPLOIT/COMPROMISE predictions (5-class: 3=EXPLOIT, or old binary 1=attack with extended session)
    if max_xgb >= 3 or max_cnn >= 3:
        return 1, 'COORDINATED_CAMPAIGN', 0.5

    # Multi-service targeting + auth success + extended sessions
    if unique_services >= 3 and has_auth and duration_min > 5:
        return 2, 'HUMAN_OPERATOR', 0.5

    # All SYN-only, high n_turns, low gap_std → bot
    if n > 10 and syn_only_count / n > 0.8 and gap_std < 2.0:
        return 0, 'COMMODITY_BOT', 0.5

    # Single-service brute pattern
    if dominant_frac > 0.9 and auth_fail_count > n * 0.5:
        return 0, 'COMMODITY_BOT', 0.5

    # Any attack prediction (binary label 1, or 5-class label 1-4) + single service + many turns → bot
    if (max_xgb >= 1 or max_cnn >= 1) and dominant_frac > 0.8 and n >= 5:
        return 0, 'COMMODITY_BOT', 0.4

    # Any attack prediction + multi-service → coordinated
    if (max_xgb >= 1 or max_cnn >= 1) and unique_services >= 2:
        return 1, 'COORDINATED_CAMPAIGN', 0.4

    # Any attack prediction at all → commodity bot (default for honeypot traffic)
    if max_xgb >= 1 or max_cnn >= 1:
        return 0, 'COMMODITY_BOT', 0.3

    # Short, diverse, no auth, sub-100ms durations → research/benign
    if (n < 10 and unique_services >= 3
            and auth_fail_count == 0 and has_auth == 0
            and gap_mean < 0.1):
        return 3, 'RESEARCH_BENIGN', 0.5

    # No attack predictions at all → likely scanning/recon → commodity bot
    if n >= 2:
        return 0, 'COMMODITY_BOT', 0.2

    return 4, 'UNKNOWN', 0.5


# ---------------------------------------------------------------------------
# Main processing
# ---------------------------------------------------------------------------

def make_conversation_id(src_ip, first_ts):
    """SHA256-based conversation_id: first 32 hex chars."""
    epoch_ms = _ts_to_epoch_ms(first_ts)
    raw = f"{src_ip}|{epoch_ms}".encode()
    return hashlib.sha256(raw).hexdigest()[:32]


def fetch_flows(ch, cutoff_dt, end_dt=None):
    """Fetch flows from dfi.flows for the given time window."""
    cutoff_str = cutoff_dt.strftime('%Y-%m-%d %H:%M:%S')
    where = f"first_ts >= '{cutoff_str}'"
    if end_dt:
        end_str = end_dt.strftime('%Y-%m-%d %H:%M:%S')
        where += f" AND first_ts < '{end_str}'"

    query = f"""
    SELECT flow_id, src_ip, dst_ip, dst_port, app_proto, first_ts, last_ts,
           duration_ms, bytes_fwd, bytes_rev, pkts_fwd, pkts_rev,
           conn_state, syn_count, fin_count, rst_count, psh_count, n_events,
           actor_id
    FROM dfi.flows
    WHERE {where}
    ORDER BY src_ip, first_ts
    """
    log.info('Querying flows: %s', where)
    result = ch.execute(query, with_column_types=True)
    cols = [c[0] for c in result[1]]
    rows = [dict(zip(cols, r)) for r in result[0]]
    log.info('Fetched %s flows', f'{len(rows):,}')
    return rows


def fetch_predictions(ch, flow_ids):
    """Fetch model predictions for a list of flow_ids.

    Returns dict: flow_id -> {xgb_label, xgb_conf, cnn_label, cnn_conf}
    """
    if not flow_ids:
        return {}

    preds = {}
    # Process in batches to avoid query size limits
    batch_size = 5000
    for i in range(0, len(flow_ids), batch_size):
        batch = flow_ids[i:i + batch_size]
        id_list = ','.join(f"'{fid}'" for fid in batch)
        query = f"""
        SELECT flow_id, model_name, label, confidence
        FROM dfi.model_predictions
        WHERE flow_id IN ({id_list})
        """
        try:
            result = ch.execute(query, with_column_types=True)
            cols = [c[0] for c in result[1]]
            for row in result[0]:
                r = dict(zip(cols, row))
                fid = r['flow_id']
                if fid not in preds:
                    preds[fid] = {}
                model = r['model_name'].lower()
                if 'xgb' in model or 'recon' in model:
                    preds[fid]['xgb_label'] = r['label']
                    preds[fid]['xgb_conf'] = r['confidence']
                elif 'cnn' in model:
                    preds[fid]['cnn_label'] = r['label']
                    preds[fid]['cnn_conf'] = r['confidence']
        except Exception as exc:
            log.warning('Failed to fetch predictions batch %d: %s', i, exc)

    return preds


def group_into_conversations(flows, staleness_cutoff_dt):
    """Group flows by src_ip with 30-minute gap detection.

    Args:
        flows: list of flow dicts sorted by (src_ip, first_ts)
        staleness_cutoff_dt: skip conversations whose last flow is newer than this

    Returns:
        list of (src_ip, flow_list) tuples for conversations with >= MIN_FLOWS
    """
    staleness_ms = _ts_to_epoch_ms(staleness_cutoff_dt)
    conversations = []
    current_src = None
    current_flows = []

    def _flush():
        if len(current_flows) >= MIN_FLOWS_PER_CONVERSATION:
            last_ms = _ts_to_epoch_ms(current_flows[-1]['last_ts'])
            if last_ms <= staleness_ms:
                conversations.append((current_src, list(current_flows)))

    for f in flows:
        src = f['src_ip']
        if src != current_src:
            # New src_ip — flush previous
            _flush()
            current_src = src
            current_flows = [f]
            continue

        # Same src_ip — check gap
        prev_end = _ts_to_epoch_ms(current_flows[-1]['last_ts'])
        curr_start = _ts_to_epoch_ms(f['first_ts'])
        gap = curr_start - prev_end

        if gap > GAP_THRESHOLD_MS:
            # Gap exceeds threshold — new conversation
            _flush()
            current_flows = [f]
        else:
            current_flows.append(f)

    # Flush last group
    _flush()

    return conversations


def truncate_turns(flows):
    """If >256 turns, keep first 128 + last 128. Returns (flows, is_truncated)."""
    if len(flows) <= MAX_TURNS:
        return flows, 0
    return flows[:TRUNCATE_KEEP] + flows[-TRUNCATE_KEEP:], 1


def compute_turn_tokens(flows, predictions):
    """Compute 12-channel tokens for each turn.

    Returns list of dicts, one per turn, each with 12 token fields.
    """
    seen_ports = set()
    turns = []
    prev_end_ms = None

    for idx, f in enumerate(flows):
        pred = predictions.get(f['flow_id'], {})

        # Gap from previous turn
        curr_start_ms = _ts_to_epoch_ms(f['first_ts'])
        if prev_end_ms is None:
            gap_ms = None  # first turn
        else:
            gap_ms = max(curr_start_ms - prev_end_ms, 0)

        bf = f['bytes_fwd'] or 0
        br = f['bytes_rev'] or 0

        tokens = {
            'ch_service_target': _service_token(f['dst_port']),
            'ch_flow_outcome': _flow_outcome_token(f, pred),
            'ch_xgb_prediction': _xgb_prediction_token(pred),
            'ch_xgb_confidence': _xgb_confidence_token(pred),
            'ch_cnn_prediction': _cnn_prediction_token(pred),
            'ch_cnn_confidence': _cnn_confidence_token(pred),
            'ch_model_agreement': _model_agreement_token(pred),
            'ch_turn_duration': _duration_token(f['duration_ms']),
            'ch_inter_turn_gap': _gap_token(gap_ms * 1000 if gap_ms is not None else None)
                                 if gap_ms is not None else 0,
            'ch_data_volume': _volume_token(bf + br),
            'ch_data_direction': _direction_token(bf, br),
            'ch_port_novelty': _port_novelty_token(f['dst_port'], seen_ports),
        }
        turns.append(tokens)
        prev_end_ms = _ts_to_epoch_ms(f['last_ts'])

    return turns


def ensure_tables(ch):
    """Create conversation tables if they don't exist."""
    ch.execute("""
    CREATE TABLE IF NOT EXISTS dfi.conversations (
        conversation_id   String,
        src_ip            String,
        first_ts          DateTime,
        last_ts           DateTime,
        n_turns           UInt32,
        is_truncated      UInt8,
        duration_total_min Float32,
        unique_services   UInt16,
        unique_dst_ports  UInt16,
        unique_dst_ips    UInt16,
        concurrent_max    UInt16,
        gap_mean_s        Float32,
        gap_std_s         Float32,
        gap_cv            Float32,
        gap_median_s      Float32,
        gap_acceleration  Float32,
        burst_count       UInt16,
        burst_mean_size   Float32,
        pacing_entropy    Float32,
        bytes_total       UInt64,
        bytes_fwd_total   UInt64,
        bytes_rev_total   UInt64,
        volume_trend      Float32,
        max_single_flow_bytes UInt64,
        volume_gini       Float32,
        max_xgb_class     UInt8,
        max_cnn_class     UInt8,
        escalation_turn   UInt32,
        escalation_fraction Float32,
        class_diversity   UInt8,
        deescalation_count UInt16,
        plateau_length    UInt32,
        has_auth_success  UInt8,
        dominant_service  UInt8,
        dominant_service_frac Float32,
        service_entropy   Float32,
        service_transition_count UInt16,
        service_breadth_first_half UInt8,
        service_breadth_second_half UInt8,
        agreement_rate    Float32,
        disagreement_max_delta UInt8,
        agreement_trend   Float32,
        cnn_available_frac Float32,
        actor_conversation_count UInt32,
        actor_unique_ips  UInt32,
        actor_mean_turns  Float32,
        actor_max_class   UInt8,
        created_at        DateTime DEFAULT now()
    ) ENGINE = ReplacingMergeTree(created_at)
    ORDER BY (conversation_id)
    """)

    ch.execute("""
    CREATE TABLE IF NOT EXISTS dfi.conversation_turns (
        conversation_id    String,
        turn_index         UInt32,
        flow_id            String,
        ch_service_target  UInt8,
        ch_flow_outcome    UInt8,
        ch_xgb_prediction  UInt8,
        ch_xgb_confidence  UInt8,
        ch_cnn_prediction  UInt8,
        ch_cnn_confidence  UInt8,
        ch_model_agreement UInt8,
        ch_turn_duration   UInt8,
        ch_inter_turn_gap  UInt8,
        ch_data_volume     UInt8,
        ch_data_direction  UInt8,
        ch_port_novelty    UInt8,
        created_at         DateTime DEFAULT now()
    ) ENGINE = ReplacingMergeTree(created_at)
    ORDER BY (conversation_id, turn_index)
    """)

    ch.execute("""
    CREATE TABLE IF NOT EXISTS dfi.conversation_labels (
        conversation_id    String,
        label              UInt8,
        label_name         String,
        label_confidence   Float32,
        label_tier         String DEFAULT 'heuristic',
        created_at         DateTime DEFAULT now()
    ) ENGINE = ReplacingMergeTree(created_at)
    ORDER BY (conversation_id)
    """)
    log.info('Tables verified/created')


def process_conversations(ch, conversations, predictions, dry_run=False):
    """Process grouped conversations: compute tokens, features, labels; write to CH.

    Args:
        ch: ClickHouse client
        conversations: list of (src_ip, flow_list) tuples
        predictions: dict flow_id -> prediction info
        dry_run: if True, skip writes

    Returns:
        (n_conversations, n_turns, label_counts)
    """
    conv_rows = []
    turn_rows = []
    label_rows = []
    label_counts = defaultdict(int)

    # ---- Build actor stats (C8) across all conversations in batch ----
    actor_convs = defaultdict(list)  # src_ip -> list of flow_lists
    for src_ip, flow_list in conversations:
        actor_convs[src_ip].append(flow_list)

    actor_stats_map = {}
    for src_ip, conv_list in actor_convs.items():
        all_dst_ips = set()
        all_turns = []
        all_max_class = 0
        for fl in conv_list:
            for f in fl:
                all_dst_ips.add(f['dst_ip'])
                pred = predictions.get(f['flow_id'], {})
                xc = int(pred.get('xgb_label', 0) or 0)
                cc = int(pred.get('cnn_label', 0) or 0)
                mc = max(xc, cc)
                if mc > all_max_class:
                    all_max_class = mc
            all_turns.append(len(fl))
        actor_stats_map[src_ip] = {
            'conversation_count': len(conv_list),
            'unique_ips': len(all_dst_ips),
            'mean_turns': sum(all_turns) / len(all_turns) if all_turns else 0,
            'max_class': all_max_class,
        }

    # ---- Process each conversation ----
    total_convs = len(conversations)
    for idx, (src_ip, flow_list) in enumerate(conversations):
        if (idx + 1) % 10000 == 0:
            log.info('Processing conversation %s / %s', f'{idx + 1:,}', f'{total_convs:,}')

        # Truncate if needed
        flow_list, is_truncated = truncate_turns(flow_list)

        # conversation_id
        conv_id = make_conversation_id(src_ip, flow_list[0]['first_ts'])

        # Turn tokens
        turn_tokens = compute_turn_tokens(flow_list, predictions)

        # Static features
        actor_stats = actor_stats_map.get(src_ip, {})
        feat = compute_static_features(flow_list, predictions, actor_stats)

        # Conversation label
        turn_outcomes = [t['ch_flow_outcome'] for t in turn_tokens]
        label, label_name, label_conf = label_conversation(feat, turn_outcomes)
        label_counts[label_name] += 1

        # Build conversation row
        first_ts = flow_list[0]['first_ts']
        last_ts = flow_list[-1]['last_ts']
        if isinstance(first_ts, datetime):
            first_ts_dt = first_ts
        else:
            first_ts_dt = datetime.utcfromtimestamp(first_ts / 1000.0)
        if isinstance(last_ts, datetime):
            last_ts_dt = last_ts
        else:
            last_ts_dt = datetime.utcfromtimestamp(last_ts / 1000.0)

        conv_row = {
            'conversation_id': conv_id,
            'src_ip': str(src_ip),
            'first_ts': first_ts_dt,
            'last_ts': last_ts_dt,
            'n_turns': feat['n_turns'],
            'is_truncated': is_truncated,
            'duration_total_min': float(feat['duration_total_min']),
            'unique_services': feat['unique_services'],
            'unique_dst_ports': feat['unique_dst_ports'],
            'unique_dst_ips': feat['unique_dst_ips'],
            'concurrent_max': feat['concurrent_max'],
            'gap_mean_s': float(feat['gap_mean_s']),
            'gap_std_s': float(feat['gap_std_s']),
            'gap_cv': float(feat['gap_cv']),
            'gap_median_s': float(feat['gap_median_s']),
            'gap_acceleration': float(feat['gap_acceleration']),
            'burst_count': feat['burst_count'],
            'burst_mean_size': float(feat['burst_mean_size']),
            'pacing_entropy': float(feat['pacing_entropy']),
            'bytes_total': feat['bytes_total'],
            'bytes_fwd_total': feat['bytes_fwd_total'],
            'bytes_rev_total': feat['bytes_rev_total'],
            'volume_trend': float(feat['volume_trend']),
            'max_single_flow_bytes': feat['max_single_flow_bytes'],
            'volume_gini': float(feat['volume_gini']),
            'max_xgb_class': feat['max_xgb_class'],
            'max_cnn_class': feat['max_cnn_class'],
            'escalation_turn': feat['escalation_turn'],
            'escalation_fraction': float(feat['escalation_fraction']),
            'class_diversity': feat['class_diversity'],
            'deescalation_count': feat['deescalation_count'],
            'plateau_length': feat['plateau_length'],
            'has_auth_success': feat['has_auth_success'],
            'dominant_service': feat['dominant_service'],
            'dominant_service_frac': float(feat['dominant_service_frac']),
            'service_entropy': float(feat['service_entropy']),
            'service_transition_count': feat['service_transition_count'],
            'service_breadth_first_half': feat['service_breadth_first_half'],
            'service_breadth_second_half': feat['service_breadth_second_half'],
            'agreement_rate': float(feat['agreement_rate']),
            'disagreement_max_delta': feat['disagreement_max_delta'],
            'agreement_trend': float(feat['agreement_trend']),
            'cnn_available_frac': float(feat['cnn_available_frac']),
            'actor_conversation_count': feat['actor_conversation_count'],
            'actor_unique_ips': feat['actor_unique_ips'],
            'actor_mean_turns': float(feat['actor_mean_turns']),
            'actor_max_class': feat['actor_max_class'],
            'label': label,
            'label_confidence': float(label_conf),
            'n_flows_attack': feat['n_flows_attack'],
            'n_flows_recon': feat['n_flows_recon'],
            'max_flow_label': feat['max_flow_label'],
            'threat_score': float(feat['threat_score']),
        }
        conv_rows.append(conv_row)

        # Build turn rows
        for tidx, (f, tokens) in enumerate(zip(flow_list, turn_tokens)):
            turn_row = {
                'conversation_id': conv_id,
                'turn_index': tidx,
                'flow_id': str(f['flow_id']),
                'ch_service_target': tokens['ch_service_target'],
                'ch_flow_outcome': tokens['ch_flow_outcome'],
                'ch_xgb_prediction': tokens['ch_xgb_prediction'],
                'ch_xgb_confidence': tokens['ch_xgb_confidence'],
                'ch_cnn_prediction': tokens['ch_cnn_prediction'],
                'ch_cnn_confidence': tokens['ch_cnn_confidence'],
                'ch_model_agreement': tokens['ch_model_agreement'],
                'ch_turn_duration': tokens['ch_turn_duration'],
                'ch_inter_turn_gap': tokens['ch_inter_turn_gap'],
                'ch_data_volume': tokens['ch_data_volume'],
                'ch_data_direction': tokens['ch_data_direction'],
                'ch_port_novelty': tokens['ch_port_novelty'],
            }
            turn_rows.append(turn_row)

        # Build label row
        label_rows.append({
            'conversation_id': conv_id,
            'label': label,
            'label_name': label_name,
            'label_confidence': float(label_conf),
            'label_tier': 'heuristic',
            'n_flows_labeled': feat['n_turns'],
            'n_flows_attack': feat['n_flows_attack'],
            'n_flows_recon': feat['n_flows_recon'],
            'n_flows_norm': feat['n_turns'] - feat['n_flows_attack'] - feat['n_flows_recon'],
            'max_flow_label': feat['max_flow_label'],
            'mean_flow_confidence': float(feat['mean_flow_confidence']),
        })

        # Batch write
        if not dry_run and len(conv_rows) >= WRITE_BATCH:
            _write_batch(ch, conv_rows, turn_rows, label_rows)
            conv_rows.clear()
            turn_rows.clear()
            label_rows.clear()

    # Final flush
    if not dry_run and conv_rows:
        _write_batch(ch, conv_rows, turn_rows, label_rows)

    return total_convs, sum(len(fl) for _, fl in conversations), label_counts


def _write_batch(ch, conv_rows, turn_rows, label_rows):
    """Write a batch of rows to the 3 conversation tables."""
    if conv_rows:
        ch.execute(
            'INSERT INTO dfi.conversations '
            '(conversation_id, src_ip, first_ts, last_ts, n_turns, is_truncated, '
            'duration_total_min, unique_services, unique_dst_ports, unique_dst_ips, concurrent_max, '
            'gap_mean_s, gap_std_s, gap_cv, gap_median_s, gap_acceleration, '
            'burst_count, burst_mean_size, pacing_entropy, '
            'bytes_total, bytes_fwd_total, bytes_rev_total, volume_trend, max_single_flow_bytes, volume_gini, '
            'max_xgb_class, max_cnn_class, escalation_turn, escalation_fraction, '
            'class_diversity, deescalation_count, plateau_length, has_auth_success, '
            'dominant_service, dominant_service_frac, service_entropy, service_transition_count, '
            'service_breadth_first_half, service_breadth_second_half, '
            'agreement_rate, disagreement_max_delta, agreement_trend, cnn_available_frac, '
            'actor_conversation_count, actor_unique_ips, actor_mean_turns, actor_max_class, '
            'label, label_confidence, n_flows_attack, n_flows_recon, max_flow_label, threat_score) '
            'VALUES',
            conv_rows,
        )
    if turn_rows:
        ch.execute(
            'INSERT INTO dfi.conversation_turns '
            '(conversation_id, turn_index, flow_id, '
            'ch_service_target, ch_flow_outcome, ch_xgb_prediction, ch_xgb_confidence, '
            'ch_cnn_prediction, ch_cnn_confidence, ch_model_agreement, '
            'ch_turn_duration, ch_inter_turn_gap, ch_data_volume, ch_data_direction, ch_port_novelty) '
            'VALUES',
            turn_rows,
        )
    if label_rows:
        ch.execute(
            'INSERT INTO dfi.conversation_labels '
            '(conversation_id, label, label_name, label_confidence, label_tier, '
            'n_flows_labeled, n_flows_attack, n_flows_recon, n_flows_norm, '
            'max_flow_label, mean_flow_confidence) '
            'VALUES',
            label_rows,
        )
    log.info('Wrote batch: %d conversations, %d turns, %d labels',
             len(conv_rows), len(turn_rows), len(label_rows))


def run(hours=2, backfill=False, dry_run=False):
    """Main processing loop."""
    t0 = time.time()
    ch = Client(CH_HOST, port=CH_PORT)

    if not dry_run:
        ensure_tables(ch)

    now = datetime.utcnow()
    staleness_cutoff = now - timedelta(milliseconds=STALENESS_MS)

    if backfill:
        # Process in daily partitions to manage memory
        # Find earliest flow
        result = ch.execute('SELECT min(first_ts) FROM dfi.flows')
        min_ts = result[0][0]
        if not min_ts:
            log.info('No flows found in dfi.flows')
            return

        log.info('Backfill: from %s to %s', min_ts, now)
        current_start = min_ts
        day_delta = timedelta(days=1)
        total_convs = 0
        total_turns = 0
        all_label_counts = defaultdict(int)

        while current_start < now:
            current_end = min(current_start + day_delta, now)
            log.info('Processing partition: %s to %s', current_start, current_end)

            flows = fetch_flows(ch, current_start, current_end)
            if not flows:
                current_start = current_end
                continue

            # Fetch predictions for this batch
            flow_ids = [f['flow_id'] for f in flows]
            predictions = fetch_predictions(ch, flow_ids)
            log.info('Fetched predictions for %s flow_ids (%s with predictions)',
                     f'{len(flow_ids):,}', f'{len(predictions):,}')

            # Group into conversations
            conversations = group_into_conversations(flows, staleness_cutoff)
            log.info('Grouped into %s conversations', f'{len(conversations):,}')

            if conversations:
                nc, nt, lc = process_conversations(ch, conversations, predictions, dry_run)
                total_convs += nc
                total_turns += nt
                for k, v in lc.items():
                    all_label_counts[k] += v

            current_start = current_end

        _log_final(total_convs, total_turns, all_label_counts, t0, dry_run)

    else:
        # Standard mode: single query for time window
        cutoff = now - timedelta(hours=hours)
        flows = fetch_flows(ch, cutoff)
        if not flows:
            log.info('No flows found')
            return

        # Fetch predictions
        flow_ids = [f['flow_id'] for f in flows]
        predictions = fetch_predictions(ch, flow_ids)
        log.info('Fetched predictions for %s flow_ids (%s with predictions)',
                 f'{len(flow_ids):,}', f'{len(predictions):,}')

        # Group into conversations
        conversations = group_into_conversations(flows, staleness_cutoff)
        log.info('Grouped into %s conversations', f'{len(conversations):,}')

        if not conversations:
            log.info('No closed conversations found (all still open or < %d flows)',
                     MIN_FLOWS_PER_CONVERSATION)
            return

        nc, nt, lc = process_conversations(ch, conversations, predictions, dry_run)
        _log_final(nc, nt, lc, t0, dry_run)


def _log_final(n_convs, n_turns, label_counts, t0, dry_run):
    """Log final summary."""
    elapsed = time.time() - t0
    mode = 'DRY-RUN' if dry_run else 'LIVE'
    log.info('[%s] Done: %s conversations, %s turns, %.1fs',
             mode, f'{n_convs:,}', f'{n_turns:,}', elapsed)
    if label_counts:
        log.info('Label distribution:')
        for label_name in sorted(label_counts):
            cnt = label_counts[label_name]
            pct = 100 * cnt / n_convs if n_convs > 0 else 0
            log.info('  %s: %s (%.1f%%)', label_name, f'{cnt:,}', pct)


def main():
    ap = argparse.ArgumentParser(description='Conversation assembler — group flows into multi-turn conversations.')
    ap.add_argument('--hours', type=int, default=2, help='Process flows from last N hours (default: 2)')
    ap.add_argument('--backfill', action='store_true', help='Process ALL flows (daily partitions)')
    ap.add_argument('--dry-run', action='store_true', help='No writes, just compute and log stats')
    args = ap.parse_args()

    run(hours=args.hours, backfill=args.backfill, dry_run=args.dry_run)


if __name__ == '__main__':
    main()
