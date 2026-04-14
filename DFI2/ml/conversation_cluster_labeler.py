#!/usr/bin/env python3
"""Conversation cluster labeler — enriches labels with temporal clustering + rDNS.

Runs hourly on PV1 and AIO. Two passes:
  1. Tier 3: temporal clustering → COMMODITY_BOT confidence uplift
  2. Tier 2: rDNS → RESEARCH_BENIGN for known scanners

Usage:
    python3 conversation_cluster_labeler.py                # standard hourly run (24h window)
    python3 conversation_cluster_labeler.py --hours 48     # custom lookback
    python3 conversation_cluster_labeler.py --dry-run      # no writes, just stats
"""
import argparse
import hashlib
import json
import logging
import os
import tempfile
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta

from clickhouse_driver import Client

try:
    import dns.resolver
    import dns.reversename
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
)
log = logging.getLogger(__name__)

CH_HOST = os.environ.get('CH_HOST', 'localhost')
CH_PORT = int(os.environ.get('CH_PORT', '9000'))

# Clustering thresholds
CLUSTER_HIGH_THRESHOLD = 50       # distinct IPs for 0.9 confidence
CLUSTER_LOW_THRESHOLD = 20        # distinct IPs for 0.7 confidence
CLUSTER_HIGH_CONFIDENCE = 0.9
CLUSTER_LOW_CONFIDENCE = 0.7

# rDNS
RDNS_CACHE_PATH = '/var/cache/dfi2/rdns_cache.json'
RDNS_TTL_DAYS = 30
RDNS_WORKERS = 20
RDNS_TIMEOUT = 2.0               # seconds per PTR query
RESEARCH_BENIGN_CONFIDENCE = 0.95

RESEARCH_DOMAINS = [
    'shodan.io',
    'censys.io',
    'binaryedge.io',
    'binaryedge.ninja',
    'shadowserver.org',
    'recyber.net',
    'stretchoid.com',
    'internet-census.org',
    'internet-measurement.com',
    'rapid7.com',
    'kudelskisecurity.com',
    'rwth-aachen.de',
    'umich.edu',
    'caida.org',
]

# Labels that clustering is allowed to override
CLUSTER_OVERRIDABLE_LABELS = {0, 4, 5}  # COMMODITY_BOT, UNKNOWN, CLEAN_BASELINE

WRITE_BATCH = 10000


# ---------------------------------------------------------------------------
# Schema setup
# ---------------------------------------------------------------------------

def ensure_schema(ch):
    """Add new columns to conversation_labels + create history table.

    NOTE: Depends on conversation_assembler having run first — the assembler's
    ensure_tables() creates conversation_labels with base columns, and its
    _write_batch() relies on n_flows_labeled, n_flows_attack, n_flows_recon,
    n_flows_norm, max_flow_label, mean_flow_confidence already existing
    (added via ALTER TABLE separately). This script only adds label_reason
    and cluster_signature.
    """
    ch.execute("""
        ALTER TABLE dfi.conversation_labels
        ADD COLUMN IF NOT EXISTS label_reason String DEFAULT ''
    """)
    ch.execute("""
        ALTER TABLE dfi.conversation_labels
        ADD COLUMN IF NOT EXISTS cluster_signature String DEFAULT ''
    """)
    ch.execute("""
        CREATE TABLE IF NOT EXISTS dfi.conversation_label_history (
            conversation_id    String,
            src_ip             String,
            label              UInt8,
            label_name         String,
            label_confidence   Float32,
            label_tier         String,
            label_reason       String,
            cluster_signature  String DEFAULT '',
            created_at         DateTime DEFAULT now()
        ) ENGINE = MergeTree()
        ORDER BY (conversation_id, created_at)
        TTL created_at + INTERVAL 30 DAY
    """)
    log.info('Schema verified (label_reason, cluster_signature, label_history)')


# ---------------------------------------------------------------------------
# Bucketing functions — signature computation
# ---------------------------------------------------------------------------

def _service_focus_bucket(dominant_service_frac):
    """Bucket dominant_service_frac: 0=<0.7, 1=0.7-0.95, 2=>0.95."""
    if dominant_service_frac < 0.7:
        return 0
    if dominant_service_frac <= 0.95:
        return 1
    return 2


def _scale_bucket(n_turns):
    """Bucket n_turns: 0=2-5, 1=6-20, 2=21-50, 3=51-100, 4=101+."""
    if n_turns <= 5:
        return 0
    if n_turns <= 20:
        return 1
    if n_turns <= 50:
        return 2
    if n_turns <= 100:
        return 3
    return 4


def _rhythm_bucket(gap_cv):
    """Bucket gap_cv: 0=<0.3 (mechanical), 1=0.3-1.0 (paced), 2=>1.0 (irregular)."""
    if gap_cv < 0.3:
        return 0
    if gap_cv <= 1.0:
        return 1
    return 2


def _evidence_tier(max_flow_label):
    """0=clean/no predictions, 1=RECON, 2=ATTACK."""
    if max_flow_label <= 0:
        return 0
    if max_flow_label == 1:
        return 1
    return 2


def _model_consensus_tier(row):
    """Compute model consensus tier 0-3 from conversation row.

    Tier 0: models say clean (nothing beyond RECON)
    Tier 1: one model attack or they disagree
    Tier 2: both attack, moderate confidence
    Tier 3: both attack, high confidence (both models, agree >= 0.5, mean_conf >= 0.85)
    """
    max_xgb = row.get('max_xgb_class', 0) or 0
    max_cnn = row.get('max_cnn_class', 0) or 0
    agree = row.get('agreement_rate', 0) or 0
    mean_conf = row.get('mean_flow_confidence', 0) or 0
    cnn_frac = row.get('cnn_available_frac', 0) or 0

    # CNN unavailable path
    if cnn_frac == 0:
        if max_xgb <= 1:
            return 0
        if mean_conf < 0.85:
            return 1
        return 2  # cap at 2 without CNN

    # Both models available
    if max_xgb <= 1 and max_cnn <= 1:
        return 0

    xgb_attack = max_xgb >= 2
    cnn_attack = max_cnn >= 2

    if xgb_attack != cnn_attack:
        return 1  # one sees attack, other doesn't
    if xgb_attack and cnn_attack:
        if agree < 0.5:
            return 1  # both attack but disagree
        if mean_conf < 0.85:
            return 2
        return 3

    return 1  # fallback


def compute_signature(row):
    """Compute 6-field signature string and SHA256 hash for a conversation row.

    Returns (signature_string, signature_hash).
    """
    fields = [
        str(int(row.get('dominant_service', 0) or 0)),
        str(_service_focus_bucket(row.get('dominant_service_frac', 0) or 0)),
        str(_scale_bucket(row.get('n_turns', 2) or 2)),
        str(_rhythm_bucket(row.get('gap_cv', 0) or 0)),
        str(_evidence_tier(row.get('max_flow_label', 0) or 0)),
        str(_model_consensus_tier(row)),
    ]
    sig_str = '|'.join(fields)
    sig_hash = hashlib.sha256(sig_str.encode()).hexdigest()[:16]
    return sig_str, sig_hash


# ---------------------------------------------------------------------------
# CH queries
# ---------------------------------------------------------------------------

def fetch_conversations(ch, hours):
    """Fetch conversations from last N hours.

    Returns list of dicts with conversation_id, src_ip, and all static features.
    """
    cutoff = (datetime.utcnow() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
    query = f"""
        SELECT conversation_id, src_ip, n_turns, dominant_service, dominant_service_frac,
               gap_cv, max_xgb_class, max_cnn_class, agreement_rate,
               cnn_available_frac
        FROM dfi.conversations
        WHERE first_ts >= '{cutoff}'
    """
    log.info('Querying conversations: first_ts >= %s', cutoff)
    result = ch.execute(query, with_column_types=True)
    cols = [c[0] for c in result[1]]
    rows = [dict(zip(cols, r)) for r in result[0]]
    log.info('Fetched %s conversations', f'{len(rows):,}')
    return rows


def fetch_existing_labels(ch, conversation_ids):
    """Fetch current labels for carry-forward columns.

    Returns dict: conversation_id -> label row dict.
    """
    if not conversation_ids:
        return {}

    labels = {}
    batch_size = 5000
    for i in range(0, len(conversation_ids), batch_size):
        batch = conversation_ids[i:i + batch_size]
        id_list = ','.join(f"'{cid}'" for cid in batch)
        query = f"""
            SELECT conversation_id, label, label_name, label_confidence, label_tier,
                   n_flows_labeled, n_flows_attack, n_flows_recon, n_flows_norm,
                   max_flow_label, mean_flow_confidence
            FROM dfi.conversation_labels
            WHERE conversation_id IN ({id_list})
        """
        try:
            result = ch.execute(query, with_column_types=True)
            cols = [c[0] for c in result[1]]
            for row in result[0]:
                r = dict(zip(cols, row))
                labels[r['conversation_id']] = r
        except Exception as exc:
            log.warning('Failed to fetch labels batch %d: %s', i, exc)

    log.info('Fetched existing labels for %s conversations', f'{len(labels):,}')
    return labels


# ---------------------------------------------------------------------------
# Tier 3 — cluster detection
# ---------------------------------------------------------------------------

def detect_clusters(conversations, existing_labels):
    """Group conversations by signature, find clusters >= CLUSTER_LOW_THRESHOLD IPs.

    Returns list of dicts ready for label write. Only includes conversations
    whose existing label is in CLUSTER_OVERRIDABLE_LABELS.
    """
    # Compute signatures
    sig_groups = defaultdict(list)  # sig_hash -> list of (conv_row, sig_str)
    for conv in conversations:
        sig_str, sig_hash = compute_signature(conv)
        sig_groups[sig_hash].append((conv, sig_str))

    # Find qualifying clusters
    label_updates = []
    cluster_count = 0

    for sig_hash, members in sig_groups.items():
        distinct_ips = set(m[0]['src_ip'] for m in members)
        n_ips = len(distinct_ips)

        if n_ips < CLUSTER_LOW_THRESHOLD:
            continue

        cluster_count += 1
        if n_ips >= CLUSTER_HIGH_THRESHOLD:
            confidence = CLUSTER_HIGH_CONFIDENCE
        else:
            confidence = CLUSTER_LOW_CONFIDENCE

        sig_str = members[0][1]  # same for all members
        reason = f"cluster: {n_ips} IPs with signature {sig_str} in 24h"

        for conv, _ in members:
            cid = conv['conversation_id']
            existing = existing_labels.get(cid, {})
            existing_label = existing.get('label', 4)  # default UNKNOWN

            # Override guard
            if existing_label not in CLUSTER_OVERRIDABLE_LABELS:
                continue

            label_updates.append({
                'conversation_id': cid,
                'src_ip': str(conv['src_ip']),
                'label': 0,  # COMMODITY_BOT
                'label_name': 'COMMODITY_BOT',
                'label_confidence': confidence,
                'label_tier': 'cluster',
                'label_reason': reason,
                'cluster_signature': sig_str,
                # Carry forward from existing
                'n_flows_labeled': existing.get('n_flows_labeled', 0),
                'n_flows_attack': existing.get('n_flows_attack', 0),
                'n_flows_recon': existing.get('n_flows_recon', 0),
                'n_flows_norm': existing.get('n_flows_norm', 0),
                'max_flow_label': existing.get('max_flow_label', 0),
                'mean_flow_confidence': float(existing.get('mean_flow_confidence', 0) or 0),
            })

    log.info('Clustering: %s signatures, %s qualifying clusters, %s label upgrades',
             f'{len(sig_groups):,}', cluster_count, f'{len(label_updates):,}')
    return label_updates


# ---------------------------------------------------------------------------
# Tier 2 — rDNS cache and PTR lookup
# ---------------------------------------------------------------------------

def load_rdns_cache():
    """Load rDNS cache from JSON file. Returns dict {ip: {ptr, ts}}."""
    if not os.path.exists(RDNS_CACHE_PATH):
        return {}
    try:
        with open(RDNS_CACHE_PATH) as f:
            cache = json.load(f)
        # Prune expired entries (>30 days)
        cutoff = time.time() - (RDNS_TTL_DAYS * 86400)
        pruned = {ip: v for ip, v in cache.items() if v.get('ts', 0) > cutoff}
        if len(pruned) < len(cache):
            log.info('rDNS cache: pruned %d expired entries', len(cache) - len(pruned))
        return pruned
    except Exception as exc:
        log.warning('Failed to load rDNS cache: %s', exc)
        return {}


def save_rdns_cache(cache):
    """Atomic-save rDNS cache to JSON file."""
    cache_dir = os.path.dirname(RDNS_CACHE_PATH)
    os.makedirs(cache_dir, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=cache_dir, suffix='.tmp')
    try:
        with os.fdopen(tmp_fd, 'w') as f:
            json.dump(cache, f)
        os.rename(tmp_path, RDNS_CACHE_PATH)
    except Exception as exc:
        log.warning('Failed to save rDNS cache: %s', exc)
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _resolve_ptr(ip):
    """Resolve PTR record for an IP. Returns (ip, hostname_or_empty)."""
    if not HAS_DNSPYTHON:
        return ip, ''
    try:
        rev = dns.reversename.from_address(ip)
        resolver = dns.resolver.Resolver()
        resolver.lifetime = RDNS_TIMEOUT
        answers = resolver.resolve(rev, 'PTR')
        if answers:
            return ip, str(answers[0]).rstrip('.')
    except Exception:
        pass
    return ip, ''


def resolve_ptrs(ips, cache):
    """Bulk PTR resolution with caching. Returns updated cache."""
    now = time.time()
    to_resolve = []
    for ip in ips:
        cached = cache.get(ip)
        if cached and (now - cached.get('ts', 0)) < (RDNS_TTL_DAYS * 86400):
            continue
        to_resolve.append(ip)

    if not to_resolve:
        log.info('rDNS: all %s IPs cached, 0 to resolve', f'{len(ips):,}')
        return cache

    log.info('rDNS: %s IPs to resolve (%s cached)',
             f'{len(to_resolve):,}', f'{len(ips) - len(to_resolve):,}')

    resolved = 0
    with ThreadPoolExecutor(max_workers=RDNS_WORKERS) as pool:
        futures = {pool.submit(_resolve_ptr, ip): ip for ip in to_resolve}
        for future in as_completed(futures):
            ip, ptr = future.result()
            cache[ip] = {'ptr': ptr, 'ts': now}
            if ptr:
                resolved += 1

    log.info('rDNS: resolved %d/%d with PTR records', resolved, len(to_resolve))
    return cache


# ---------------------------------------------------------------------------
# Tier 2 — rDNS label assignment
# ---------------------------------------------------------------------------

def _is_research_domain(ptr):
    """Check if PTR hostname matches a known research scanner domain."""
    if not ptr:
        return False
    ptr_lower = ptr.lower()
    return any(ptr_lower.endswith('.' + domain) or ptr_lower == domain
               for domain in RESEARCH_DOMAINS)


def apply_rdns_labels(conversations, existing_labels, cache, label_updates_map):
    """Check src_ips against rDNS cache, override matching to RESEARCH_BENIGN.

    Args:
        conversations: list of conversation row dicts
        existing_labels: dict cid -> existing label row
        cache: rDNS cache dict {ip: {ptr, ts}}
        label_updates_map: dict cid -> label update dict (mutated in place)

    Returns number of rDNS overrides.
    """
    # Build ip -> list of conversations
    ip_to_convs = defaultdict(list)
    for conv in conversations:
        ip_to_convs[conv['src_ip']].append(conv)

    rdns_count = 0
    for ip, convs in ip_to_convs.items():
        cached = cache.get(ip)
        if not cached:
            continue
        ptr = cached.get('ptr', '')
        if not _is_research_domain(ptr):
            continue

        reason = f"rdns: PTR resolves to {ptr}"
        for conv in convs:
            cid = conv['conversation_id']
            existing = existing_labels.get(cid, {})
            label_updates_map[cid] = {
                'conversation_id': cid,
                'src_ip': str(conv['src_ip']),
                'label': 3,  # RESEARCH_BENIGN
                'label_name': 'RESEARCH_BENIGN',
                'label_confidence': RESEARCH_BENIGN_CONFIDENCE,
                'label_tier': 'rdns',
                'label_reason': reason,
                'cluster_signature': '',
                # Carry forward
                'n_flows_labeled': existing.get('n_flows_labeled', 0),
                'n_flows_attack': existing.get('n_flows_attack', 0),
                'n_flows_recon': existing.get('n_flows_recon', 0),
                'n_flows_norm': existing.get('n_flows_norm', 0),
                'max_flow_label': existing.get('max_flow_label', 0),
                'mean_flow_confidence': float(existing.get('mean_flow_confidence', 0) or 0),
            }
            rdns_count += 1

    log.info('rDNS: %d conversations labeled RESEARCH_BENIGN', rdns_count)
    return rdns_count


# ---------------------------------------------------------------------------
# Write functions
# ---------------------------------------------------------------------------

def write_labels(ch, label_rows):
    """Batch write to conversation_labels and conversation_label_history."""
    if not label_rows:
        return

    for i in range(0, len(label_rows), WRITE_BATCH):
        batch = label_rows[i:i + WRITE_BATCH]

        # Write to conversation_labels (ReplacingMergeTree — newest wins)
        ch.execute(
            'INSERT INTO dfi.conversation_labels '
            '(conversation_id, label, label_name, label_confidence, label_tier, '
            'label_reason, cluster_signature, '
            'n_flows_labeled, n_flows_attack, n_flows_recon, n_flows_norm, '
            'max_flow_label, mean_flow_confidence) '
            'VALUES',
            batch,
        )

        # Write to history (append-only audit trail)
        history_rows = [{
            'conversation_id': r['conversation_id'],
            'src_ip': r.get('src_ip', ''),
            'label': r['label'],
            'label_name': r['label_name'],
            'label_confidence': r['label_confidence'],
            'label_tier': r['label_tier'],
            'label_reason': r.get('label_reason', ''),
            'cluster_signature': r.get('cluster_signature', ''),
        } for r in batch]

        ch.execute(
            'INSERT INTO dfi.conversation_label_history '
            '(conversation_id, src_ip, label, label_name, label_confidence, '
            'label_tier, label_reason, cluster_signature) '
            'VALUES',
            history_rows,
        )

        log.info('Wrote batch: %d labels + %d history rows', len(batch), len(history_rows))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(hours=24, dry_run=False):
    """Main processing loop."""
    t0 = time.time()

    if not HAS_DNSPYTHON:
        log.error('dnspython is required: pip3 install dnspython')
        return

    ch = Client(CH_HOST, port=CH_PORT)

    if not dry_run:
        ensure_schema(ch)

    # Step 3: Fetch conversations
    conversations = fetch_conversations(ch, hours)
    if not conversations:
        log.info('No conversations found in last %d hours', hours)
        return

    # Step 4: Fetch existing labels
    conv_ids = [c['conversation_id'] for c in conversations]
    existing_labels = fetch_existing_labels(ch, conv_ids)

    # Enrich conversations with fields from labels table
    # (mean_flow_confidence and max_flow_label may not be in conversations table on all hosts)
    for conv in conversations:
        lbl = existing_labels.get(conv['conversation_id'], {})
        conv.setdefault('mean_flow_confidence', lbl.get('mean_flow_confidence', 0) or 0)
        conv.setdefault('max_flow_label', lbl.get('max_flow_label', 0) or 0)

    # Step 5: Tier 3 — Clustering
    cluster_updates = detect_clusters(conversations, existing_labels)

    # Build update map (cid -> label row), cluster first
    label_updates_map = {}
    for update in cluster_updates:
        label_updates_map[update['conversation_id']] = update

    # Step 6: Tier 2 — rDNS
    unique_ips = list(set(c['src_ip'] for c in conversations))
    log.info('rDNS: %s unique src_ips in window', f'{len(unique_ips):,}')
    cache = load_rdns_cache()
    cache = resolve_ptrs(unique_ips, cache)

    if not dry_run:
        save_rdns_cache(cache)

    rdns_count = apply_rdns_labels(conversations, existing_labels, cache, label_updates_map)

    # Step 7: Write
    final_updates = list(label_updates_map.values())

    if dry_run:
        log.info('[DRY-RUN] Would write %s label updates', f'{len(final_updates):,}')
    elif final_updates:
        write_labels(ch, final_updates)

    # Step 8: Summary
    elapsed = time.time() - t0
    label_dist = defaultdict(int)
    for u in final_updates:
        label_dist[u['label_name']] += 1

    mode = 'DRY-RUN' if dry_run else 'LIVE'
    log.info('[%s] Done in %.1fs: %s conversations, %s labels written',
             mode, elapsed, f'{len(conversations):,}', f'{len(final_updates):,}')
    log.info('  Cluster upgrades: %d', len(cluster_updates))
    log.info('  rDNS overrides: %d', rdns_count)
    if label_dist:
        log.info('  Label distribution:')
        for name in sorted(label_dist):
            log.info('    %s: %d', name, label_dist[name])


def main():
    ap = argparse.ArgumentParser(description='Conversation cluster labeler')
    ap.add_argument('--hours', type=int, default=24,
                    help='Lookback window in hours (default: 24)')
    ap.add_argument('--dry-run', action='store_true',
                    help='No writes, just compute and log stats')
    args = ap.parse_args()
    run(hours=args.hours, dry_run=args.dry_run)


if __name__ == '__main__':
    main()
