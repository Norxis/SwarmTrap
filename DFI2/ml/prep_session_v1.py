#!/usr/bin/env python3
"""Prepare session_v1 training data: 31 features with kill chain history.

Runs on Test (polars, 252GB RAM, 72 cores).
Pattern: prep_evil_02.py

Steps:
  1. Load session features + timestamps + source stats + labels
  2. Compute IAT features from flow_timestamps arrays
  3. Compute F5 Source Context via group_by('src_ip')
  4. Compute F6 Kill Chain History (prior stage counts per src_ip timeline)
  5. Label mapping: attack(1-3)/dirty → 1, clean/norm(0,5) → 0
  6. Output: session_v1_training.parquet (31 features)

Usage:
    python3 -u prep_session_v1.py /nvme0n1-disk/ml/data/sessions/
"""
import os
import re
import sys
import time

import numpy as np
import polars as pl

# 31 session features for XGBoost
SESSION_FEAT_COLS = [
    # F1 Volume (6)
    'sess_flow_count', 'sess_bytes_fwd', 'sess_bytes_rev',
    'sess_pkts_fwd', 'sess_pkts_rev', 'sess_reply_ratio',
    # F2 Temporal (5)
    'sess_duration', 'sess_avg_iat', 'sess_min_iat', 'sess_max_iat', 'sess_avg_flow_dur',
    # F3 Depth (5)
    'sess_max_flow_dur', 'sess_max_bytes_rev', 'sess_avg_bytes_per_flow',
    'sess_payload_ratio', 'sess_bidirectional_ratio',
    # F4 TCP Behavior (4)
    'sess_syn_only_ratio', 'sess_rst_ratio', 'sess_completed_ratio', 'sess_avg_tcp_flags',
    # F5 Source Context (6)
    'src_total_sessions', 'src_total_ports', 'src_total_flows',
    'src_avg_session_depth', 'src_single_flow_sessions', 'src_reply_rate',
    # F6 Kill Chain History (5)
    'prior_scan_count', 'prior_brute_count', 'prior_exploit_count',
    'time_since_first_seen', 'max_prior_stage',
]


def parse_timestamp_array(s):
    """Parse CH groupArray output like ['2026-01-01 00:00:00.000',...] to epoch seconds."""
    if s is None or s == '[]':
        return []
    # Strip brackets, split by comma, parse each timestamp
    s = s.strip('[]')
    parts = re.findall(r"'([^']+)'", s)
    if not parts:
        # Try unquoted format
        parts = [p.strip() for p in s.split(',') if p.strip()]
    epochs = []
    for p in parts:
        try:
            # Parse datetime string to epoch seconds
            from datetime import datetime
            dt = datetime.strptime(p.strip(), '%Y-%m-%d %H:%M:%S.%f')
            epochs.append(dt.timestamp())
        except ValueError:
            try:
                dt = datetime.strptime(p.strip(), '%Y-%m-%d %H:%M:%S')
                epochs.append(dt.timestamp())
            except ValueError:
                continue
    return sorted(epochs)


def compute_iat_features(timestamps):
    """Compute avg/min/max IAT from sorted timestamp list."""
    if len(timestamps) < 2:
        return 0.0, 0.0, 0.0
    diffs = np.diff(timestamps)
    return float(np.mean(diffs)), float(np.min(diffs)), float(np.max(diffs))


def classify_stage(row):
    """Classify a session's kill chain stage from its features.

    Returns: 0=none, 1=RECON, 2=BRUTE, 3=EXPLOIT, 4=C2
    """
    fc = row['sess_flow_count']
    syn_ratio = row['sess_syn_only_ratio']
    reply_ratio = row['sess_reply_ratio']
    bidir_ratio = row['sess_bidirectional_ratio']
    max_flow_dur = row['sess_max_flow_dur']
    max_bytes_rev = row['sess_max_bytes_rev']
    duration = row['sess_duration']

    # C2: persistent reconnect (duration > 300s or many flows with consistent IAT)
    if duration > 300 and fc > 5 and bidir_ratio > 0.3:
        return 4
    # EXPLOIT: interactive, long flows, significant reverse traffic
    if bidir_ratio > 0.5 and max_flow_dur > 30000 and max_bytes_rev > 1024:
        return 3
    # BRUTE: many flows to one port, moderate reply
    if fc > 20 and 0.3 < reply_ratio < 0.7:
        return 2
    # RECON: thin SYN scans
    if fc <= 3 and syn_ratio > 0.5 and reply_ratio < 0.2:
        return 1
    return 0


def load_sessions(data_dir, prefix, has_timestamps=True):
    """Load session features + optional timestamps, compute IAT."""
    feat_path = os.path.join(data_dir, f'{prefix}_features.csv') if 'session' not in prefix else os.path.join(data_dir, f'{prefix}.csv')

    # Try multiple naming conventions
    for candidate in [
        os.path.join(data_dir, f'{prefix}.csv'),
        os.path.join(data_dir, f'{prefix}_features.csv'),
        os.path.join(data_dir, f'dfi_{prefix}.csv'),
    ]:
        if os.path.exists(candidate):
            feat_path = candidate
            break

    t0 = time.time()
    df = pl.read_csv(feat_path, infer_schema_length=10000,
                     null_values=[r'\N', 'NULL', ''],
                     try_parse_dates=False)
    # Cast numeric columns
    for col in df.columns:
        if col.startswith('sess_') or col.startswith('src_') or col.startswith('prior_'):
            df = df.with_columns(pl.col(col).cast(pl.Float64, strict=False).fill_null(0))
    print(f'  {prefix}: {len(df):,} rows ({time.time()-t0:.1f}s)')

    # Compute IAT features from timestamps if available
    if has_timestamps:
        ts_path = None
        for candidate in [
            os.path.join(data_dir, f'{prefix.replace("sessions", "timestamps").replace("session_features", "session_timestamps")}.csv'),
            os.path.join(data_dir, f'{prefix}_timestamps.csv'),
        ]:
            if os.path.exists(candidate):
                ts_path = candidate
                break

        if ts_path:
            print(f'  Loading timestamps from {os.path.basename(ts_path)} ...')
            ts_df = pl.read_csv(ts_path, infer_schema_length=10000,
                                null_values=[r'\N', 'NULL', ''],
                                try_parse_dates=False)

            # Build (src_ip, dst_ip, dst_port) -> timestamps map
            ts_map = {}
            for row in ts_df.iter_rows(named=True):
                key = (str(row['src_ip']), str(row['dst_ip']), int(float(row['dst_port'])))
                ts_str = row.get('flow_timestamps', '[]')
                ts_map[key] = parse_timestamp_array(ts_str)

            # Compute IAT features
            avg_iats, min_iats, max_iats = [], [], []
            for row in df.iter_rows(named=True):
                key = (str(row['src_ip']), str(row['dst_ip']), int(float(row['dst_port'])))
                timestamps = ts_map.get(key, [])
                avg_iat, min_iat, max_iat = compute_iat_features(timestamps)
                avg_iats.append(avg_iat)
                min_iats.append(min_iat)
                max_iats.append(max_iat)

            df = df.with_columns([
                pl.Series('sess_avg_iat', avg_iats, dtype=pl.Float64),
                pl.Series('sess_min_iat', min_iats, dtype=pl.Float64),
                pl.Series('sess_max_iat', max_iats, dtype=pl.Float64),
            ])
        else:
            print(f'  WARNING: No timestamps file found for {prefix}, IAT features = 0')
            df = df.with_columns([
                pl.lit(0.0).alias('sess_avg_iat'),
                pl.lit(0.0).alias('sess_min_iat'),
                pl.lit(0.0).alias('sess_max_iat'),
            ])
    else:
        df = df.with_columns([
            pl.lit(0.0).alias('sess_avg_iat'),
            pl.lit(0.0).alias('sess_min_iat'),
            pl.lit(0.0).alias('sess_max_iat'),
        ])

    return df


def compute_source_context(df):
    """Compute F5 Source Context features via group_by('src_ip')."""
    print('Computing F5 Source Context ...')
    t0 = time.time()

    src_agg = df.group_by('src_ip').agg([
        pl.len().alias('src_total_sessions'),
        pl.col('dst_port').n_unique().alias('src_total_ports'),
        pl.col('sess_flow_count').sum().alias('src_total_flows'),
        pl.col('sess_flow_count').mean().alias('src_avg_session_depth'),
        (pl.col('sess_flow_count') == 1).sum().alias('src_single_flow_sessions'),
        pl.col('sess_reply_ratio').mean().alias('src_reply_rate'),
    ])

    df = df.join(src_agg, on='src_ip', how='left')
    print(f'  Done ({time.time()-t0:.1f}s)')
    return df


def compute_kill_chain_history(df):
    """Compute F6 Kill Chain History features.

    For each session, count how many prior sessions from the same src_ip
    match each kill chain stage. Uses _first_seen timestamp for ordering.
    """
    print('Computing F6 Kill Chain History ...')
    t0 = time.time()

    # Classify each session's stage
    stages = []
    for row in df.iter_rows(named=True):
        stages.append(classify_stage(row))
    df = df.with_columns(pl.Series('_stage', stages, dtype=pl.UInt8))

    # Parse _first_seen to epoch for ordering
    if '_first_seen' in df.columns:
        # Try to parse as datetime
        try:
            df = df.with_columns(
                pl.col('_first_seen').str.to_datetime(strict=False).dt.epoch('s').alias('_epoch')
            )
        except Exception:
            df = df.with_columns(pl.lit(0).alias('_epoch'))
    else:
        df = df.with_columns(pl.lit(0).alias('_epoch'))

    # Sort by src_ip, _epoch for rolling computation
    df = df.sort(['src_ip', '_epoch'])

    # Group by src_ip and compute rolling history
    prior_scan = []
    prior_brute = []
    prior_exploit = []
    time_since_first = []
    max_prior = []

    current_ip = None
    ip_stages = []  # (epoch, stage)
    ip_first_epoch = 0

    for row in df.iter_rows(named=True):
        src = str(row['src_ip'])
        epoch = row['_epoch'] if row['_epoch'] is not None else 0
        stage = row['_stage']

        if src != current_ip:
            current_ip = src
            ip_stages = []
            ip_first_epoch = epoch

        # Count prior stages (everything before this session)
        scan_cnt = sum(1 for _, s in ip_stages if s == 1)
        brute_cnt = sum(1 for _, s in ip_stages if s == 2)
        exploit_cnt = sum(1 for _, s in ip_stages if s >= 3)
        max_s = max((s for _, s in ip_stages), default=0)
        t_since = epoch - ip_first_epoch if ip_first_epoch > 0 and epoch > 0 else 0

        prior_scan.append(scan_cnt)
        prior_brute.append(brute_cnt)
        prior_exploit.append(exploit_cnt)
        time_since_first.append(max(t_since, 0))
        max_prior.append(max_s)

        # Add this session to history
        ip_stages.append((epoch, stage))

    df = df.with_columns([
        pl.Series('prior_scan_count', prior_scan, dtype=pl.Float64),
        pl.Series('prior_brute_count', prior_brute, dtype=pl.Float64),
        pl.Series('prior_exploit_count', prior_exploit, dtype=pl.Float64),
        pl.Series('time_since_first_seen', time_since_first, dtype=pl.Float64),
        pl.Series('max_prior_stage', max_prior, dtype=pl.Float64),
    ])

    print(f'  Stage distribution: {dict(df["_stage"].value_counts().sort("_stage").iter_rows())}')
    print(f'  Done ({time.time()-t0:.1f}s)')
    return df


def main():
    if len(sys.argv) < 2:
        print('Usage: python3 -u prep_session_v1.py <data_dir>')
        sys.exit(1)

    data_dir = sys.argv[1]
    t_start = time.time()
    print('=== prep_session_v1: Session model training data ===\n')

    # 1. Load DFI labeled sessions
    print('Loading DFI labeled sessions ...')
    dfi_sessions = load_sessions(data_dir, 'dfi_session_features')
    dfi_labels = pl.read_csv(
        os.path.join(data_dir, 'dfi_session_labels.csv'),
        infer_schema_length=10000,
        null_values=[r'\N', 'NULL', ''],
        try_parse_dates=False,
    )
    print(f'  Labels: {len(dfi_labels):,} rows')

    # Cast label columns
    for col in ['label', 'label_confidence', 'labeled_flow_count', 'dst_port']:
        if col in dfi_labels.columns:
            dfi_labels = dfi_labels.with_columns(
                pl.col(col).cast(pl.Float64, strict=False).fill_null(0)
            )

    # Join labels to sessions
    join_cols = ['src_ip', 'dst_ip', 'dst_port']
    dfi_sessions = dfi_sessions.join(dfi_labels, on=join_cols, how='inner')
    print(f'  Labeled sessions: {len(dfi_sessions):,}')

    # Split into attack (label 1-3) and norm (label 0,5)
    attack = dfi_sessions.filter(pl.col('label').is_between(1, 3))
    norm = dfi_sessions.filter(pl.col('label').is_in([0, 5]))
    print(f'  Attack sessions: {len(attack):,}')
    print(f'  Norm sessions: {len(norm):,}')

    # 2. Load dirty sessions (label = 1, evil)
    print('\nLoading dirty sessions ...')
    dirty = load_sessions(data_dir, 'dirty_sessions')
    dirty = dirty.with_columns([
        pl.lit(1.0).alias('label'),
        pl.lit(2.0).alias('label_confidence'),
    ])

    # 3. Load clean sessions (label = 5, clean)
    print('\nLoading clean sessions ...')
    clean = load_sessions(data_dir, 'clean_sessions')
    clean = clean.with_columns([
        pl.lit(5.0).alias('label'),
        pl.lit(1.0).alias('label_confidence'),
    ])

    # 4. Balance: all attack + enough dirty to match clean count
    n_clean = len(clean)
    n_attack = len(attack)
    n_norm = min(len(norm), n_clean // 4)  # some norm as additional clean
    n_dirty_needed = max(0, n_clean - n_attack)

    print(f'\nBalance plan:')
    print(f'  Clean:  {n_clean:,}')
    print(f'  Attack: {n_attack:,} (keep all)')
    print(f'  Norm:   {len(norm):,} -> sample {n_norm:,} (as clean)')
    print(f'  Dirty:  {len(dirty):,} -> sample {n_dirty_needed:,}')

    if n_dirty_needed > len(dirty):
        print(f'  WARNING: need {n_dirty_needed:,} dirty but only {len(dirty):,}, adjusting')
        n_dirty_needed = len(dirty)
        n_clean = min(n_clean, n_attack + n_dirty_needed)
        clean = clean.sample(n=n_clean, seed=42)

    dirty_sampled = dirty.sample(n=min(n_dirty_needed, len(dirty)), seed=42) if n_dirty_needed > 0 else dirty.head(0)

    # Assign labels
    attack = attack.with_columns(pl.lit(1.0).alias('label'), pl.lit(5.0).alias('label_confidence'))
    norm_sampled = norm.sample(n=n_norm, seed=42) if n_norm > 0 else norm.head(0)
    norm_sampled = norm_sampled.with_columns(pl.lit(5.0).alias('label'), pl.lit(1.0).alias('label_confidence'))

    # 5. Concat all
    print('\nConcatenating ...')
    all_frames = [attack, norm_sampled, dirty_sampled, clean]
    # Align columns
    all_cols = set()
    for f in all_frames:
        all_cols.update(f.columns)
    aligned = []
    for f in all_frames:
        for col in all_cols - set(f.columns):
            f = f.with_columns(pl.lit(None).alias(col))
        aligned.append(f)

    df = pl.concat(aligned, how='diagonal_relaxed')
    del attack, norm_sampled, dirty_sampled, clean, aligned

    n_evil = int((df['label'] == 1).sum())
    n_clean_final = int((df['label'] == 5).sum())
    print(f'Combined: {len(df):,} rows (EVIL={n_evil:,}, CLEAN={n_clean_final:,})')

    # Ensure all needed columns are Float64
    for col in df.columns:
        if col.startswith('sess_') and df[col].dtype not in [pl.Float64, pl.Float32]:
            df = df.with_columns(pl.col(col).cast(pl.Float64, strict=False).fill_null(0))

    # 6. Compute F5 Source Context
    df = compute_source_context(df)

    # 7. Compute F6 Kill Chain History
    df = compute_kill_chain_history(df)

    # 8. Add actor_id for GroupKFold (use src_ip as actor)
    df = df.with_columns(pl.col('src_ip').cast(pl.Utf8).alias('actor_id'))

    # 9. Binary label: attack(1-3)/dirty → 1, clean/norm(0,5) → 0
    # Keep raw label for train_xgb.py mapping (it does y_raw==5 → 0, else → 1)
    # So label=5 → clean(0), label=1 → evil(1). Already correct.

    # 10. Select final columns
    keep_cols = SESSION_FEAT_COLS + ['actor_id', 'label', 'label_confidence', 'src_ip', 'dst_ip', 'dst_port']
    # Only keep columns that exist
    keep_cols = [c for c in keep_cols if c in df.columns]
    df = df.select(keep_cols)

    # Fill any remaining nulls
    for col in SESSION_FEAT_COLS:
        if col in df.columns:
            df = df.with_columns(pl.col(col).fill_null(0))

    # Shuffle
    df = df.sample(fraction=1.0, seed=42, shuffle=True)

    feat_cols = [c for c in SESSION_FEAT_COLS if c in df.columns]
    print(f'\nFeatures: {len(feat_cols)}')
    print(f'Feature names: {feat_cols}')

    # Write parquet (faster than CSV for large data)
    out_path = os.path.join(data_dir, 'session_v1_training.parquet')
    print(f'\nWriting {out_path} ...')
    df.write_parquet(out_path)
    size_mb = os.path.getsize(out_path) / 1e6
    print(f'Done: {len(df):,} rows, {size_mb:.0f} MB ({time.time()-t_start:.1f}s total)')

    # Also write CSV for train_xgb.py compatibility
    csv_path = os.path.join(data_dir, 'session_v1_training.csv')
    print(f'Writing CSV: {csv_path} ...')
    df.write_csv(csv_path)
    csv_mb = os.path.getsize(csv_path) / 1e6
    print(f'CSV: {csv_mb:.0f} MB')

    print(f'\nTrain command:')
    print(f'  python3 -u /sdb-disk/ml/train_xgb.py {csv_path} --folds 5 --gpu --evil --scale-pos-weight 5.0 --session')


if __name__ == '__main__':
    main()
