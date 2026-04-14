#!/usr/bin/env python3
"""Prepare conversation_v1 training parquet: static features + 12-channel turn sequences.

Runs on Test (polars, 252GB RAM, 72 cores).
Pattern: prep_session_v1.py / prep_cnn_evil_03.py

Steps:
  1. Load conversations.csv (42 static features + metadata)
  2. Load turns.csv (12 channel tokens per turn)
  3. Pivot turns into 12 x 256 = 3,072 positional sequence columns
  4. Load labels.csv and join
  5. Add training columns: actor_id, label, label_confidence
  6. Drop identity columns, fill nulls, shuffle
  7. Write parquet

Usage:
    python3 -u prep_conversation_v1.py /path/to/conv/ -o conversation_v1_training.parquet
    python3 -u prep_conversation_v1.py /path/to/conv/ -o training.parquet --max-turns 256
"""
import argparse
import os
import sys
import time

import polars as pl

# 12 turn channels: (csv_column, output_prefix)
CHANNELS = [
    ('ch_service_target',   'svc_seq'),
    ('ch_flow_outcome',     'outcome_seq'),
    ('ch_xgb_prediction',   'xgb_pred_seq'),
    ('ch_xgb_confidence',   'xgb_conf_seq'),
    ('ch_cnn_prediction',   'cnn_pred_seq'),
    ('ch_cnn_confidence',   'cnn_conf_seq'),
    ('ch_model_agreement',  'agree_seq'),
    ('ch_turn_duration',    'dur_seq'),
    ('ch_inter_turn_gap',   'gap_seq'),
    ('ch_data_volume',      'vol_seq'),
    ('ch_data_direction',   'dir_seq'),
    ('ch_port_novelty',     'novelty_seq'),
]

# Identity / metadata columns to drop from final training data
DROP_IDENTITY_COLS = [
    'conversation_id', 'src_ip', 'first_ts', 'last_ts',
    'assembled_at', 'labeled_at', 'label_source', 'label_detail', 'label_tier',
]

NULL_VALUES = [r'\N', 'NULL', '']


def pivot_channel(turns_grouped, ch_col, prefix, max_turns):
    """Pivot one channel from long turns into wide positional columns.

    Args:
        turns_grouped: dict of conversation_id -> list of (turn_idx, value) sorted by turn_idx
        ch_col: source column name in turns.csv
        prefix: output column prefix (e.g. 'svc_seq')
        max_turns: number of positional columns to create

    Returns:
        polars DataFrame with columns: conversation_id, {prefix}_0 .. {prefix}_{max_turns-1}
    """
    t0 = time.time()
    print(f'  {ch_col} -> {prefix}_0..{prefix}_{max_turns-1} ...', flush=True)

    conv_ids = []
    # Pre-allocate a list of lists for each position
    position_data = [[] for _ in range(max_turns)]

    for conv_id, turn_values in turns_grouped.items():
        conv_ids.append(conv_id)
        # turn_values is already sorted list of floats, padded/truncated to max_turns
        for i in range(max_turns):
            if i < len(turn_values):
                position_data[i].append(turn_values[i])
            else:
                position_data[i].append(0.0)

    # Build DataFrame: conversation_id + positional columns
    schema = {'conversation_id': pl.Utf8}
    data = {'conversation_id': conv_ids}
    for i in range(max_turns):
        col_name = f'{prefix}_{i}'
        data[col_name] = position_data[i]
        schema[col_name] = pl.Float32

    result = pl.DataFrame(data, schema=schema)
    print(f'    done {time.time()-t0:.1f}s ({len(conv_ids):,} conversations)', flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(
        description='Prepare conversation_v1 training parquet')
    parser.add_argument('input_dir', help='Directory with conversations.csv, turns.csv, labels.csv')
    parser.add_argument('-o', '--output', default='conversation_v1_training.parquet',
                        help='Output filename (default: conversation_v1_training.parquet)')
    parser.add_argument('--max-turns', type=int, default=256,
                        help='Max turn positions per conversation (default: 256)')
    args = parser.parse_args()

    input_dir = args.input_dir
    max_turns = args.max_turns
    t_start = time.time()

    print(f'=== prep_conversation_v1: {max_turns} turn positions x 12 channels ===\n', flush=True)
    print(f'Input:  {input_dir}', flush=True)

    # Resolve output path: if relative, place inside input_dir
    if os.path.isabs(args.output):
        out_path = args.output
    else:
        out_path = os.path.join(input_dir, args.output)
    print(f'Output: {out_path}', flush=True)
    print(flush=True)

    # ------------------------------------------------------------------
    # 1. Load CSVs
    # ------------------------------------------------------------------
    print('Loading CSVs ...', flush=True)

    t0 = time.time()
    convs = pl.read_csv(
        os.path.join(input_dir, 'conversations.csv'),
        infer_schema_length=10000,
        null_values=NULL_VALUES,
        try_parse_dates=False,
    )
    print(f'  conversations.csv: {len(convs):,} rows, {len(convs.columns)} cols ({time.time()-t0:.1f}s)', flush=True)

    t0 = time.time()
    turns = pl.read_csv(
        os.path.join(input_dir, 'turns.csv'),
        infer_schema_length=10000,
        null_values=NULL_VALUES,
        try_parse_dates=False,
    )
    print(f'  turns.csv: {len(turns):,} rows, {len(turns.columns)} cols ({time.time()-t0:.1f}s)', flush=True)

    t0 = time.time()
    labels = pl.read_csv(
        os.path.join(input_dir, 'labels.csv'),
        infer_schema_length=10000,
        null_values=NULL_VALUES,
        try_parse_dates=False,
    )
    print(f'  labels.csv: {len(labels):,} rows, {len(labels.columns)} cols ({time.time()-t0:.1f}s)', flush=True)
    print(flush=True)

    # ------------------------------------------------------------------
    # 2. Cast turn channel columns to Float32
    # ------------------------------------------------------------------
    print('Casting turn channels to Float32 ...', flush=True)
    ch_cols = [ch for ch, _ in CHANNELS]
    cast_exprs = []
    for ch in ch_cols:
        if ch in turns.columns:
            cast_exprs.append(
                pl.col(ch).cast(pl.Float32, strict=False).fill_null(0.0).alias(ch)
            )
    if cast_exprs:
        turns = turns.with_columns(cast_exprs)

    # Ensure conversation_id is string for consistent joining
    if 'conversation_id' in turns.columns:
        turns = turns.with_columns(pl.col('conversation_id').cast(pl.Utf8))
    if 'conversation_id' in convs.columns:
        convs = convs.with_columns(pl.col('conversation_id').cast(pl.Utf8))
    if 'conversation_id' in labels.columns:
        labels = labels.with_columns(pl.col('conversation_id').cast(pl.Utf8))

    # Ensure turn_idx exists and is numeric for ordering
    if 'turn_idx' in turns.columns:
        turns = turns.with_columns(
            pl.col('turn_idx').cast(pl.Int32, strict=False).fill_null(0)
        )
    else:
        # If no turn_idx, generate row-based index within each conversation
        turns = turns.with_columns(
            pl.arange(0, pl.len()).over('conversation_id').cast(pl.Int32).alias('turn_idx')
        )

    # Sort turns by conversation_id, turn_idx for ordered grouping
    turns = turns.sort(['conversation_id', 'turn_idx'])

    # ------------------------------------------------------------------
    # 3. Build grouped turn data: conversation_id -> ordered channel values
    # ------------------------------------------------------------------
    print(f'\nBuilding per-conversation turn groups ({len(turns):,} rows) ...', flush=True)
    t0 = time.time()

    # Group by conversation_id and collect each channel as a list
    # This is more memory-efficient than iterating row by row
    grouped = {}  # conv_id -> {ch_col: [values]}

    # Pre-group: for each conversation, store ordered values per channel
    # Use polars group_by + agg for speed
    agg_exprs = [pl.col(ch).alias(ch) for ch in ch_cols if ch in turns.columns]
    turn_groups = turns.group_by('conversation_id', maintain_order=True).agg(agg_exprs)

    # Convert to dict: conv_id -> {ch_col: list_of_values}
    for row in turn_groups.iter_rows(named=True):
        conv_id = row['conversation_id']
        grouped[conv_id] = {}
        for ch in ch_cols:
            if ch in row and row[ch] is not None:
                vals = list(row[ch])
                # Truncate to max_turns, replace None with 0
                vals = [v if v is not None else 0.0 for v in vals[:max_turns]]
                grouped[conv_id][ch] = vals
            else:
                grouped[conv_id][ch] = []

    del turn_groups
    print(f'  Grouped {len(grouped):,} conversations ({time.time()-t0:.1f}s)', flush=True)

    # ------------------------------------------------------------------
    # 4. Pivot each channel into wide positional columns
    # ------------------------------------------------------------------
    print(f'\nPivoting 12 channels x {max_turns} positions ...', flush=True)

    pivot_dfs = []
    for ch_col, prefix in CHANNELS:
        if ch_col not in turns.columns:
            print(f'  WARNING: {ch_col} not in turns.csv — filling zeros', flush=True)
            # Create a zero-filled DataFrame
            conv_ids = list(grouped.keys())
            data = {'conversation_id': conv_ids}
            schema = {'conversation_id': pl.Utf8}
            for i in range(max_turns):
                col_name = f'{prefix}_{i}'
                data[col_name] = [0.0] * len(conv_ids)
                schema[col_name] = pl.Float32
            pivot_dfs.append(pl.DataFrame(data, schema=schema))
            continue

        # Build per-channel grouped data
        ch_grouped = {}
        for conv_id, channels in grouped.items():
            ch_grouped[conv_id] = channels.get(ch_col, [])

        pivot_df = pivot_channel(ch_grouped, ch_col, prefix, max_turns)
        pivot_dfs.append(pivot_df)
        del ch_grouped

    # Free grouped data
    del grouped, turns
    print(flush=True)

    # ------------------------------------------------------------------
    # 5. Join all pivoted channels together on conversation_id
    # ------------------------------------------------------------------
    print('Joining pivoted channels ...', flush=True)
    t0 = time.time()

    seq_df = pivot_dfs[0]
    for pdf in pivot_dfs[1:]:
        seq_df = seq_df.join(pdf, on='conversation_id', how='left')
    del pivot_dfs

    n_seq_cols = len(seq_df.columns) - 1  # minus conversation_id
    print(f'  Sequence columns: {n_seq_cols:,} ({time.time()-t0:.1f}s)', flush=True)

    # ------------------------------------------------------------------
    # 6. Join static features from conversations.csv
    # ------------------------------------------------------------------
    print('\nJoining static features ...', flush=True)
    t0 = time.time()

    df = seq_df.join(convs, on='conversation_id', how='left')
    del seq_df, convs
    print(f'  After static join: {len(df):,} rows, {len(df.columns)} cols ({time.time()-t0:.1f}s)', flush=True)

    # ------------------------------------------------------------------
    # 7. Join labels
    # ------------------------------------------------------------------
    print('\nJoining labels ...', flush=True)
    t0 = time.time()

    # Ensure label and label_confidence are numeric
    for col in ['label', 'label_confidence']:
        if col in labels.columns:
            labels = labels.with_columns(
                pl.col(col).cast(pl.Float32, strict=False).fill_null(0.0)
            )

    df = df.join(labels, on='conversation_id', how='inner')
    del labels
    print(f'  After label join: {len(df):,} rows, {len(df.columns)} cols ({time.time()-t0:.1f}s)', flush=True)

    # ------------------------------------------------------------------
    # 8. Add training columns
    # ------------------------------------------------------------------
    print('\nAdding training columns ...', flush=True)

    # actor_id = src_ip (for GroupKFold)
    if 'src_ip' in df.columns:
        df = df.with_columns(pl.col('src_ip').cast(pl.Utf8).alias('actor_id'))
    else:
        print('  WARNING: src_ip not found — actor_id set to conversation_id', flush=True)
        df = df.with_columns(pl.col('conversation_id').cast(pl.Utf8).alias('actor_id'))

    # ------------------------------------------------------------------
    # 9. Drop identity columns
    # ------------------------------------------------------------------
    drop_existing = [c for c in DROP_IDENTITY_COLS if c in df.columns]
    if drop_existing:
        print(f'  Dropping {len(drop_existing)} identity cols: {drop_existing}', flush=True)
        df = df.drop(drop_existing)

    # ------------------------------------------------------------------
    # 10. Cast all numeric columns to Float32, fill nulls with 0
    # ------------------------------------------------------------------
    print('\nCasting numeric columns to Float32 and filling nulls ...', flush=True)
    t0 = time.time()

    skip_cols = {'actor_id', 'label', 'label_confidence'}
    cast_exprs = []
    for col in df.columns:
        if col in skip_cols:
            continue
        dtype = df[col].dtype
        if dtype in (pl.Float64, pl.Float32, pl.Int8, pl.Int16, pl.Int32, pl.Int64,
                     pl.UInt8, pl.UInt16, pl.UInt32, pl.UInt64):
            cast_exprs.append(
                pl.col(col).cast(pl.Float32, strict=False).fill_null(0.0).alias(col)
            )
        elif dtype == pl.Utf8:
            # Try casting string columns to Float32
            cast_exprs.append(
                pl.col(col).cast(pl.Float32, strict=False).fill_null(0.0).alias(col)
            )
    if cast_exprs:
        df = df.with_columns(cast_exprs)

    print(f'  Done ({time.time()-t0:.1f}s)', flush=True)

    # ------------------------------------------------------------------
    # 11. Shuffle
    # ------------------------------------------------------------------
    print('\nShuffling ...', flush=True)
    df = df.sample(fraction=1.0, seed=42, shuffle=True)

    # ------------------------------------------------------------------
    # 12. Summary
    # ------------------------------------------------------------------
    seq_cols = [c for c in df.columns if any(c.startswith(p + '_') for _, p in CHANNELS)]
    meta_cols = [c for c in df.columns if c in ('actor_id', 'label', 'label_confidence')]
    static_cols = [c for c in df.columns if c not in seq_cols and c not in meta_cols]

    print(f'\n{"="*60}', flush=True)
    print(f'SUMMARY', flush=True)
    print(f'{"="*60}', flush=True)
    print(f'  Total conversations: {len(df):,}', flush=True)
    print(f'  Total columns:       {len(df.columns):,}', flush=True)
    print(f'    Sequence columns:  {len(seq_cols):,} (12 x {max_turns})', flush=True)
    print(f'    Static features:   {len(static_cols):,}', flush=True)
    print(f'    Training meta:     {len(meta_cols):,} (actor_id, label, label_confidence)', flush=True)

    # Class distribution
    if 'label' in df.columns:
        print(f'\n  Class distribution:', flush=True)
        dist = df.group_by('label').len().sort('label')
        for row in dist.iter_rows(named=True):
            lbl = row['label']
            cnt = row['len']
            pct = 100.0 * cnt / len(df)
            print(f'    label={lbl}: {cnt:,} ({pct:.1f}%)', flush=True)

    # ------------------------------------------------------------------
    # 13. Write parquet
    # ------------------------------------------------------------------
    print(f'\nWriting {out_path} ...', flush=True)
    t0 = time.time()
    df.write_parquet(out_path, compression='zstd')
    size_mb = os.path.getsize(out_path) / 1e6
    print(f'  Written: {len(df):,} rows, {len(df.columns)} cols, {size_mb:.1f} MB ({time.time()-t0:.1f}s)', flush=True)
    print(f'\nTotal time: {time.time()-t_start:.0f}s', flush=True)


if __name__ == '__main__':
    main()
