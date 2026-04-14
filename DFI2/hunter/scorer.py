#!/usr/bin/env python3
"""Inline scorers: XGBoost (legacy) and CNN (active)."""
import logging
import os

import numpy as np

log = logging.getLogger('hunter.scorer')


class InlineScorer:
    """Loads an XGBoost Booster and scores feature dicts in <1ms."""

    def __init__(self, model_path: str):
        import xgboost as xgb

        if not os.path.isfile(model_path):
            raise FileNotFoundError(f'XGB model not found: {model_path}')

        self._booster = xgb.Booster({'nthread': 80})
        self._booster.load_model(model_path)
        self._model_feats = self._booster.feature_names
        self.model_version = os.path.basename(model_path)
        self._xgb = xgb
        log.info('scorer_loaded model=%s feats=%d', self.model_version, len(self._model_feats))

    def predict(self, feat: dict) -> dict:
        """Score a single feature dict. Missing keys become NaN (XGBoost handles natively).

        Returns dict with keys: label, confidence, prob_attack, class_probs
        """
        row = [float(feat.get(f) if feat.get(f) is not None else 0.0)
               for f in self._model_feats]
        dmat = self._xgb.DMatrix(
            np.array([row], dtype=np.float32),
            feature_names=self._model_feats,
            nthread=80,
        )
        raw = self._booster.predict(dmat)[0]
        if isinstance(raw, np.ndarray):
            # Multi-class: raw is array of probabilities
            class_probs = [float(p) for p in raw]
            label = int(np.argmax(raw))
            confidence = float(raw[label])
            prob_attack = 1.0 - float(raw[0])  # 1 - P(normal)
        else:
            # Binary: raw is scalar probability
            prob_attack = float(raw)
            label = 1 if prob_attack > 0.5 else 0
            confidence = prob_attack if label == 1 else 1.0 - prob_attack
            class_probs = [1.0 - prob_attack, prob_attack]
        return {
            'label': label,
            'confidence': confidence,
            'prob_attack': prob_attack,
            'class_probs': class_probs,
        }


class InlineCNNScorer:
    """Inline CNN scorer — packet sequences (5 channels × 128) + 42 static features."""

    SEQ_LEN = 128
    STATIC_COLS = [
        'dst_port', 'ip_proto', 'app_proto', 'pkts_fwd', 'pkts_rev', 'bytes_fwd', 'bytes_rev',
        'rtt_ms', 'n_events', 'duration_ms', 'pps', 'bps',
        'entropy_first', 'entropy_fwd_mean', 'entropy_rev_mean', 'printable_frac', 'null_frac',
        'byte_std', 'high_entropy_frac', 'payload_len_first',
        'fwd_size_mean', 'fwd_size_std', 'fwd_size_min', 'fwd_size_max',
        'rev_size_mean', 'rev_size_std', 'rev_size_max',
        'hist_tiny', 'hist_small', 'hist_medium', 'hist_large', 'hist_full', 'frac_full',
        'syn_count', 'fin_count', 'rst_count', 'psh_count', 'ack_only_count',
        'conn_state', 'rst_frac', 'syn_to_data', 'psh_burst_max', 'retransmit_est', 'window_size_init',
        'iat_fwd_mean_ms', 'iat_fwd_std_ms', 'think_time_mean_ms', 'think_time_std_ms',
        'iat_to_rtt', 'payload_rtt_ratio',
    ]

    def __init__(self, model_path: str):
        import torch
        import torch.nn as nn

        if not os.path.isfile(model_path):
            raise FileNotFoundError(f'CNN model not found: {model_path}')

        class _DFI_CNN(nn.Module):
            def __init__(self):
                super().__init__()
                self.size_emb = nn.Embedding(24, 12, padding_idx=0)
                self.flag_emb = nn.Embedding(17, 6, padding_idx=0)
                self.iat_emb  = nn.Embedding(9,  6, padding_idx=0)
                self.rtt_emb  = nn.Embedding(10, 6, padding_idx=0)
                self.ent_emb  = nn.Embedding(7,  4, padding_idx=0)
                self.conv3 = nn.Sequential(nn.Conv1d(34, 32, 3, padding=1), nn.BatchNorm1d(32), nn.ReLU())
                self.conv5 = nn.Sequential(nn.Conv1d(34, 32, 5, padding=2), nn.BatchNorm1d(32), nn.ReLU())
                self.conv7 = nn.Sequential(nn.Conv1d(34, 32, 7, padding=3), nn.BatchNorm1d(32), nn.ReLU())
                self.merge = nn.Sequential(nn.Conv1d(96, 128, 5, padding=2), nn.BatchNorm1d(128), nn.ReLU(), nn.AdaptiveMaxPool1d(1))
                self.static_bn = nn.BatchNorm1d(50)
                self.head = nn.Sequential(nn.Linear(178, 128), nn.ReLU(), nn.Dropout(0.3), nn.Linear(128, 3))

            def forward(self, size_seq, flag_seq, iat_seq, rtt_seq, ent_seq, static_feat):
                x = torch.cat([self.size_emb(size_seq), self.flag_emb(flag_seq),
                                self.iat_emb(iat_seq), self.rtt_emb(rtt_seq),
                                self.ent_emb(ent_seq)], dim=2).transpose(1, 2)
                x = x * (size_seq != 0).unsqueeze(1).float()
                x = torch.cat([self.conv3(x), self.conv5(x), self.conv7(x)], dim=1)
                x = self.merge(x).squeeze(2)
                return self.head(torch.cat([x, self.static_bn(static_feat)], dim=1))

        self._torch = torch
        self._model = _DFI_CNN()
        self._model.load_state_dict(torch.load(model_path, map_location='cpu', weights_only=True))
        self._model.eval()
        self.model_version = os.path.basename(model_path)
        log.info('cnn_scorer_loaded model=%s', self.model_version)

    def predict(self, feat: dict, pkt_tokens: list) -> dict:
        """Score one flow. pkt_tokens from tokenize_packets(). Missing static features → 0."""
        n = min(len(pkt_tokens), self.SEQ_LEN)
        size_arr = np.zeros(self.SEQ_LEN, dtype=np.int64)
        flag_arr = np.zeros(self.SEQ_LEN, dtype=np.int64)
        iat_arr  = np.zeros(self.SEQ_LEN, dtype=np.int64)
        rtt_arr  = np.zeros(self.SEQ_LEN, dtype=np.int64)
        ent_arr  = np.zeros(self.SEQ_LEN, dtype=np.int64)
        for i in range(n):
            t = pkt_tokens[i]
            raw = int(t['size_dir_token'])
            size_arr[i] = 0 if raw == 0 else (raw + 12)  # +12 offset: matches training
            flag_arr[i] = int(t['flag_token'])
            iat_arr[i]  = int(t['iat_log_ms_bin'])
            rtt_arr[i]  = int(t['iat_rtt_bin'])
            ent_arr[i]  = int(t['entropy_bin'])

        static = np.array([float(feat.get(c) or 0.0) for c in self.STATIC_COLS], dtype=np.float32)

        with self._torch.no_grad():
            logits = self._model(
                self._torch.tensor(size_arr[None], dtype=self._torch.long),
                self._torch.tensor(flag_arr[None], dtype=self._torch.long),
                self._torch.tensor(iat_arr[None],  dtype=self._torch.long),
                self._torch.tensor(rtt_arr[None],  dtype=self._torch.long),
                self._torch.tensor(ent_arr[None],  dtype=self._torch.long),
                self._torch.tensor(static[None],   dtype=self._torch.float32),
            )
            probs = self._torch.softmax(logits, dim=1).numpy()[0]

        label = int(np.argmax(probs))
        confidence = float(probs[label])
        prob_attack = 1.0 - float(probs[0])  # 1 - P(clean)
        return {
            'label': label,
            'confidence': confidence,
            'prob_attack': prob_attack,
            'class_probs': [float(p) for p in probs],
        }
