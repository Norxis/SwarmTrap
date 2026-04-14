/* Auto-generated feature mapping: model index → ARM features.c index */
/* Model: /opt/dfi2/ml/models/5class_20260318_181733.json (50 features) */
/* ARM: features.c (75 features) */

#ifndef DFI_FEATURE_MAP_H_
#define DFI_FEATURE_MAP_H_

#define MODEL_FEAT_COUNT 50

/* FEAT_MAP[model_index] = ARM features[] index */
static const int FEAT_MAP[50] = {
      0,  /* [ 0] dst_port */
      1,  /* [ 1] ip_proto */
      2,  /* [ 2] app_proto */
      3,  /* [ 3] pkts_fwd */
      4,  /* [ 4] pkts_rev */
      5,  /* [ 5] bytes_fwd */
      6,  /* [ 6] bytes_rev */
     12,  /* [ 7] rtt_ms */
     11,  /* [ 8] duration_ms */
     13,  /* [ 9] iat_fwd_mean_ms */
     14,  /* [10] iat_fwd_std_ms */
     15,  /* [11] think_time_mean_ms */
     16,  /* [12] think_time_std_ms */
     17,  /* [13] iat_to_rtt */
     18,  /* [14] pps */
     19,  /* [15] bps */
     20,  /* [16] payload_rtt_ratio */
     21,  /* [17] n_events */
     22,  /* [18] fwd_size_mean */
     23,  /* [19] fwd_size_std */
     24,  /* [20] fwd_size_min */
     25,  /* [21] fwd_size_max */
     26,  /* [22] rev_size_mean */
     27,  /* [23] rev_size_std */
     28,  /* [24] rev_size_max */
     29,  /* [25] hist_tiny */
     30,  /* [26] hist_small */
     31,  /* [27] hist_medium */
     32,  /* [28] hist_large */
     33,  /* [29] hist_full */
     34,  /* [30] frac_full */
     35,  /* [31] syn_count */
     36,  /* [32] fin_count */
     37,  /* [33] rst_count */
     38,  /* [34] psh_count */
     39,  /* [35] ack_only_count */
     40,  /* [36] conn_state */
     41,  /* [37] rst_frac */
     42,  /* [38] syn_to_data */
     43,  /* [39] psh_burst_max */
     44,  /* [40] retransmit_est */
     45,  /* [41] window_size_init */
     46,  /* [42] entropy_first */
     47,  /* [43] entropy_fwd_mean */
     48,  /* [44] entropy_rev_mean */
     49,  /* [45] printable_frac */
     50,  /* [46] null_frac */
     51,  /* [47] byte_std */
     52,  /* [48] high_entropy_frac */
     53,  /* [49] payload_len_first */
};

/* Model feature names (for verification) */
static const char *MODEL_FEAT_NAMES[50] = {
    "dst_port",
    "ip_proto",
    "app_proto",
    "pkts_fwd",
    "pkts_rev",
    "bytes_fwd",
    "bytes_rev",
    "rtt_ms",
    "duration_ms",
    "iat_fwd_mean_ms",
    "iat_fwd_std_ms",
    "think_time_mean_ms",
    "think_time_std_ms",
    "iat_to_rtt",
    "pps",
    "bps",
    "payload_rtt_ratio",
    "n_events",
    "fwd_size_mean",
    "fwd_size_std",
    "fwd_size_min",
    "fwd_size_max",
    "rev_size_mean",
    "rev_size_std",
    "rev_size_max",
    "hist_tiny",
    "hist_small",
    "hist_medium",
    "hist_large",
    "hist_full",
    "frac_full",
    "syn_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "ack_only_count",
    "conn_state",
    "rst_frac",
    "syn_to_data",
    "psh_burst_max",
    "retransmit_est",
    "window_size_init",
    "entropy_first",
    "entropy_fwd_mean",
    "entropy_rev_mean",
    "printable_frac",
    "null_frac",
    "byte_std",
    "high_entropy_frac",
    "payload_len_first",
};

#endif /* DFI_FEATURE_MAP_H_ */
