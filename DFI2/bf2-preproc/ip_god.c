/*
 * ip_god.c — GOD sees every IP, scores every flow.
 *
 * Single C file. DPDK. 6K IPs/sec, 250K pkt/s.
 * Packet → parse → upsert IP → track flow → 10 pkts → XGB → update IP
 * NATS PUB scores → CH. Verdict file → eSwitch DROP + evict.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <math.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdatomic.h>
#include <arpa/inet.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_flow.h>

static volatile int quit = 0;
static void sig(int s) { quit = 1; }

/* ============================================================
 * HONEYPOT IPs
 * ============================================================ */
#define HP_MAX 256
static uint32_t hp_ips[HP_MAX];
static int hp_count = 0;
static void hp_add(uint32_t ip) {
    /* Dedup */
    for (int i = 0; i < hp_count; i++) if (hp_ips[i] == ip) return;
    if (hp_count < HP_MAX) hp_ips[hp_count++] = ip;
}
static int is_honeypot(uint32_t ip) {
    for (int i = 0; i < hp_count; i++) if (hp_ips[i] == ip) return 1;
    return 0;
}
static void load_honeypots(void) {
    for (int i = 128; i < 192; i++) hp_add((216u<<24)|(126u<<16)|i);
    uint8_t s[] = {200,201,206,210,211,212,213,214,215,216,217,218,219,145};
    for (int i = 0; i < 14; i++) hp_add((216u<<24)|(126u<<16)|s[i]);
    hp_add((108u<<24)|(181u<<16)|(161u<<8)|199u);
}

/* ============================================================
 * XGB MODEL — binary loader + tree prediction
 * ============================================================ */
typedef struct { int32_t left, right; uint16_t feature; float value, leaf; } XNode;

static struct {
    XNode *nodes;
    uint32_t *tree_off;
    uint32_t n_trees, n_classes, n_features, n_nodes;
} xgb;

static int xgb_load(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    uint32_t hdr[4];
    if (fread(hdr, 4, 4, fp) != 4) { fclose(fp); return -1; }
    if (hdr[0] != 0x58474231) { fclose(fp); return -1; }
    xgb.n_trees = hdr[1]; xgb.n_classes = hdr[2]; xgb.n_features = hdr[3];

    long pos = ftell(fp);
    fseek(fp, 0, SEEK_END);
    size_t data_sz = ftell(fp) - pos;
    fseek(fp, pos, SEEK_SET);
    uint8_t *data = malloc(data_sz);
    if (fread(data, 1, data_sz, fp) != data_sz) { fclose(fp); free(data); return -1; }
    fclose(fp);

    /* Format: [tree_size(4)] [nodes(18 each)] repeated per tree */
    uint32_t total = 0;
    size_t off = 0;
    for (uint32_t t = 0; t < xgb.n_trees; t++) {
        uint32_t sz; memcpy(&sz, data + off, 4); off += 4;
        total += sz;
        off += sz * 18;
    }

    xgb.n_nodes = total;
    xgb.tree_off = malloc(xgb.n_trees * 4);
    xgb.nodes = malloc(total * sizeof(XNode));

    off = 0;
    uint32_t ni = 0;
    for (uint32_t t = 0; t < xgb.n_trees; t++) {
        uint32_t sz; memcpy(&sz, data + off, 4); off += 4;
        xgb.tree_off[t] = ni;
        for (uint32_t n = 0; n < sz; n++) {
            uint8_t *r = data + off;
            uint16_t feat; float val, leaf; int32_t left, right;
            memcpy(&feat, r, 2); memcpy(&val, r+2, 4);
            memcpy(&left, r+6, 4); memcpy(&right, r+10, 4); memcpy(&leaf, r+14, 4);
            xgb.nodes[ni++] = (XNode){left, right, feat, val, leaf};
            off += 18;
        }
    }
    free(data);
    printf("XGB: %u trees, %u classes, %u features, %u nodes\n",
           xgb.n_trees, xgb.n_classes, xgb.n_features, xgb.n_nodes);
    return 0;
}

static void xgb_predict(const float *feat, uint8_t *cls, float *conf) {
    float scores[16] = {0};
    for (uint32_t t = 0; t < xgb.n_trees; t++) {
        XNode *tree = &xgb.nodes[xgb.tree_off[t]];
        int n = 0;
        for (int d = 0; d < 32; d++) {
            if (tree[n].left == -1) { scores[t % xgb.n_classes] += tree[n].leaf; break; }
            uint16_t fi = tree[n].feature;
            float fv = (fi < xgb.n_features) ? feat[fi] : NAN;
            if (isnan(fv)) n = tree[n].left;
            else if (fv < tree[n].value) n = tree[n].left;
            else n = tree[n].right;
        }
    }
    float mx = scores[0];
    for (uint32_t c = 1; c < xgb.n_classes; c++) if (scores[c] > mx) mx = scores[c];
    float sum = 0;
    for (uint32_t c = 0; c < xgb.n_classes; c++) { scores[c] = expf(scores[c]-mx); sum += scores[c]; }
    float best = 0; uint8_t best_c = 0;
    for (uint32_t c = 0; c < xgb.n_classes; c++) {
        scores[c] /= sum;
        if (scores[c] > best) { best = scores[c]; best_c = c; }
    }
    *cls = best_c; *conf = best;
}

/* ============================================================
 * FLOW TRACKER
 * ============================================================ */
#define FLOW_MAX 524288
#define FLOW_MASK (FLOW_MAX - 1)
#define FLOW_SCORE_PKTS 10
#define FLOW_EXPIRE_NS (60ULL * 1000000000ULL)  /* 60 seconds idle → expire */

typedef struct {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t  proto, scored, _pad[2];
    uint32_t pkts_fwd, pkts_rev, bytes_fwd, bytes_rev;
    uint64_t first_ts, last_ts, prev_ts;
    float    iat_sum, iat_sq_sum;
    uint16_t n_iat;
    uint16_t dst_port_feat;
    uint16_t syn, fin, rst, psh, ack_only;
    uint8_t  app_proto, _pad2;
    /* Size stats for features */
    uint32_t fwd_size_sum, rev_size_sum;
    uint32_t fwd_size_min, fwd_size_max;
    uint32_t rev_size_max;
    uint16_t fwd_pkt_count, rev_pkt_count;  /* for mean calc */
} Flow;

static Flow *flows;
static uint32_t flow_count = 0;
static uint32_t flows_expired = 0;

static uint8_t port_to_proto(uint16_t port) {
    switch(port) {
        case 22: return 1; case 80: case 8080: case 8443: return 2;
        case 443: return 3; case 3389: return 4; case 3306: return 5;
        case 6379: return 6; case 445: return 7; default: return 0;
    }
}

static uint32_t flow_hash(uint32_t a, uint32_t b, uint16_t c, uint16_t d, uint8_t p) {
    uint32_t h = 2166136261u;
    h ^= a; h *= 16777619u; h ^= b; h *= 16777619u;
    h ^= c; h *= 16777619u; h ^= d; h *= 16777619u;
    h ^= p; h *= 16777619u;
    return h & FLOW_MASK;
}

static Flow *flow_get(uint32_t src, uint32_t dst, uint16_t sp, uint16_t dp, uint8_t proto, uint64_t ts) {
    uint32_t h = flow_hash(src, dst, sp, dp, proto);
    for (int i = 0; i < 64; i++) {
        uint32_t idx = (h + i) & FLOW_MASK;
        Flow *f = &flows[idx];
        if (f->src_ip == src && f->dst_ip == dst && f->src_port == sp &&
            f->dst_port == dp && f->proto == proto) return f;
        if (f->src_ip == 0) {
            f->src_ip = src; f->dst_ip = dst; f->src_port = sp;
            f->dst_port = dp; f->proto = proto;
            f->first_ts = ts; f->last_ts = ts; f->prev_ts = ts;
            f->dst_port_feat = dp;
            f->app_proto = port_to_proto(dp);
            flow_count++;
            return f;
        }
    }
    return NULL;
}

/* Expire idle flows — reclaim slots */
static void flow_expire(uint64_t now_ns) {
    uint32_t expired = 0;
    for (uint32_t i = 0; i < FLOW_MAX; i++) {
        if (flows[i].src_ip != 0 && (now_ns - flows[i].last_ts) > FLOW_EXPIRE_NS) {
            memset(&flows[i], 0, sizeof(Flow));
            flow_count--;
            expired++;
        }
    }
    if (expired > 0) flows_expired += expired;
}

static void flow_to_features(const Flow *f, float *feat, int n_feat) {
    for (int i = 0; i < n_feat; i++) feat[i] = NAN;

    float dur_ms = (f->last_ts > f->first_ts) ? (float)(f->last_ts - f->first_ts) / 1e6f : 0;
    float total_pkts = f->pkts_fwd + f->pkts_rev;
    float total_bytes = f->bytes_fwd + f->bytes_rev;
    float bpp_fwd = f->pkts_fwd > 0 ? (float)f->bytes_fwd / f->pkts_fwd : 0;
    float bpp_rev = f->pkts_rev > 0 ? (float)f->bytes_rev / f->pkts_rev : 0;
    float pkt_ratio = total_pkts > 0 ? (float)f->pkts_fwd / total_pkts : 0.5f;
    float byte_ratio = total_bytes > 0 ? (float)f->bytes_fwd / total_bytes : 0.5f;
    float iat_mean = f->n_iat > 0 ? f->iat_sum / f->n_iat : 0;
    float iat_var = f->n_iat > 1 ? (f->iat_sq_sum - f->iat_sum*f->iat_sum/f->n_iat)/(f->n_iat-1) : 0;
    float iat_std = iat_var > 0 ? sqrtf(iat_var) : 0;
    float pps = dur_ms > 0 ? total_pkts / (dur_ms/1000.0f) : 0;
    float bps = dur_ms > 0 ? total_bytes / (dur_ms/1000.0f) : 0;

    feat[0] = f->dst_port_feat;
    feat[1] = f->proto;
    feat[2] = f->app_proto;
    feat[3] = f->pkts_fwd;
    feat[4] = f->pkts_rev;
    feat[5] = f->bytes_fwd;
    feat[6] = f->bytes_rev;
    feat[7] = bpp_fwd;
    feat[8] = bpp_rev;
    feat[9] = pkt_ratio;
    feat[10] = byte_ratio;
    feat[11] = dur_ms;
    feat[13] = iat_mean;
    feat[14] = iat_std;
    feat[17] = pps;
    feat[18] = bps;
    /* F4: Packet Size Shape */
    feat[20] = total_pkts;                                          /* n_events */
    feat[21] = f->fwd_pkt_count > 0 ? (float)f->fwd_size_sum / f->fwd_pkt_count : 0;  /* fwd_size_mean */
    feat[23] = f->fwd_size_min;                                     /* fwd_size_min */
    feat[24] = f->fwd_size_max;                                     /* fwd_size_max */
    feat[25] = f->rev_pkt_count > 0 ? (float)f->rev_size_sum / f->rev_pkt_count : 0;  /* rev_size_mean */
    feat[27] = f->rev_size_max;                                     /* rev_size_max */
    /* F5: TCP */
    feat[31] = f->syn;
    feat[32] = f->fin;
    feat[33] = f->rst;
    feat[34] = f->psh;
    feat[35] = f->ack_only;
    /* F5 extras */
    if (total_pkts > 0) feat[37] = (float)f->rst / total_pkts;     /* rst_frac */
}

/* ============================================================
 * IP TABLE — 1M entries, mmap, direct write
 * ============================================================ */
#define TABLE_MAX    1048576
#define TABLE_BUCKETS 2097152
#define EMPTY 0xFFFFFFFF

typedef struct {
    uint32_t ip;
    uint8_t  state;
    uint8_t  is_attacker;
    uint8_t  xgb_class;
    uint8_t  app_proto;
    float    xgb_conf;
    uint16_t hit_count;
    uint16_t flow_count;
    uint64_t first_seen;
    uint64_t last_seen;
    uint32_t next;
} IPEntry;

static struct {
    uint32_t magic;
    _Atomic uint32_t count;
    uint32_t max_entries;
    uint32_t buckets_n;
    uint8_t  _pad[48];
} *g_hdr;

static uint32_t *g_buckets;
static IPEntry *g_entries;
static void *g_mmap;
static size_t g_mmap_sz;

static uint32_t iphash(uint32_t ip) {
    uint32_t h = 2166136261u;
    h ^= (ip&0xFF); h *= 16777619u; h ^= ((ip>>8)&0xFF); h *= 16777619u;
    h ^= ((ip>>16)&0xFF); h *= 16777619u; h ^= ((ip>>24)&0xFF); h *= 16777619u;
    return h & (TABLE_BUCKETS - 1);
}

static int table_open(const char *path) {
    size_t hs = 64, bs = TABLE_BUCKETS*4, es = (size_t)TABLE_MAX*sizeof(IPEntry);
    g_mmap_sz = hs + bs + es;
    char dir[256]; snprintf(dir,sizeof(dir),"%s",path);
    char *sl=strrchr(dir,'/'); if(sl){*sl=0;mkdir(dir,0755);}
    int fd = open(path, O_RDWR|O_CREAT, 0644);
    if (fd<0) return -1;
    struct stat st; fstat(fd,&st);
    if ((size_t)st.st_size < g_mmap_sz) ftruncate(fd, g_mmap_sz);
    g_mmap = mmap(NULL, g_mmap_sz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (g_mmap==MAP_FAILED) return -1;
    g_hdr = g_mmap; g_buckets = (uint32_t*)((uint8_t*)g_mmap+hs);
    g_entries = (IPEntry*)((uint8_t*)g_mmap+hs+bs);
    if (g_hdr->magic != 0x474F4432) {
        g_hdr->magic = 0x474F4432;
        atomic_store(&g_hdr->count, 0);
        g_hdr->max_entries = TABLE_MAX; g_hdr->buckets_n = TABLE_BUCKETS;
        for (uint32_t i=0;i<TABLE_BUCKETS;i++) g_buckets[i]=EMPTY;
        for (uint32_t i=0;i<TABLE_MAX;i++) { g_entries[i].ip=0; g_entries[i].next=EMPTY; }
        msync(g_mmap, g_mmap_sz, MS_SYNC);
        printf("Table: new (1M × %zu = %.0fMB)\n", sizeof(IPEntry), g_mmap_sz/1e6);
    } else {
        printf("Table: existing (%u IPs)\n", atomic_load(&g_hdr->count));
    }
    return 0;
}

static void table_upsert(uint32_t ip, int attacker, uint8_t xclass, float xconf,
                          uint8_t app_proto, uint64_t now) {
    if (!ip) return;
    uint32_t b = iphash(ip);
    uint32_t idx = g_buckets[b];
    for (int d=0; idx!=EMPTY && d<64; d++) {
        if (idx>=TABLE_MAX) break;
        IPEntry *e = &g_entries[idx];
        if (e->ip == ip) {
            e->last_seen = now;
            if (e->hit_count < 65535) e->hit_count++;
            if (attacker && !e->is_attacker) { e->is_attacker=1; e->state=2; }
            if (xconf > e->xgb_conf) { e->xgb_class=xclass; e->xgb_conf=xconf; }
            if (e->state==0 && xconf>=0.70f) e->state=1;
            return;
        }
        idx = e->next;
    }
    uint32_t c = atomic_load(&g_hdr->count);
    if (c >= TABLE_MAX) return;  /* TODO: eviction */
    int32_t slot = -1;
    for (uint32_t i=0; i<TABLE_MAX; i++) {
        uint32_t si = (c+i)%TABLE_MAX;
        if (g_entries[si].ip==0) { slot=si; break; }
    }
    if (slot<0) return;
    IPEntry *e = &g_entries[slot];
    *e = (IPEntry){.ip=ip, .state=attacker?2:0, .is_attacker=attacker,
                   .xgb_class=xclass, .xgb_conf=xconf, .app_proto=app_proto,
                   .hit_count=1, .flow_count=0, .first_seen=now, .last_seen=now,
                   .next=g_buckets[b]};
    g_buckets[b] = slot;
    atomic_fetch_add(&g_hdr->count, 1);
}

#include "feature_map.h"

/* ============================================================
 * NATS PUBLISHER — send only, no recv
 * ============================================================ */
static int nats_sock = -1;
static time_t nats_last_ping = 0;

static int nats_connect(const char *host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_in addr = {.sin_family=AF_INET, .sin_port=htons(port)};
    inet_pton(AF_INET, host, &addr.sin_addr);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(sock); return -1;
    }
    char buf[4096];
    usleep(100000);
    recv(sock, buf, sizeof(buf), MSG_DONTWAIT);
    const char *conn = "CONNECT {\"verbose\":false}\r\n";
    send(sock, conn, strlen(conn), MSG_NOSIGNAL);
    nats_last_ping = time(NULL);
    return sock;
}

/* Send PING to keep NATS alive */
static void nats_keepalive(void) {
    if (nats_sock < 0) return;
    time_t now = time(NULL);
    if (now - nats_last_ping >= 30) {
        /* Drain any pending data (PING from server) */
        char drain[4096];
        recv(nats_sock, drain, sizeof(drain), MSG_DONTWAIT);
        /* Send PING */
        if (send(nats_sock, "PING\r\n", 6, MSG_NOSIGNAL) < 0) {
            close(nats_sock); nats_sock = -1;
        }
        nats_last_ping = now;
    }
}

#define NATS_BATCH_MAX 1024
static struct { uint32_t ip; uint8_t cls; float conf; uint8_t svc; uint8_t atk; } nats_buf[NATS_BATCH_MAX];
static int nats_buf_n = 0;

static void nats_flush(void) {
    if (nats_buf_n == 0 || nats_sock < 0) return;
    static char payload[256 * 1024];  /* static, not stack */
    int pos = 0;
    pos += snprintf(payload+pos, sizeof(payload)-pos, "{\"ips\":[");
    for (int i = 0; i < nats_buf_n; i++) {
        uint32_t ip = nats_buf[i].ip;
        if (i > 0) payload[pos++] = ',';
        pos += snprintf(payload+pos, sizeof(payload)-pos,
            "{\"src_ip\":\"%u.%u.%u.%u\",\"state\":%d,\"best_xgb_class\":%u,"
            "\"best_xgb_confidence\":%.4f,\"service_id\":%u,"
            "\"label_source\":3,\"label_confidence\":%.4f,"
            "\"capture_depth\":2,\"has_any_evidence\":%d}",
            (ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF,
            nats_buf[i].atk ? 2 : (nats_buf[i].conf >= 0.70f ? 1 : 0),
            nats_buf[i].cls, nats_buf[i].conf, nats_buf[i].svc,
            nats_buf[i].conf, nats_buf[i].atk);
    }
    pos += snprintf(payload+pos, sizeof(payload)-pos, "]}");
    char hdr[128];
    int hlen = snprintf(hdr, sizeof(hdr), "PUB dfi.xgb.classifications %d\r\n", pos);
    if (send(nats_sock, hdr, hlen, MSG_NOSIGNAL) < 0 ||
        send(nats_sock, payload, pos, MSG_NOSIGNAL) < 0 ||
        send(nats_sock, "\r\n", 2, MSG_NOSIGNAL) < 0) {
        close(nats_sock); nats_sock = -1;
    }
    nats_buf_n = 0;
}

static void nats_add(uint32_t ip, uint8_t cls, float conf, uint8_t svc, uint8_t atk) {
    if (nats_buf_n >= NATS_BATCH_MAX) nats_flush();
    nats_buf[nats_buf_n++] = (typeof(nats_buf[0])){ip, cls, conf, svc, atk};
}

/* ============================================================
 * eSwitch — ICMP DROP + verdict DROP
 * ============================================================ */
static uint32_t eswitch_drops = 0;

static void eswitch_icmp_drop(void) {
    struct rte_flow_error error;
    struct rte_flow_attr attr = { .ingress = 1 };
    struct rte_flow_item_ipv4 spec = { .hdr.next_proto_id = 1 };
    struct rte_flow_item_ipv4 mask = { .hdr.next_proto_id = 0xFF };
    struct rte_flow_item pattern[] = {
        { .type = RTE_FLOW_ITEM_TYPE_ETH },
        { .type = RTE_FLOW_ITEM_TYPE_IPV4, .spec = &spec, .mask = &mask },
        { .type = RTE_FLOW_ITEM_TYPE_END },
    };
    struct rte_flow_action actions[] = {
        { .type = RTE_FLOW_ACTION_TYPE_DROP },
        { .type = RTE_FLOW_ACTION_TYPE_END },
    };
    if (rte_flow_create(0, &attr, pattern, actions, &error))
        printf("eSwitch: ICMP → DROP\n");
    else
        printf("eSwitch: ICMP DROP failed: %s\n", error.message ? error.message : "?");
}

static int eswitch_drop(uint32_t ip_host_order) {
    struct rte_flow_error error;
    struct rte_flow_attr attr = { .ingress = 1 };
    uint32_t ip_be = htonl(ip_host_order);
    struct rte_flow_item_ipv4 spec = { .hdr.src_addr = ip_be };
    struct rte_flow_item_ipv4 mask = { .hdr.src_addr = 0xFFFFFFFF };
    struct rte_flow_item pattern[] = {
        { .type = RTE_FLOW_ITEM_TYPE_ETH },
        { .type = RTE_FLOW_ITEM_TYPE_IPV4, .spec = &spec, .mask = &mask },
        { .type = RTE_FLOW_ITEM_TYPE_END },
    };
    struct rte_flow_action actions[] = {
        { .type = RTE_FLOW_ACTION_TYPE_DROP },
        { .type = RTE_FLOW_ACTION_TYPE_END },
    };
    struct rte_flow *f = rte_flow_create(0, &attr, pattern, actions, &error);
    if (!f) return -1;
    eswitch_drops++;
    return 0;
}

/* Evict IP from table */
static void table_evict(uint32_t ip) {
    if (!ip) return;
    uint32_t b = iphash(ip);
    uint32_t idx = g_buckets[b];
    uint32_t prev = EMPTY;
    for (int d = 0; idx != EMPTY && d < 64; d++) {
        if (idx >= TABLE_MAX) break;
        if (g_entries[idx].ip == ip) {
            if (prev == EMPTY) g_buckets[b] = g_entries[idx].next;
            else g_entries[prev].next = g_entries[idx].next;
            memset(&g_entries[idx], 0, sizeof(IPEntry));
            g_entries[idx].next = EMPTY;
            atomic_fetch_sub(&g_hdr->count, 1);
            return;
        }
        prev = idx;
        idx = g_entries[idx].next;
    }
}

/* ============================================================
 * VERDICT FILE
 * ============================================================ */
#define VERDICT_PATH "/var/lib/dfi-preproc/verdicts.txt"

static void process_verdicts(void) {
    FILE *fp = fopen(VERDICT_PATH, "r");
    if (!fp) return;
    char line[64];
    int count = 0;
    while (fgets(line, sizeof(line), fp)) {
        unsigned a, b, c, d;
        if (sscanf(line, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) continue;
        uint32_t ip = (a<<24)|(b<<16)|(c<<8)|d;
        if (!ip) continue;
        eswitch_drop(ip);
        table_evict(ip);
        count++;
    }
    fclose(fp);
    unlink(VERDICT_PATH);
    if (count > 0) printf("VERDICTS: %d IPs → eSwitch DROP + evicted\n", count);
}

/* ============================================================
 * TIME — nanoseconds from monotonic clock, cached per burst
 * ============================================================ */
static uint64_t now_ns;
static time_t now_sec;

static void update_time(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    now_sec = ts.tv_sec;
}

/* ============================================================
 * MAIN
 * ============================================================ */
int main(int argc, char *argv[]) {
    signal(SIGINT, sig); signal(SIGTERM, sig);
    setbuf(stdout, NULL);

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) return 1;

    load_honeypots();

    if (table_open("/var/lib/dfi-preproc/god2_table.db") < 0) return 1;

    int has_model = (xgb_load("/var/lib/dfi-preproc/models/xgb_5class_v2.bin") == 0);

    nats_sock = nats_connect("192.168.0.100", 4222);
    if (nats_sock >= 0) printf("NATS: connected (scores → CH)\n");

    flows = calloc(FLOW_MAX, sizeof(Flow));
    printf("Flows: %u slots (%zuMB)\n", FLOW_MAX, FLOW_MAX*sizeof(Flow)/1000000);

    struct rte_mempool *pool = rte_pktmbuf_pool_create("P", 16383, 256, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, 0);
    struct rte_eth_conf conf = {0};
    rte_eth_dev_configure(0, 1, 0, &conf);
    rte_eth_rx_queue_setup(0, 0, 2048, 0, NULL, pool);
    rte_eth_dev_start(0);
    rte_eth_promiscuous_enable(0);

    /* ICMP DROP in hardware */
    eswitch_icmp_drop();

    printf("GOD is alive. Seeing every IP. Scoring every flow.\n\n");

    struct rte_mbuf *bufs[64];
    uint64_t pkts=0;
    uint32_t new_ips=0, scored=0, new_atk=0;
    update_time();
    time_t last_sec = now_sec;
    time_t start_sec = now_sec;
    time_t last_expire = now_sec;

    while (!quit) {
        uint16_t nb = rte_eth_rx_burst(0, 0, bufs, 64);
        if (nb > 0) update_time();  /* update clock once per burst, not per packet */

        for (uint16_t i = 0; i < nb; i++) {
            uint8_t *p = rte_pktmbuf_mtod(bufs[i], uint8_t *);
            uint32_t len = rte_pktmbuf_data_len(bufs[i]);
            int off = 14;
            uint16_t etype = (p[12]<<8)|p[13];
            if (etype == 0x8100) { off+=4; etype=(p[16]<<8)|p[17]; }
            if (etype != 0x0800 || len < (uint32_t)(off+20)) {
                rte_pktmbuf_free(bufs[i]); pkts++; continue;
            }

            uint32_t src = (p[off+12]<<24)|(p[off+13]<<16)|(p[off+14]<<8)|p[off+15];
            uint32_t dst = (p[off+16]<<24)|(p[off+17]<<16)|(p[off+18]<<8)|p[off+19];
            uint8_t proto = p[off+9];
            uint16_t sp=0, dp=0;
            uint8_t tcp_flags=0;
            int ihl = (p[off]&0xF)*4;

            if (proto == 6 && len >= (uint32_t)(off+ihl+20)) {
                sp = (p[off+ihl]<<8)|p[off+ihl+1];
                dp = (p[off+ihl+2]<<8)|p[off+ihl+3];
                tcp_flags = p[off+ihl+13];
            } else if (proto == 17 && len >= (uint32_t)(off+ihl+8)) {
                sp = (p[off+ihl]<<8)|p[off+ihl+1];
                dp = (p[off+ihl+2]<<8)|p[off+ihl+3];
            }

            int src_hp = is_honeypot(src), dst_hp = is_honeypot(dst);
            uint32_t ext_ip;
            int is_atk = 0, is_fwd;

            if (dst_hp && !src_hp) {
                ext_ip = src; is_atk = 1; is_fwd = 1;
            } else if (src_hp && !dst_hp) {
                ext_ip = dst; is_atk = 1; is_fwd = 0;
            } else if (!src_hp && !dst_hp) {
                ext_ip = src; is_atk = 0; is_fwd = 1;
            } else {
                rte_pktmbuf_free(bufs[i]); pkts++; continue;
            }

            /* UPSERT EVERY IP */
            uint32_t prev_count = atomic_load(&g_hdr->count);
            table_upsert(ext_ip, is_atk, 0, 0.0f, port_to_proto(dp), now_ns);
            if (atomic_load(&g_hdr->count) > prev_count) {
                new_ips++;
                if (is_atk) new_atk++;
            }

            if (!src_hp && !dst_hp) {
                prev_count = atomic_load(&g_hdr->count);
                table_upsert(dst, 0, 0, 0.0f, port_to_proto(dp), now_ns);
                if (atomic_load(&g_hdr->count) > prev_count) new_ips++;
            }

            /* FLOW TRACKING */
            uint32_t fk_src, fk_dst; uint16_t fk_sp, fk_dp;
            if (is_fwd) { fk_src=src; fk_dst=dst; fk_sp=sp; fk_dp=dp; }
            else { fk_src=dst; fk_dst=src; fk_sp=dp; fk_dp=sp; }

            Flow *f = flow_get(fk_src, fk_dst, fk_sp, fk_dp, proto, now_ns);
            if (f) {
                f->last_ts = now_ns;
                if (is_fwd) {
                    f->pkts_fwd++; f->bytes_fwd += len;
                    f->fwd_size_sum += len;
                    if (f->fwd_pkt_count == 0 || len < f->fwd_size_min) f->fwd_size_min = len;
                    if (len > f->fwd_size_max) f->fwd_size_max = len;
                    f->fwd_pkt_count++;
                } else {
                    f->pkts_rev++; f->bytes_rev += len;
                    f->rev_size_sum += len;
                    if (len > f->rev_size_max) f->rev_size_max = len;
                    f->rev_pkt_count++;
                }
                if (f->prev_ts > 0 && now_ns > f->prev_ts) {
                    float iat = (float)(now_ns - f->prev_ts) / 1e6f;
                    f->iat_sum += iat; f->iat_sq_sum += iat*iat; f->n_iat++;
                }
                f->prev_ts = now_ns;
                if (tcp_flags & 0x02) f->syn++;
                if (tcp_flags & 0x01) f->fin++;
                if (tcp_flags & 0x04) f->rst++;
                if (tcp_flags & 0x08) f->psh++;
                if (tcp_flags == 0x10) f->ack_only++;

                /* XGB SCORE after 10 packets */
                uint32_t total_pkts = f->pkts_fwd + f->pkts_rev;
                if (has_model && !f->scored && total_pkts >= FLOW_SCORE_PKTS) {
                    float arm_feat[75];
                    flow_to_features(f, arm_feat, 75);
                    float model_feat[MODEL_FEAT_COUNT];
                    for (int fi=0; fi<MODEL_FEAT_COUNT; fi++)
                        model_feat[fi] = arm_feat[FEAT_MAP[fi]];

                    uint8_t cls; float cconf;
                    xgb_predict(model_feat, &cls, &cconf);

                    table_upsert(ext_ip, is_atk, cls, cconf, f->app_proto, now_ns);
                    /* Also score dst for non-honeypot traffic */
                    if (!src_hp && !dst_hp)
                        table_upsert(dst, 0, cls, cconf, f->app_proto, now_ns);
                    nats_add(ext_ip, cls, cconf, f->app_proto, is_atk);
                    f->scored = 1;
                    scored++;
                }
            }

            pkts++;
            rte_pktmbuf_free(bufs[i]);
        }

        if (now_sec != last_sec) {
            nats_flush();
            nats_keepalive();
            if (nats_sock < 0 && (now_sec - start_sec) % 10 == 0)
                nats_sock = nats_connect("192.168.0.100", 4222);
            process_verdicts();

            /* Expire dead flows every 30 seconds */
            if (now_sec - last_expire >= 30) {
                flow_expire(now_ns);
                last_expire = now_sec;
            }

            uint32_t total = atomic_load(&g_hdr->count);
            printf("[%lds] TABLE:%u | +%u/s (atk:%u) | scored:%u | esDROP:%u | flows:%u (exp:%u) | %lupkt/s\n",
                   (long)(now_sec-start_sec), total, new_ips, new_atk, scored, eswitch_drops,
                   flow_count, flows_expired, (unsigned long)pkts);
            new_ips=0; new_atk=0; scored=0; pkts=0; flows_expired=0; eswitch_drops=0;
            last_sec = now_sec;
        }
    }

    printf("\nFinal: %u IPs, %u flows\n", atomic_load(&g_hdr->count), flow_count);
    nats_flush();
    msync(g_mmap, g_mmap_sz, MS_SYNC);
    rte_eth_dev_stop(0);
    return 0;
}
