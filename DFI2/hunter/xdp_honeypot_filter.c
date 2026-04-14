// XDP pre-filter for SPAN capture on PV1 BlueField-2 (ens3f0np0)
// Passes honeypot-related traffic to AF_PACKET, drops everything else.
//
// Honeypot ranges:
//   216.126.0.128/25 (.128-.255) — all honeypot VMs + farm + LXC
//   108.181.161.199              — external VPS honeypot
//
// Compile: clang -O2 -target bpf -c xdp_honeypot_filter.c -o xdp_honeypot_filter.o
// Attach:  ip link set dev ens3f0np0 xdpdrv obj xdp_honeypot_filter.o sec xdp
// Detach:  ip link set dev ens3f0np0 xdp off

// Minimal self-contained definitions — no system headers needed
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define ETH_P_IP    0x0800
#define ETH_P_8021Q 0x8100

#define XDP_ABORTED 0
#define XDP_DROP    1
#define XDP_PASS    2
#define XDP_TX      3
#define XDP_REDIRECT 4

struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

// Ethernet header (14 bytes)
struct ethhdr {
    __u8  h_dest[6];
    __u8  h_source[6];
    __u16 h_proto;      // big-endian
} __attribute__((packed));

// VLAN header (4 bytes)
struct vlanhdr {
    __u16 h_vlan_TCI;
    __u16 h_vlan_encapsulated_proto;
} __attribute__((packed));

// IP header (20+ bytes)
struct iphdr {
    __u8  ihl_version;  // version:4, ihl:4
    __u8  tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8  ttl;
    __u8  protocol;
    __u16 check;
    __u32 saddr;        // network byte order
    __u32 daddr;        // network byte order
} __attribute__((packed));

#define bpf_htons(x) ((__u16)__builtin_bswap16(x))

#ifndef __section
#define __section(NAME) __attribute__((section(NAME), used))
#endif
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

// Honeypot IP ranges (network byte order — as stored in iphdr saddr/daddr)
// 216.126.0.128/25 covers .128-.255 (all honeypot VMs + farm + LXC)
#define HONEYPOT_NET    0xD87E0080U  // 216.126.0.128
#define HONEYPOT_MASK   0xFFFFFF80U  // /25 mask
#define VPS_IP          0x6CB5A1C7U  // 108.181.161.199

static __always_inline int is_honeypot_ip(__u32 ip_nbo)
{
    if ((ip_nbo & HONEYPOT_MASK) == HONEYPOT_NET)
        return 1;
    if (ip_nbo == VPS_IP)
        return 1;
    return 0;
}

__section("xdp")
int xdp_honeypot(struct xdp_md *ctx)
{
    void *data = (void *)(__u64)ctx->data;
    void *data_end = (void *)(__u64)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 eth_type = eth->h_proto;
    void *l3 = (void *)(eth + 1);

    // Handle 802.1Q VLAN tag
    if (eth_type == bpf_htons(ETH_P_8021Q)) {
        struct vlanhdr *vlan = l3;
        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;
        eth_type = vlan->h_vlan_encapsulated_proto;
        l3 = (void *)(vlan + 1);
    }

    // Only filter IPv4 — pass everything else (ARP, IPv6, etc.)
    if (eth_type != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = l3;
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Pass if src or dst is a honeypot IP
    if (is_honeypot_ip(ip->saddr) || is_honeypot_ip(ip->daddr))
        return XDP_PASS;

    // Non-honeypot IPv4 → drop before AF_PACKET
    return XDP_DROP;
}

char _license[] __section("license") = "GPL";
