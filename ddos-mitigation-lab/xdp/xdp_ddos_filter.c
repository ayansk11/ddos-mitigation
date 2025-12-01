#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/types.h>

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

typedef __u64 u64;
typedef __u32 u32;

static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
    (void *)BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(void *map, const void *key,
                                  const void *value, u64 flags) =
    (void *)BPF_FUNC_map_update_elem;
static u64 (*bpf_ktime_get_ns)(void) =
    (void *)BPF_FUNC_ktime_get_ns;
static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
    (void *)BPF_FUNC_trace_printk;

static __always_inline __u16 bpf_htons(__u16 x)
{
    return __builtin_bswap16(x);
}


#define THRESHOLD_PKTS        5000ULL
#define TIME_WINDOW_NS   1000000000ULL  // 1 second


struct rate_state {
    u64 last_ts_ns;
    u64 pkt_count;
};


struct bpf_map_def {
    u32 type;
    u32 key_size;
    u32 value_size;
    u32 max_entries;
    u32 map_flags;
};

SEC("maps")
struct bpf_map_def rate_limit_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(u32),
    .value_size  = sizeof(struct rate_state),
    .max_entries = 65536,
    .map_flags   = 0,
};

SEC("maps")
struct bpf_map_def drop_cnt = {
    .type        = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size    = sizeof(u32),
    .value_size  = sizeof(u64),
    .max_entries = 1,
    .map_flags   = 0,
};

static __always_inline void count_drop(void)
{
    u32 key = 0;
    u64 *val = bpf_map_lookup_elem(&drop_cnt, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}


SEC("xdp")
int xdp_ddos_main(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    u32 src_ip = iph->saddr;
    u64 now = bpf_ktime_get_ns();

    struct rate_state *st = bpf_map_lookup_elem(&rate_limit_map, &src_ip);
    struct rate_state new = {};

    if (!st) {
        new.last_ts_ns = now;
        new.pkt_count  = 1;
        bpf_map_update_elem(&rate_limit_map, &src_ip, &new, BPF_ANY);
        return XDP_PASS;
    }

    if (now - st->last_ts_ns > TIME_WINDOW_NS) {
        st->last_ts_ns = now;
        st->pkt_count  = 1;
        return XDP_PASS;
    }

    st->pkt_count++;

    if (st->pkt_count > THRESHOLD_PKTS) {
        count_drop();
        char fmt[] = "XDP DROP src=%x count=%llu\n";
        bpf_trace_printk(fmt, sizeof(fmt), src_ip, st->pkt_count);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
