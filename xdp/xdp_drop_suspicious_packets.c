#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_HLEN 14
#define IP_HLEN 20

SEC("xdp")
int xdp_drop_suspicious_packets(struct xdp_md *ctx) {
    // get the packet data
    void* data = (void*)((long)ctx->data);
    void* data_end = (void*)((long)ctx->data_end);

    // check that we have enough data to hold the Ethernet and IP headers
    if (data + ETH_HLEN + IP_HLEN > data_end) {
        return XDP_PASS;
    }

    // get the source IP address
    __u32 src_ip = *(__u32*)(data + ETH_HLEN + 12);

    // check for suspicious packets
    if (src_ip == bpf_htonl(0xC0A80101)) { // check for source IP address of 192.168.1.1
        // drop the packet
        return XDP_DROP;
    }

    // allow the packet to continue through the network stack
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
