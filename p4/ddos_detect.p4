#include <core.p4>
#include <v1model.p4>


const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<8>  IP_PROTO_TCP   = 6;
const bit<8>  IP_PROTO_UDP   = 17;

const bit<32> DDOS_THRESHOLD = 10000;

const bit<9>  CPU_PORT       = 255;
const bit<32> MIRROR_SESSION_ID = 1;

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<9>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}


struct metadata_t {
    bit<1> suspect;  // set to 1 when DDoS threshold exceeded
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
}


parser MyParser(
    packet_in packet,
    out headers hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata)
{
    state start {
        meta.suspect = 0;
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default:        accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            default:      accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

register<bit<32>>(1024) src_ip_counter;


control MyIngress(
    inout headers hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata)
{
    action count_and_flag() {
        if (hdr.ipv4.isValid()) {
            bit<32> src = hdr.ipv4.srcAddr;
            bit<10> idx = (bit<10>) src[9:0];  // toy hash: last 10 bits

            bit<32> count;
            src_ip_counter.read(count, idx);
            count = count + 1;
            src_ip_counter.write(idx, count);

            if (count > DDOS_THRESHOLD) {
                meta.suspect = 1;
            }
        }
    }

    action ipv4_forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action drop() {
        standard_metadata.egress_spec = 0; // 0 is "drop" in v1model
    }

    action mirror_suspicious() {
        standard_metadata.instance_type = 1; // marker; handled by target
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = { ipv4_forward; drop; NoAction; }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            count_and_flag();
        }

        if (meta.suspect == 1) {
            mirror_suspicious();
            /* Option 1: just mirror but still forward */
            // ipv4_lpm.apply();

            /* Option 2: mirror AND drop at the data-plane */
            drop();
            return;
        }

        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        } else {
            drop();
        }
    }
}

control MyEgress(
    inout headers hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata)
{
    apply { }
}


control MyDeparser(
    packet_out packet,
    in headers hdr)
{
    apply {
        packet.emit(hdr.ethernet);
        if (hdr.ipv4.isValid()) {
            packet.emit(hdr.ipv4);
            if (hdr.tcp.isValid()) {
                packet.emit(hdr.tcp);
            } else if (hdr.udp.isValid()) {
                packet.emit(hdr.udp);
            }
        }
    }
}


V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
