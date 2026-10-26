#ifndef _SPREADSKETCH_HEADERS_P4_
#define _SPREADSKETCH_HEADERS_P4_

#include <t2na.p4>

header ethernet_h {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header vlan_h {
    bit<3>  pcp;
    bit<1>  dei;
    bit<12> vid;
    bit<16> etherType;
}

header ipv4_h {
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

header tcp_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> totalLen;
    bit<16> checksum;
}

struct headers_t {
    ethernet_h  ethernet;
    vlan_h      vlan;
    ipv4_h      ipv4;
    tcp_h       tcp;
    udp_h       udp;
}

struct ig_metadata_t {

    bit<32> src_addr;
    bit<32> dst_addr;
    bit<16> transport_src_port;
    bit<16> transport_dst_port;

    bit<32> h1;
    bit<32> h2;

    bit<9>  pos;
    bit<4>  bm_word;
    bit<5>  bit_idx;
    bit<32> bm_mask;

    bit<8>  b0;
    bit<8>  b1;
    bit<8>  b2;
    bit<8>  b3;
    bit<8>  tz_acc;
    bit<1>  tz_done;
    bit<8>  lvl;

    bit<11> bucket_r0;
    bit<11> bucket_r1;
    bit<11> bucket_r2;
    bit<11> bucket_r3;
    bit<15> bm_idx_r0;
    bit<15> bm_idx_r1;
    bit<15> bm_idx_r2;
    bit<15> bm_idx_r3;
    bit<11> raw11_r0;
    bit<11> raw11_r1;
    bit<11> raw11_r2;
    bit<11> raw11_r3;
    bit<32> old_lvl_r0;
    bit<32> old_lvl_r1;
    bit<32> old_lvl_r2;
    bit<32> old_lvl_r3;
    bool    takeover_r0;
    bool    takeover_r1;
    bool    takeover_r2;
    bool    takeover_r3;
}

struct eg_metadata_t {
    bit<8> _pad;
}

#endif
