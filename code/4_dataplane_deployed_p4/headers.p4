
#ifndef _SWEEP_HEADERS_P4_
#define _SWEEP_HEADERS_P4_

#include <t2na.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
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

struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

struct eg_metadata_t {
    bit<8> _pad;
}









struct sweep_digest_t {
    bit<32> dst_addr;
    bit<8>  pkt_old;
    bit<8>  nn_old;
    bit<32> key_old;
    bit<16> C_old;
    bit<32> tstamp;
}

struct sweep_meta_t {
    bit<13> idx1;       
    bit<3>  _p1;
    bit<8>  pkt_old;    
    bit<8>  nn_old;     
    bit<32> key_old;    
    bit<32> key_new;    
    bit<16> C_old;      
    bit<32> dg_tstamp;  
}

#endif
