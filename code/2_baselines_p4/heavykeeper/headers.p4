




















#ifndef _HK_HEADERS_P4_
#define _HK_HEADERS_P4_

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

    
    bit<32> key24;                  

    
    bit<14> col_r0;
    bit<14> col_r1;
    bit<14> col_r2;

    
    bit<32> rv_r0;
    bit<32> rv_r1;
    bit<32> rv_r2;

    
    bit<16> cnt_r0;
    bit<16> cnt_r1;
    bit<16> cnt_r2;

    
    bool    hit0;                   
    bool    hit1;
    bool    hit2;
    bool    empty0;                 
    bool    empty1;
    bool    empty2;
    bool    cnt_eq1_0;              
    bool    cnt_eq1_1;
    bool    cnt_eq1_2;
    bool    decay0;                 
    bool    decay1;
    bool    decay2;

    
    bit<8>  c8_r0;
    bit<8>  c8_r1;
    bit<8>  c8_r2;

    
    bit<32> r_r0;
    bit<32> r_r1;
    bit<32> r_r2;
    bit<32> thr_r0;                 
    bit<32> thr_r1;
    bit<32> thr_r2;
    bit<32> r_sub0;                 
    bit<32> r_sub1;
    bit<32> r_sub2;

    
    
    
    bool    le_r0;                  
    bool    le_r1;
    bool    le_r2;

    
    bit<1>  in_heap;
    bit<16> hmin;                   

    
    bit<16> transport_src_port;
    bit<16> transport_dst_port;
}





struct eg_metadata_t {
    bit<8> _pad;
}

#endif 
