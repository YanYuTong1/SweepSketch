

#ifndef _ENTROPY_HEADERS_P4_
#define _ENTROPY_HEADERS_P4_

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











struct en_meta_t {

    
    bit<32> pfx;                        

    
    bit<11> slot;                       
    bit<6>  pos0;                       
    bit<6>  pos1;                       
    bit<6>  pos2;                       

    
    bit<16> idx0;                       
    bit<16> idx1;                       
    bit<16> idx2;                       
    bit<1>  sel0;                       
    bit<1>  sel1;                       
    bit<1>  sel2;                       
}





struct eg_metadata_t {
    bit<8> _pad;
}

#endif 
