
#ifndef _TRW_HEADERS_P4_
#define _TRW_HEADERS_P4_

#include <t2na.p4>

#define DIGEST_MTU 48      





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

struct headers_t {
    ethernet_h  ethernet;
    vlan_h      vlan;
    ipv4_h      ipv4;
}






struct trw_digest_t {
    bit<32> src;          
    bit<32> dst;          
    bit<16> lam;          
    bit<8>  epoch;        
    bit<8>  reason;       
    bit<32> tstamp;       
}





struct trw_meta_t {

    
    bit<32> src;                     
    bit<32> dst;                     

    
    bit<16> slot;                    
    bit<32> pair_hash;               
    bit<16> pair_word;               
    bit<5>  pair_bit;                
    bit<32> mask;                    

    
    bit<32> key_old;
    bit<32> key_eq;        
    bit<32> bm_masked;      
    bool    bm_clear;    
    bit<32> bm_old;                  
    bit<16> lam_now;                 

    
    bit<1>  hit;                     
    bit<1>  pair_seen;               
    bit<1>  do_event;                
    bit<1>  do_claim;                

    
    bit<1>  alarm;                   
    bit<1>  alerted;                 
    bit<32> dg_src;
    bit<32> dg_dst;
    bit<16> dg_lam;
    bit<8>  dg_epoch;
    bit<8>  dg_reason;
    bit<32> dg_tstamp;
}





struct eg_metadata_t {
    bit<8> _pad;
}

#endif 
