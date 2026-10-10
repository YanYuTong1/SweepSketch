






#ifndef _SWEEP_HEADERS_P4_
#define _SWEEP_HEADERS_P4_

#include <t2na.p4>

#define DIGEST_MTU 48      

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
    bit<32> l1_prefix;    
    bit<8>  l1_pkt;       
    bit<8>  l1_n_new;     
    bit<1>  l1_event;     
    bit<1>  l1_held;      
    bit<6>  _pad1;
    bit<16> l1_C;         
    bit<16> l1_delta_C;   
    bit<32> l2_prefix;
    bit<8>  l2_pkt;
    bit<8>  l2_n_new;
    bit<1>  l2_event;
    bit<7>  _pad2;
    bit<16> l2_C;
    bit<16> l2_delta_C;
    bit<32> tstamp;       
}   





struct sweep_meta_t {
    
    bit<13> idx1;            
    bit<3>  _p1;
    bit<12> idx2;            
    bit<4>  _p2;
    bit<5>  r;               
    bit<5>  rho;             
    bit<1>  rho_done;        
    bit<3>  r_tail;          
    bit<2>  _p3;
    bit<5>  global_epoch;    
    bit<3>  _p4;
    
    bool    key_nz;          
    bool    pkt_ge_min;      
    bool    C_lt;            
    bool    key_ok;
    bool    claim;
    bool    rollover;        
    bool    tag_ne;          
    bool    rho_gt;          
    bool    ge3;             
    bool    ge3c;            
    bool    nn_ge;           
    bool    nn_ge_2ne;       
    bool    ge3b;            
    bit<1>  event;
    bit<1>  cold;
    bit<1>  skip;
    bit<1>  held_new;        
    bit<3>  _p5;
    
    bool    key2_nz;         
    bool    pkt2_ge_min;     
    bool    C2_lt;           
    bool    key_ok2;
    bool    claim2;
    bool    rollover2;
    bool    tag2_ne;         
    bool    rho2_gt;         
    bit<1>  cold2;
    bit<1>  skip2;
    bit<1>  event2;
    bit<4>  _p6;
    
    bit<8>  r_hi;   
    bit<8>  r_mid;
    bit<8>  r_lo;
    bit<8>  ep_old;          
    bit<8>  e1;              
    bit<8>  ep_new;          
    bit<8>  win_new;         
    bit<8>  hll_rv;          
    bit<8>  w5;              
    bit<8>  hll_new;         
    bit<8>  w5_2;            
    bit<8>  e1_2;            
    bit<8>  nn_old;          
    bit<8>  ne_old;          
    bit<8>  ne2;             
    bit<8>  pkt_old;         
    bit<8>  pkt2_old;        
                             
    bit<8>  ep_new2;         
    bit<8>  ep2_old;
    bit<8>  win2_new;        
    bit<8>  hll_new2;        
    bit<8>  hll2_rv;
    bit<8>  nn2_old;
    
    bit<16> C_old;           
    bit<16> delta_total;     
    bit<16> delta2_total;    
    bit<16> C2_old;
    
    bit<32> pkt_key;         
    bit<32> pkt_key2;        
    bit<32> hr;              
    
    bit<32> dg_prefix;
    @pa_container_size("ingress", "ingress::meta.dg_pkt", 8)
    bit<8>  dg_pkt;
    bit<8>  dg_n_new;
    @pa_container_size("ingress", "ingress::meta.dg_event", 8)
    bit<1>  dg_event;   
    bit<1>  dg_held;     
    bit<16> dg_C;
    bit<16> dg_delta;
    bit<32> dg_tstamp;
    
    bit<32> dg2_prefix;
    bit<8>  dg2_pkt;
    bit<8>  dg2_n_new;
    bit<1>  dg2_event;   
    bit<16> dg2_C;
    bit<16> dg2_delta;
}

#endif
