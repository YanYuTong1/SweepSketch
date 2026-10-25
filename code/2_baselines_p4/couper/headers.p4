

#ifndef _COUPER_HEADERS_P4_
#define _COUPER_HEADERS_P4_

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



























struct cp_meta_t {

    
    bit<32> f;                      
    bit<32> e;                      

    
    bit<17> c1;                     
    bit<17> c2;                     
    bit<16> c1_16;                  
    bit<16> c2_16;                  
    bit<1>  sel_c1;                 
    bit<1>  sel_c2;                 
    bit<16> bm1;                    
    bit<16> bm2;                    
    bit<16> merged;                 
    bit<8>  m_hi;                   
    bit<8>  m_lo;                   
    bit<5>  pc;                     
    bit<5>  pc_hi_v;               
    bit<5>  pc_lo_v;               
    bit<1>  l1_path;                
    bit<4>  q;                      
    bit<16> qmask;                  

    
    bit<32> h32;                    
    bit<6>  reg;                    
    bit<8>  rho;                    

    
    bit<12> g1;                     
    bit<12> g2;                     
    bit<16> hidx1;                  
    bit<16> hidx2;                  
    bit<1>  sel_g1;                 
    bit<1>  sel_g2;                 
    bit<8>  rho_old_g1;             
    bit<8>  rho_old_g2;             
    bit<1>  upd_g;                  
    bit<16> delta_g;                
    bit<1>  upd2_g;                 
    bit<16> delta2_g;               
    bit<16> lam1;                   
    bit<16> lam2;                   
    bit<16> lam;                    
    bit<1>  lam1_le;                

    
    bit<12> idx_i;                  
    bit<12> idx_j;                  
    bit<32> fi;                     
    bit<32> fj;                     
    bit<16> di;                     
    bit<16> dj;                     
    bool    upd1_ok;                
    bool    upd2_ok;                
    bool    fi_zero;                
    bool    fi_self;                
    bit<1>  fi_ok;                  
    bool    fj_zero;
    bool    fj_self;
    bit<1>  fj_ok;                  
    bool    di_le;                  
    bool    di_lam;                 
    bool    dj_lam;                 
    bit<1>  need_dig;               
    bit<1>  choose_i;               
    bit<16> dig_k;                  
    bit<1>  tsc_wr;                 
    bit<12> tsc_slot;               
}





struct eg_metadata_t {
    bit<8> _pad;
}

#endif 
