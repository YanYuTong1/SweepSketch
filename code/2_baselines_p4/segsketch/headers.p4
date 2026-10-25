

#ifndef _HEADERS_P4_
#define _HEADERS_P4_

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









header user_h {
    bit<8>  dst_byte_1;         
    bit<8>  dst_byte_2;         
    bit<8>  dst_byte_3;         
    bit<8>  dst_byte_4;         
    bit<8>  src_byte_1;         
    bit<8>  src_byte_2;         
    bit<8>  src_byte_3;         
    bit<8>  src_byte_4;         
}





struct headers_t {
    ethernet_h  ethernet;
    vlan_h      vlan;
    ipv4_h      ipv4;
    tcp_h       tcp;
    udp_h       udp;
    user_h      user;           
}











struct ig_metadata_t {

    
    bit<32> src_addr;                   
    bit<32> dst_addr;                   
    bit<16> transport_src_port;         
    bit<16> transport_dst_port;         

    
    
    
    bit<1>  hash_s1;                    
    bit<1>  hash_s2;                    
    bit<1>  hash_s3;                    
    bit<1>  hash_s4;                    

    
    
    
    
    bit<8>  mask1;                      
    bit<8>  mask2;                      
    bit<8>  mask3;                      

    
    
    
    
    bit<16> subnet_bm;                  

    
    
    bit<8>  prefix_len;

    
    
    bit<8>  col_r0;                     
    bit<8>  col_r1;                     
    bit<8>  col_r2;                     

    
    
    bit<8>  host_bm_byte;              
    bit<5>  host_bm_bit;               
    bit<3>  host_bm_word;              
    bit<9>  host_bm_index;            
    bit<9>  host_bm_index_r1;         
    bit<9>  host_bm_index_r2;         
    bit<32> host_bm_mask;             

    
    bit<32> r0_key;                     
    bit<32> r1_key;                     
    bit<32> r2_key;                     

    bit<16> r0_subnet_bm;              
    bit<16> r1_subnet_bm;              
    bit<16> r2_subnet_bm;              

    bit<32> r0_host_bm_word;           
    bit<32> r1_host_bm_word;           
    bit<32> r2_host_bm_word;           

    bit<32> r0_pkt_cnt;                
    bit<32> r1_pkt_cnt;                
    bit<32> r2_pkt_cnt;                

    
    bit<2>  match_row;                  
    bool    has_empty;                  
    bit<8>  empty_col;                  
    bit<2>  empty_row;                  

    
    bit<2>  victim_row;                 
    bool    do_replace;                 

    
    
    
    bool    active_r0;                  
    bool    active_r1;                  
    bool    active_r2;                  

    
    bit<16> is_new_pkt;                 
    bit<16> pkt_tag;                    
}





struct eg_metadata_t {
    bit<8> _pad;
}

#endif 
