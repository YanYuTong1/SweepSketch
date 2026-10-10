















#ifndef _ELASTIC_HEADERS_P4_
#define _ELASTIC_HEADERS_P4_

#include <t2na.p4>





header ethernet_h {
    bit<48> dstAddr;
    bit<48> srcAddr;
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












header resubmit_h {
    bit<8>  op;         
    bit<8>  cell;       
    bit<24> key;        
    bit<24> ev_key;     
    bit<8>  ev_val;     
    bit<8>  ev_flag;    
    bit<16> guard_new;  
    bit<8>  _pad;       
}





struct headers_t {
    ethernet_h  ethernet;
    ipv4_h      ipv4;
    resubmit_h  resubmit;
}





struct ig_metadata_t {

    
    bit<32> key;            
    bit<12> bucket;         
    bit<18> light_pos;      
    bit<18> light_pos_ev;   
    bit<32> ev_key32;       
    bit<7>  ev_val;         
    bit<1>  ev_flag;        
    bit<8>  ev_val8;        
    bit<8>  light_old_ev;     
    bit<8>  room_ev;          
    bool    ovf_ev;           
    bool    not_ovf_ev;       
    bool    lev_lt;           
                              
    bool    guard_ge;         

    
    bit<32> v0;
    bit<32> v1;
    bit<32> v2;
    bit<32> v3;
    bit<32> v4;
    bit<32> v5;
    bit<32> v6;
    bool    hit0;   
    bool    hit1;
    bool    hit2;
    bool    hit3;
    bool    hit4;
    bool    hit5;
    bool    hit6;
    bool    emp0;  
    bool    sat0;              
    bool    emp1;  
    bool    sat1;              
    bool    emp2;  
    bool    sat2;              
    bool    emp3;  
    bool    sat3;              
    bool    emp4;  
    bool    sat4;              
    bool    emp5;  
    bool    sat5;              
    bool    emp6;  
    bool    sat6;              

    
    bit<32> w01;    
    bit<32> w23;
    bit<32> w45;
    bit<8>  m01;    
    bit<8>  m23;
    bit<8>  m45;
    bit<32> w0123;
    bit<32> w456;
    bit<3>  m0123;
    bit<8>  m456;
    bit<32> wmin;             
    bit<8>  min_i;            
    bit<10> min_x8;           

    
    bit<16> guard_old;        
    bit<1>  do_swap;          

    
    bit<1>  has_empty;        
    bit<8>  first_empty;      

    
    bit<32> newcell;          

    
    bit<8>  rs_op;            
    bit<8>  rs_cell;          
    bit<24> rs_key;           
    bit<24> rs_ev_key;        
    bit<8>  rs_ev_val;        
    bit<8>  rs_ev_flag;       
    bit<16> rs_guard_new;     
    bit<32> rs_key32;         
    bit<32> rs_ev_key32;      
}





struct eg_metadata_t {
    bit<8> _pad;
}

#endif 
