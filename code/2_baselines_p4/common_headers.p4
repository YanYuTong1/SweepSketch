
#ifndef _BASELINE_COMMON_HEADERS_P4_
#define _BASELINE_COMMON_HEADERS_P4_

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


struct bl_meta_t {
    bit<16> idx;        
    bit<8>  idx2;       
    bit<8>  partition;  
    bit<8>  rho_reg;    
    bit<8>  hll_new;    
    bool    rho_gt;     
    bit<8>  rho;        
    bit<1>  rho_done;
    bit<32> h;          
    bit<8>  r_hi;        
    bit<8>  r_mid;
    bit<8>  r_lo;
    bit<3>  r_tail;
    bit<16> pos;        
    bit<32> mask;       
    bit<1>  alert;
    bit<32> key32;      
    
    bit<3>  sel_m;      
    bit<2>  sel_a;      
    bit<11> m1;         
    bit<16> m16;        
    bit<16> ma16;       
    bit<14> pkts_idx;   
}

parser BlParser(
    packet_in pkt,
    out headers_t hdr,
    out bl_meta_t meta,
    out ingress_intrinsic_metadata_t ig_intr_md)
{
    state start {
        pkt.extract(ig_intr_md);
        
        meta.idx = 0; meta.idx2 = 0; meta.partition = 0;
        meta.rho = 0; meta.rho_done = 0; meta.h = 0;
        meta.r_hi = 0; meta.r_mid = 0; meta.r_lo = 0; meta.r_tail = 0;
        meta.pos = 0; meta.mask = 0; meta.alert = 0; meta.key32 = 0;
        meta.sel_m = 0; meta.sel_a = 0; meta.m1 = 0; meta.m16 = 0;
        meta.rho_reg = 0; meta.hll_new = 0; meta.rho_gt = false;
        meta.ma16 = 0; meta.pkts_idx = 0;
        hdr.ethernet.setInvalid();
        hdr.ipv4.setInvalid();
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x0800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

control BlDeparser(packet_out pkt, inout headers_t hdr, in bl_meta_t meta,
                   in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)

{
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
    }
}






parser EgressParser(
    packet_in                        pkt,
    out headers_t                    hdr,
    out bl_meta_t                    meta,
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    state start {
        pkt.extract(eg_intr_md);
        meta.idx = 0; meta.idx2 = 0; meta.partition = 0;
        meta.rho = 0; meta.rho_done = 0; meta.h = 0;
        meta.r_hi = 0; meta.r_mid = 0; meta.r_lo = 0; meta.r_tail = 0;
        meta.pos = 0; meta.mask = 0; meta.alert = 0; meta.key32 = 0;
        meta.sel_m = 0; meta.sel_a = 0; meta.m1 = 0; meta.m16 = 0;
        meta.rho_reg = 0; meta.hll_new = 0; meta.rho_gt = false;
        meta.ma16 = 0; meta.pkts_idx = 0;
        transition accept;
    }
}

control EgressDeparser(
    packet_out                                     pkt,
    inout headers_t                                hdr,
    in    bl_meta_t                                meta,
    in    egress_intrinsic_metadata_for_deparser_t eg_dprsr_md)
{
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
    }
}

#endif  
