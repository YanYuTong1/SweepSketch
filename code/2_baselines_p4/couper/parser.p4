

#ifndef _COUPER_PARSER_P4_
#define _COUPER_PARSER_P4_

#include <t2na.p4>
#include "headers.p4"




const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_VLAN = 0x8100;
const bit<8>  IP_PROTO_TCP   = 0x06;
const bit<8>  IP_PROTO_UDP   = 0x11;




parser IngressParser(
    packet_in                        pkt,
    out   headers_t                  hdr,
    out   cp_meta_t                  meta,
    out   ingress_intrinsic_metadata_t ig_intr_md)
{
    
    
    
    state start {
        pkt.extract(ig_intr_md);

        
        meta.f          = 32w0;
        meta.e          = 32w0;
        meta.c1         = 17w0;
        meta.c2         = 17w0;
        meta.c1_16      = 16w0;
        meta.c2_16      = 16w0;
        meta.sel_c1     = 1w0;
        meta.sel_c2     = 1w0;
        meta.bm1        = 16w0;
        meta.bm2        = 16w0;
        meta.merged     = 16w0;
        meta.m_hi       = 8w0;
        meta.m_lo       = 8w0;
        meta.pc         = 5w0;
        meta.pc_hi_v    = 5w0;
        meta.pc_lo_v    = 5w0;
        meta.l1_path    = 1w0;
        meta.q          = 4w0;
        meta.qmask      = 16w0;
        meta.h32        = 32w0;
        meta.reg        = 6w0;
        meta.rho        = 8w1;   
        meta.g1         = 12w0;
        meta.g2         = 12w0;
        meta.hidx1      = 16w0;
        meta.hidx2      = 16w0;
        meta.sel_g1     = 1w0;
        meta.sel_g2     = 1w0;
        meta.rho_old_g1 = 8w0;
        meta.rho_old_g2 = 8w0;
        meta.upd_g      = 1w0;
        meta.delta_g    = 16w0;
        meta.upd2_g     = 1w0;
        meta.delta2_g   = 16w0;
        meta.lam1       = 16w0;
        meta.lam2       = 16w0;
        meta.lam        = 16w0;
        meta.lam1_le    = 1w0;
        meta.idx_i      = 12w0;
        meta.idx_j      = 12w0;
        meta.fi         = 32w0;
        meta.fj         = 32w0;
        meta.di         = 16w0;
        meta.dj         = 16w0;
        meta.upd1_ok    = false;
        meta.upd2_ok    = false;
        meta.fi_zero    = false;
        meta.fi_self    = false;
        meta.fi_ok      = 1w0;
        meta.fj_zero    = false;
        meta.fj_self    = false;
        meta.fj_ok      = 1w0;
        meta.di_le      = false;
        meta.di_lam     = false;
        meta.dj_lam     = false;
        meta.need_dig   = 1w0;
        meta.choose_i   = 1w0;
        meta.dig_k      = 16w0;
        meta.tsc_wr     = 1w0;
        meta.tsc_slot   = 12w0;

        transition select(ig_intr_md.resubmit_flag) {
            1       : parse_resubmit;
            default : parse_port_metadata;
        }
    }

    
    
    
    state parse_resubmit {
        transition parse_ethernet;
    }

    
    
    
    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    
    
    
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_VLAN : parse_vlan;
            default        : accept;
        }
    }

    
    
    
    state parse_vlan {
        pkt.extract(hdr.vlan);
        transition select(hdr.vlan.etherType) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default        : accept;
        }
    }

    
    
    
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        meta.f = hdr.ipv4.srcAddr;      
        meta.e = hdr.ipv4.dstAddr;      
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP : parse_tcp;
            IP_PROTO_UDP : parse_udp;
            default      : accept;
        }
    }

    
    
    
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    
    
    
    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}




control IngressDeparser(
    packet_out                                      pkt,
    inout headers_t                                 hdr,
    in    cp_meta_t                                 meta,
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.vlan);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}




parser EgressParser(
    packet_in                       pkt,
    out headers_t                   hdr,
    out eg_metadata_t               meta,
    out egress_intrinsic_metadata_t eg_intr_md)
{
    state start {
        pkt.extract(eg_intr_md);
        meta._pad = 8w0;
        transition accept;
    }
}




control EgressDeparser(
    packet_out                                      pkt,
    inout headers_t                                 hdr,
    in    eg_metadata_t                             meta,
    in    egress_intrinsic_metadata_for_deparser_t   eg_dprsr_md)
{
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.vlan);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}

#endif 
