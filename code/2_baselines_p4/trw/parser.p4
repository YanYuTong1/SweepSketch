
#ifndef _TRW_PARSER_P4_
#define _TRW_PARSER_P4_

#include <t2na.p4>
#include "headers.p4"




const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_VLAN = 0x8100;




parser TrwParser(
    packet_in                        pkt,
    out   headers_t                  hdr,
    out   trw_meta_t                 meta,
    out   ingress_intrinsic_metadata_t ig_intr_md)
{
    
    
    
    state start {
        pkt.extract(ig_intr_md);

        
        meta.src        = 32w0;
        meta.dst        = 32w0;
        meta.slot       = 16w0;
        meta.pair_hash  = 32w0;
        meta.pair_word  = 16w0;
        meta.pair_bit   = 5w0;
        meta.mask       = 32w0;
        meta.key_old    = 32w0;
        meta.key_eq     = 32w0;
        meta.bm_masked  = 32w0;
        meta.bm_clear  = false;
        meta.bm_old     = 32w0;
        meta.lam_now    = 16w0;
        meta.hit        = 1w0;
        meta.pair_seen  = 1w0;
        meta.do_event   = 1w0;
        meta.do_claim   = 1w0;
        meta.alarm      = 1w0;
        meta.alerted    = 1w0;
        meta.dg_src     = 32w0;
        meta.dg_dst     = 32w0;
        meta.dg_lam     = 16w0;
        meta.dg_epoch   = 8w0;
        meta.dg_reason  = 8w0;
        meta.dg_tstamp  = 32w0;

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
        transition accept;
    }
}




control TrwDeparser(
    packet_out                                      pkt,
    inout headers_t                                 hdr,
    in    trw_meta_t                                meta,
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Digest<trw_digest_t>() dg;

    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.vlan);
        pkt.emit(hdr.ipv4);
        if (meta.alerted == 1) {
            trw_digest_t d;
            d.src     = meta.dg_src;
            d.dst     = meta.dg_dst;
            d.lam     = meta.dg_lam;
            d.epoch   = meta.dg_epoch;
            d.reason  = meta.dg_reason;
            d.tstamp  = meta.dg_tstamp;
            dg.pack(d);
        }
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
    }
}

#endif 
