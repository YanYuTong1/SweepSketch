













#ifndef _ELASTIC_PARSER_P4_
#define _ELASTIC_PARSER_P4_

#include <t2na.p4>
#include "headers.p4"

const bit<16> ETHERTYPE_IPV4 = 0x0800;




parser IngressParser(
    packet_in                          pkt,
    out   headers_t                    hdr,
    out   ig_metadata_t                meta,
    out   ingress_intrinsic_metadata_t ig_intr_md)
{
    state start {
        pkt.extract(ig_intr_md);

        
        meta.key          = 32w0;
        meta.bucket       = 12w0;
        meta.light_pos    = 18w0;
        meta.light_pos_ev = 18w0;
        meta.ev_key32     = 32w0;
        meta.ev_val       = 7w0;
        meta.ev_flag      = 1w0;
        meta.ev_val8      = 8w0;
        meta.light_old_ev = 8w0;
        meta.room_ev      = 8w0;
        meta.ovf_ev       = false;
        meta.not_ovf_ev   = false;
        meta.lev_lt       = false;
        meta.guard_ge     = false;
        meta.v0           = 32w0;
        meta.v1           = 32w0;
        meta.v2           = 32w0;
        meta.v3           = 32w0;
        meta.v4           = 32w0;
        meta.v5           = 32w0;
        meta.v6           = 32w0;
        meta.hit0         = false;
        meta.hit1         = false;
        meta.hit2         = false;
        meta.hit3         = false;
        meta.hit4         = false;
        meta.hit5         = false;
        meta.hit6         = false;
        meta.emp0         = false;
        meta.sat0         = false;
        meta.emp1         = false;
        meta.sat1         = false;
        meta.emp2         = false;
        meta.sat2         = false;
        meta.emp3         = false;
        meta.sat3         = false;
        meta.emp4         = false;
        meta.sat4         = false;
        meta.emp5         = false;
        meta.sat5         = false;
        meta.emp6         = false;
        meta.sat6         = false;
        meta.w01          = 32w0;
        meta.w23          = 32w0;
        meta.w45          = 32w0;
        meta.m01          = 3w0;
        meta.m23          = 3w0;
        meta.m45          = 3w0;
        meta.w0123        = 32w0;
        meta.w456         = 32w0;
        meta.m0123        = 3w0;
        meta.m456         = 3w0;
        meta.wmin         = 32w0;
        meta.min_i        = 3w0;
        meta.min_x8       = 10w0;
        meta.guard_old    = 16w0;
        meta.do_swap      = 1w0;
        meta.has_empty    = 1w0;
        meta.first_empty  = 3w0;
        meta.newcell      = 32w0;
        meta.rs_op        = 3w0;
        meta.rs_cell      = 3w0;
        meta.rs_key       = 24w0;
        meta.rs_ev_key    = 24w0;
        meta.rs_ev_val    = 7w0;
        meta.rs_ev_flag   = 1w0;
        meta.rs_guard_new = 16w0;
        meta.rs_key32     = 32w0;
        meta.rs_ev_key32  = 32w0;

        transition select(ig_intr_md.resubmit_flag) {
            1       : parse_resubmit;
            default : parse_port_metadata;
        }
    }

    
    
    
    
    state parse_resubmit {
        pkt.extract(hdr.resubmit);
        meta.rs_op        = hdr.resubmit.op;
        meta.rs_cell      = hdr.resubmit.cell;
        meta.rs_key       = hdr.resubmit.key;
        meta.rs_ev_key    = hdr.resubmit.ev_key;
        meta.rs_ev_val    = hdr.resubmit.ev_val;
        meta.rs_ev_flag   = hdr.resubmit.ev_flag;
        meta.rs_guard_new = hdr.resubmit.guard_new;
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
            default        : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}




control IngressDeparser(
    packet_out                                     pkt,
    inout headers_t                                hdr,
    in    ig_metadata_t                            meta,
    in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    apply {
        
        
        
        
        pkt.emit(hdr.resubmit);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
    }
}




parser EgressParser(
    packet_in                        pkt,
    out headers_t                    hdr,
    out eg_metadata_t                meta,
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    state start {
        pkt.extract(eg_intr_md);
        meta._pad = 8w0;
        transition accept;
    }
}

control EgressDeparser(
    packet_out                                     pkt,
    inout headers_t                                hdr,
    in    eg_metadata_t                            meta,
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
    }
}

#endif 
