












#ifndef _ENTROPY_PARSER_P4_
#define _ENTROPY_PARSER_P4_

#include <t2na.p4>
#include "headers.p4"




const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_VLAN = 0x8100;
const bit<8>  IP_PROTO_TCP   = 0x06;
const bit<8>  IP_PROTO_UDP   = 0x11;




parser IngressParser(
    packet_in                        pkt,
    out   headers_t                  hdr,
    out   en_meta_t                  meta,
    out   ingress_intrinsic_metadata_t ig_intr_md)
{
    
    
    
    state start {
        pkt.extract(ig_intr_md);

        
        meta.pfx  = 32w0;
        meta.slot = 11w0;
        meta.pos0 = 6w0;
        meta.pos1 = 6w0;
        meta.pos2 = 6w0;
        meta.idx0 = 16w0;
        meta.idx1 = 16w0;
        meta.idx2 = 16w0;
        meta.sel0 = 1w0;
        meta.sel1 = 1w0;
        meta.sel2 = 1w0;

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
    in    en_meta_t                                 meta,
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
