

#ifndef _SPREADSKETCH_PARSER_P4_
#define _SPREADSKETCH_PARSER_P4_

#include <t2na.p4>
#include "headers.p4"




const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_VLAN = 0x8100;
const bit<8>  IP_PROTO_TCP   = 0x06;
const bit<8>  IP_PROTO_UDP   = 0x11;




parser IngressParser(
    packet_in                        pkt,
    out   headers_t                  hdr,
    out   ig_metadata_t              meta,
    out   ingress_intrinsic_metadata_t ig_intr_md)
{
    
    
    
    
    state start {
        pkt.extract(ig_intr_md);

        meta.src_addr           = 32w0;
        meta.dst_addr           = 32w0;
        meta.transport_src_port = 16w0;
        meta.transport_dst_port = 16w0;
        meta.h1                 = 32w0;
        meta.h2                 = 32w0;
        meta.pos                = 9w0;
        meta.bm_word            = 4w0;
        meta.bit_idx            = 5w0;
        meta.bm_mask            = 32w0;
        meta.b0                 = 8w0;
        meta.b1                 = 8w0;
        meta.b2                 = 8w0;
        meta.b3                 = 8w0;
        meta.tz_acc             = 8w0;
        meta.tz_done            = 1w0;
        meta.lvl                = 8w0;
        meta.bucket_r0          = 10w0;
        meta.bucket_r1          = 10w0;
        meta.bucket_r2          = 10w0;
        meta.bucket_r3          = 10w0;
        meta.bm_idx_r0          = 14w0;
        meta.bm_idx_r1          = 14w0;
        meta.bm_idx_r2          = 14w0;
        meta.bm_idx_r3          = 14w0;
        meta.old_lvl_r0         = 8w0;
        meta.old_lvl_r1         = 8w0;
        meta.old_lvl_r2         = 8w0;
        meta.old_lvl_r3         = 8w0;
        meta.takeover_r0        = false;
        meta.takeover_r1        = false;
        meta.takeover_r2        = false;
        meta.takeover_r3        = false;

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
        meta.transport_src_port = hdr.tcp.srcPort;
        meta.transport_dst_port = hdr.tcp.dstPort;
        transition accept;
    }

    
    
    
    state parse_udp {
        pkt.extract(hdr.udp);
        meta.transport_src_port = hdr.udp.srcPort;
        meta.transport_dst_port = hdr.udp.dstPort;
        transition accept;
    }
}




control IngressDeparser(
    packet_out                                      pkt,
    inout headers_t                                 hdr,
    in    ig_metadata_t                             meta,
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
