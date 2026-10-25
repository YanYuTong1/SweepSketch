

#ifndef _PARSER_P4_
#define _PARSER_P4_

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
        meta.hash_s1            = 1w0;
        meta.hash_s2            = 1w0;
        meta.hash_s3            = 1w0;
        meta.hash_s4            = 1w0;
        meta.mask1              = 8w0;
        meta.mask2              = 8w0;
        meta.mask3              = 8w0;
        meta.subnet_bm          = 16w0;
        meta.prefix_len         = 8w0;
        meta.col_r0             = 8w0;
        meta.col_r1             = 8w0;
        meta.col_r2             = 8w0;
        meta.host_bm_byte       = 8w0;
        meta.host_bm_bit        = 5w0;
        meta.host_bm_word       = 3w0;
        meta.host_bm_index      = 9w0;
        meta.host_bm_index_r1   = 9w0;
        meta.host_bm_index_r2   = 9w0;
        meta.host_bm_mask       = 32w0;
        meta.r0_key             = 32w0;
        meta.r1_key             = 32w0;
        meta.r2_key             = 32w0;
        meta.r0_subnet_bm       = 16w0;
        meta.r1_subnet_bm       = 16w0;
        meta.r2_subnet_bm       = 16w0;
        meta.r0_host_bm_word    = 32w0;
        meta.r1_host_bm_word    = 32w0;
        meta.r2_host_bm_word    = 32w0;
        meta.r0_pkt_cnt         = 32w0;
        meta.r1_pkt_cnt         = 32w0;
        meta.r2_pkt_cnt         = 32w0;
        meta.match_row          = 2w0;
        meta.has_empty          = false;
        meta.empty_col          = 8w0;
        meta.empty_row          = 2w0;
        meta.victim_row         = 2w0;
        meta.do_replace         = false;
        meta.active_r0          = false;
        meta.active_r1          = false;
        meta.active_r2          = false;
        meta.is_new_pkt         = 16w0;
        meta.pkt_tag            = 16w0;

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

        
        
        
        hdr.user.setValid();
        hdr.user.dst_byte_1 = hdr.ipv4.dstAddr[31:24];
        hdr.user.dst_byte_2 = hdr.ipv4.dstAddr[23:16];
        hdr.user.dst_byte_3 = hdr.ipv4.dstAddr[15:8];
        hdr.user.dst_byte_4 = hdr.ipv4.dstAddr[7:0];
        hdr.user.src_byte_1 = hdr.ipv4.srcAddr[31:24];
        hdr.user.src_byte_2 = hdr.ipv4.srcAddr[23:16];
        hdr.user.src_byte_3 = hdr.ipv4.srcAddr[15:8];
        hdr.user.src_byte_4 = hdr.ipv4.srcAddr[7:0];

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
