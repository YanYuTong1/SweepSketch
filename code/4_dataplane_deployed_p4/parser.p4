
#include "headers.p4"

parser IngressParser(
    packet_in pkt,
    out headers_t hdr,
    out sweep_meta_t meta,
    out ingress_intrinsic_metadata_t ig_intr_md)
{
    state start {
        pkt.extract(ig_intr_md);
        meta.idx1 = 0;
        meta._p1 = 0;
        meta.pkt_old = 0;
        meta.nn_old = 0;
        meta.key_old = 0;
        meta.key_new = 0;
        meta.C_old = 0;
        meta.dg_tstamp = 0;
        hdr.ethernet.setInvalid();
        hdr.ipv4.setInvalid();
        
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            default : parse_port_metadata;
        }
    }

    state parse_resubmit {
        
        transition parse_normal;
    }

    state parse_port_metadata {
        
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_normal;
    }

    state parse_normal {
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

control IngressDeparser(packet_out pkt, inout headers_t hdr, in sweep_meta_t meta,
                        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    Digest<sweep_digest_t>() dg;

    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        
        if (hdr.ipv4.isValid()) {
            sweep_digest_t d;
            d.dst_addr = hdr.ipv4.dstAddr;
            d.pkt_old  = meta.pkt_old;
            d.nn_old   = meta.nn_old;
            d.key_old  = meta.key_old;
            d.C_old    = meta.C_old;
            d.tstamp   = meta.dg_tstamp;
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
        pkt.emit(hdr.ipv4);
    }
}
