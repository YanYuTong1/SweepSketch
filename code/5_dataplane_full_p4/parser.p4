








#include "headers.p4"

parser IngressParser(
    packet_in pkt,
    out headers_t hdr,
    out sweep_meta_t meta,
    out ingress_intrinsic_metadata_t ig_intr_md)
{
    state start {
        pkt.extract(ig_intr_md);
        
        meta.idx1 = 0; meta.idx2 = 0; meta.r = 0; meta.rho = 0;
        meta.rho_done = 0; meta.hr = 0;
        meta.r_hi = 0; meta.r_mid = 0; meta.r_lo = 0; meta.r_tail = 0;
        meta.global_epoch = 0; meta.pkt_key = 0; meta.pkt_key2 = 0;
        meta.C_old = 0; meta.pkt_old = 0; meta.pkt2_old = 0;   
        meta.key_ok = false; meta.cold = 0; meta.claim = false; meta.skip = 0;
        meta.key_nz       = false;
        meta.pkt_ge_min   = false;
        meta.C_lt         = false;
        meta.delta_total  = 16w0;
        meta.ep_old = 0; meta.win_new = 0; meta.rollover = false;
        meta.e1 = 0; meta.ep_new = 0;
        meta.hll_rv = 0; meta.event = 0;
        meta.tag_ne = false; meta.rho_gt = false; meta.w5 = 0; meta.hll_new = 0;
        meta.nn_old = 0;
        meta.ge3 = false; meta.held_new = 0;   
        meta.ge3c = false; meta.nn_ge = false;   
        meta.nn_ge_2ne = false; meta.ne_old = 0; meta.ne2 = 0;   
        
        meta.ge3b = false;
        meta.w5_2 = 0; meta.e1_2 = 0;
        meta.delta2_total = 16w0;
        
        meta.C2_old = 0;
        meta.key_ok2 = false; meta.cold2 = 0; meta.claim2 = false; meta.skip2 = 0;
        meta.key2_nz      = false;
        meta.pkt2_ge_min  = false;
        meta.C2_lt        = false;
        meta.ep2_old = 0; meta.win2_new = 0; meta.rollover2 = false;
        meta.ep_new2 = 0;
        meta.hll2_rv = 0; meta.event2 = 0;
        meta.tag2_ne = false; meta.rho2_gt = false; meta.hll_new2 = 0;
        meta.nn2_old = 0;
        
        meta.dg_prefix = 0;
        meta.dg_pkt = 0; meta.dg_n_new = 0;
        meta.dg_event = 0;
        meta.dg_held = 0;   
        meta.dg_C = 0; meta.dg_delta = 0;
        meta.dg_tstamp = 0;
        meta.dg2_prefix = 0;
        meta.dg2_pkt = 0; meta.dg2_n_new = 0;
        meta.dg2_event = 0;
        meta.dg2_C = 0; meta.dg2_delta = 0;
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
            d.l1_prefix   = meta.dg_prefix;
            d.l1_pkt      = meta.dg_pkt;
            d.l1_n_new    = meta.dg_n_new;
            d.l1_event    = meta.dg_event;
            d.l1_held     = meta.dg_held;   
            d.l1_C        = meta.dg_C;
            d.l1_delta_C  = meta.dg_delta;
            d.l2_prefix   = meta.dg2_prefix;
            d.l2_pkt      = meta.dg2_pkt;
            d.l2_n_new    = meta.dg2_n_new;
            d.l2_event    = meta.dg2_event;
            d.l2_C        = meta.dg2_C;
            d.l2_delta_C  = meta.dg2_delta;
            d.tstamp      = meta.dg_tstamp;
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
