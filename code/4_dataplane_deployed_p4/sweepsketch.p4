




















#include <t2na.p4>
#include "headers.p4"
#include "parser.p4"

control Ingress(
    inout headers_t                                hdr,
    inout sweep_meta_t                            meta,
    in    ingress_intrinsic_metadata_t             ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t      ig_tm_md)
{
    
    Register<bit<8>,  bit<13>>(8192, 8w0)  l1_pkt;
    Register<bit<8>,  bit<13>>(8192, 8w0)  l1_nn;
    Register<bit<32>, bit<13>>(8192, 32w0) l1_key;
    Register<bit<16>, bit<13>>(8192, 16w0) l1_C;

    
    Hash<bit<16>>(HashAlgorithm_t.CRC32) h_idx1;

    
    RegisterAction<bit<8>, bit<13>, void>(l1_pkt) ra1_padd = {
        void apply(inout bit<8> value) { value = value + 1; }
    };
    
    RegisterAction<bit<8>, bit<13>, void>(l1_nn) ra2_nadd = {
        void apply(inout bit<8> value) { value = value + 1; }
    };
    RegisterAction<bit<8>, bit<13>, void>(l1_nn) ra2_nclr = {
        void apply(inout bit<8> value) { value = 8w0; }
    };
    
    RegisterAction<bit<32>, bit<13>, void>(l1_key) ra3_kw = {
        void apply(inout bit<32> value) { value = meta.key_new; }
    };
    RegisterAction<bit<16>, bit<13>, void>(l1_C) ra3_cadd = {
        void apply(inout bit<16> value) { value = value + 1; }
    };

    
    action nop() {}
    action set_egr(bit<9> port) { ig_tm_md.ucast_egress_port = port; }

    action do_h1()   { meta.idx1 = (bit<13>)(h_idx1.get({8w1, hdr.ipv4.dstAddr}) & 16w0x1FFF); }
    action do1_rp()  { meta.pkt_old = l1_pkt.read((bit<13>)meta.idx1); }
    action do1_padd(){ ra1_padd.execute((bit<13>)meta.idx1); }
    action do2_rp()  { meta.nn_old = l1_nn.read((bit<13>)meta.idx1); }
    action do2_nadd(){ ra2_nadd.execute((bit<13>)meta.idx1); }
    action do2_nclr(){ ra2_nclr.execute((bit<13>)meta.idx1); }
    
    action do3_km()  { meta.key_new = hdr.ipv4.dstAddr & 32w0xFFFFFF00; }
    action do3_kr()  { meta.key_old = l1_key.read((bit<13>)meta.idx1); }
    action do3_kw()  { ra3_kw.execute((bit<13>)meta.idx1); }
    action do3_cr()  { meta.C_old = l1_C.read((bit<13>)meta.idx1); }
    action do3_cadd(){ ra3_cadd.execute((bit<13>)meta.idx1); }
    action do_dg()   { meta.dg_tstamp = ig_prsr_md.global_tstamp[47:16]; }

    table forward_ipv4 {
        key = { ig_intr_md.ingress_port : exact; }
        actions = { set_egr; nop; } default_action = nop(); size = 2;
    }
    
    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr : lpm; }
        actions = { set_egr; nop; } default_action = nop(); size = 4096;
    }
    table tb_h1    { actions = { do_h1; }     default_action = do_h1();     size = 1; }
    table tb1_rp   { actions = { do1_rp; }    default_action = do1_rp();    size = 1; }
    table tb1_padd { actions = { do1_padd; }  default_action = do1_padd();  size = 1; }
    table tb2_rp   { actions = { do2_rp; }    default_action = do2_rp();    size = 1; }
    table tb2_nadd { actions = { do2_nadd; }  default_action = do2_nadd();  size = 1; }
    table tb2_nclr { actions = { do2_nclr; }  default_action = do2_nclr();  size = 1; }
    table tb3_km   { actions = { do3_km; }    default_action = do3_km();    size = 1; }
    table tb3_kr   { actions = { do3_kr; }    default_action = do3_kr();    size = 1; }
    table tb3_kw   { actions = { do3_kw; }    default_action = do3_kw();    size = 1; }
    table tb3_cr   { actions = { do3_cr; }    default_action = do3_cr();    size = 1; }
    table tb3_cadd { actions = { do3_cadd; }  default_action = do3_cadd();  size = 1; }
    table tb_dg    { actions = { do_dg; }     default_action = do_dg();     size = 1; }

    apply {
        forward_ipv4.apply();
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();               
            tb_h1.apply();
            tb1_rp.apply();
            tb1_padd.apply();
            tb2_rp.apply();
            tb2_nadd.apply();
            
            if (hdr.ipv4.totalLen == 16w0) {
                tb2_nclr.apply();
            }
            tb3_km.apply();
            tb3_kr.apply();
            
            if (hdr.ipv4.totalLen == 16w0) {
                tb3_kw.apply();
            }
            tb3_cr.apply();
            tb3_cadd.apply();
            tb_dg.apply();
        }
    }
}

control Egress(
    inout headers_t                                   hdr,
    inout eg_metadata_t                               meta,
    in    egress_intrinsic_metadata_t                 eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_oport_md)
{
    apply { }
}

Pipeline(IngressParser(), Ingress(), IngressDeparser(),
         EgressParser(), Egress(), EgressDeparser()) pipe;

Switch(pipe) main;
