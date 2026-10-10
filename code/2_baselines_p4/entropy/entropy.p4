































#include <t2na.p4>
#include "headers.p4"
#include "parser.p4"


#define NB 2048    
#define Z  64      
#define G  3       

control Ingress(
    inout headers_t                                 hdr,
    inout en_meta_t                                 meta,
    in    ingress_intrinsic_metadata_t              ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md)
{
    
    
    
    
    Register<bit<32>, bit<16>>(NB * Z / 2, 32w0) ctr_lo;   
    Register<bit<32>, bit<16>>(NB * Z / 2, 32w0) ctr_hi;   

    
    
    Hash<bit<16>>(HashAlgorithm_t.CRC32) h_bkt;   
    Hash<bit<16>>(HashAlgorithm_t.CRC32) h_pos0;  
    Hash<bit<16>>(HashAlgorithm_t.CRC32) h_pos1;  
    Hash<bit<16>>(HashAlgorithm_t.CRC32) h_pos2;  

    
    
    
    RegisterAction<bit<32>, bit<16>, void>(ctr_lo) ra_inc0_lo = {
        void apply(inout bit<32> value) {
            if (value != 32w0xFFFFFFFF) { value = value + 1; }
        }
    };
    RegisterAction<bit<32>, bit<16>, void>(ctr_hi) ra_inc0_hi = {
        void apply(inout bit<32> value) {
            if (value != 32w0xFFFFFFFF) { value = value + 1; }
        }
    };
    RegisterAction<bit<32>, bit<16>, void>(ctr_lo) ra_inc1_lo = {
        void apply(inout bit<32> value) {
            if (value != 32w0xFFFFFFFF) { value = value + 1; }
        }
    };
    RegisterAction<bit<32>, bit<16>, void>(ctr_hi) ra_inc1_hi = {
        void apply(inout bit<32> value) {
            if (value != 32w0xFFFFFFFF) { value = value + 1; }
        }
    };
    RegisterAction<bit<32>, bit<16>, void>(ctr_lo) ra_inc2_lo = {
        void apply(inout bit<32> value) {
            if (value != 32w0xFFFFFFFF) { value = value + 1; }
        }
    };
    RegisterAction<bit<32>, bit<16>, void>(ctr_hi) ra_inc2_hi = {
        void apply(inout bit<32> value) {
            if (value != 32w0xFFFFFFFF) { value = value + 1; }
        }
    };

    
    action nop() {}
    action set_egr(bit<9> port) { ig_tm_md.ucast_egress_port = port; }

    
    action do_hb() {
        meta.slot = (bit<11>)(h_bkt.get({16w0xB000, meta.pfx}) & 16w0x07FF);
    }
    
    action do_pfx() { meta.pfx = hdr.ipv4.dstAddr & 32w0xFFFFFF00; }
    
    action do_h0() {
        meta.pos0 = (bit<6>)(h_pos0.get({16w0xC100, hdr.ipv4.dstAddr}) & 16w0x3F);
    }
    action do_h1() {
        meta.pos1 = (bit<6>)(h_pos1.get({16w0xC101, hdr.ipv4.dstAddr}) & 16w0x3F);
    }
    action do_h2() {
        meta.pos2 = (bit<6>)(h_pos2.get({16w0xC102, hdr.ipv4.dstAddr}) & 16w0x3F);
    }
    
    
    
    action do_i0() {
        meta.idx0 = meta.slot[10:0] ++ meta.pos0[4:0];
        meta.sel0 = meta.pos0[5:5];
    }
    action do_i1() {
        meta.idx1 = meta.slot[10:0] ++ meta.pos1[4:0];
        meta.sel1 = meta.pos1[5:5];
    }
    action do_i2() {
        meta.idx2 = meta.slot[10:0] ++ meta.pos2[4:0];
        meta.sel2 = meta.pos2[5:5];
    }

    
    action do_inc0_lo() { ra_inc0_lo.execute(meta.idx0); }
    action do_inc0_hi() { ra_inc0_hi.execute(meta.idx0); }
    action do_inc1_lo() { ra_inc1_lo.execute(meta.idx1); }
    action do_inc1_hi() { ra_inc1_hi.execute(meta.idx1); }
    action do_inc2_lo() { ra_inc2_lo.execute(meta.idx2); }
    action do_inc2_hi() { ra_inc2_hi.execute(meta.idx2); }

    
    table forward_ipv4 {
        key = { ig_intr_md.ingress_port : exact; }
        actions = { set_egr; nop; } default_action = nop(); size = 2;
    }
    
    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr : lpm; }
        actions = { set_egr; nop; } default_action = nop(); size = 4096;
    }
    
    table tb_pfx  { actions = { do_pfx; }  default_action = do_pfx();  size = 1; }
    table tb_hb   { actions = { do_hb; }   default_action = do_hb();   size = 1; }
    table tb_h0   { actions = { do_h0; }   default_action = do_h0();   size = 1; }
    table tb_h1   { actions = { do_h1; }   default_action = do_h1();   size = 1; }
    table tb_h2   { actions = { do_h2; }   default_action = do_h2();   size = 1; }
    table tb_i0   { actions = { do_i0; }   default_action = do_i0();   size = 1; }
    table tb_i1   { actions = { do_i1; }   default_action = do_i1();   size = 1; }
    table tb_i2   { actions = { do_i2; }   default_action = do_i2();   size = 1; }
    table tb_inc0_lo { actions = { do_inc0_lo; } default_action = do_inc0_lo(); size = 1; }
    table tb_inc0_hi { actions = { do_inc0_hi; } default_action = do_inc0_hi(); size = 1; }
    table tb_inc1_lo { actions = { do_inc1_lo; } default_action = do_inc1_lo(); size = 1; }
    table tb_inc1_hi { actions = { do_inc1_hi; } default_action = do_inc1_hi(); size = 1; }
    table tb_inc2_lo { actions = { do_inc2_lo; } default_action = do_inc2_lo(); size = 1; }
    table tb_inc2_hi { actions = { do_inc2_hi; } default_action = do_inc2_hi(); size = 1; }

    apply {
        forward_ipv4.apply();
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();               
            tb_pfx.apply();
            tb_hb.apply();
            tb_h0.apply(); tb_h1.apply(); tb_h2.apply();
            tb_i0.apply(); tb_i1.apply(); tb_i2.apply();
            
            if (meta.sel0 == 1w1) { tb_inc0_hi.apply(); } else { tb_inc0_lo.apply(); }
            if (meta.sel1 == 1w1) { tb_inc1_hi.apply(); } else { tb_inc1_lo.apply(); }
            if (meta.sel2 == 1w1) { tb_inc2_hi.apply(); } else { tb_inc2_lo.apply(); }
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
