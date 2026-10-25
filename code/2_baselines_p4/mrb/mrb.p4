
#include <t2na.p4>
#include "headers.p4"
#include "parser.p4"


#define NB          2048    
#define MRB_B       512     
#define MRB_LASTB   1024    
#define B_WORDS     16      
#define LASTB_WORDS 32      

control Ingress(
    inout headers_t                                 hdr,
    inout mr_meta_t                                 meta,
    in    ingress_intrinsic_metadata_t              ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md)
{
    
    Register<bit<32>, bit<15>>(NB * B_WORDS, 32w0)     b0w;   
    Register<bit<32>, bit<15>>(NB * B_WORDS, 32w0)     b1w;   
    Register<bit<32>, bit<16>>(NB * LASTB_WORDS, 32w0) blw;   

    
    
    Hash<bit<16>>(HashAlgorithm_t.CRC32) h_bkt;   
    Hash<bit<32>>(HashAlgorithm_t.CRC32) h_p;     

    
    RegisterAction<bit<32>, bit<15>, void>(b1w) ra_b1 = {
        void apply(inout bit<32> value) { value = value | meta.mask; }
    };
    RegisterAction<bit<32>, bit<16>, void>(blw) ra_bl = {
        void apply(inout bit<32> value) { value = value | meta.mask; }
    };

    
    action nop() {}
    action set_egr(bit<9> port) { ig_tm_md.ucast_egress_port = port; }

    
    action do_hb() {
        meta.slot = (bit<11>)(h_bkt.get({16w0xA100, meta.pfx}) & 16w0x07FF);
    }
    
    action do_hp() { meta.p32 = h_p.get({16w0xB100, hdr.ipv4.dstAddr}); }

    
    action do_pfx() { meta.pfx = hdr.ipv4.dstAddr & 32w0xFFFFFF00; }

    
    
    action do_split() {
        meta.p_bit0 = meta.p32[0:0];
        meta.word1  = meta.p32[31:28];
        meta.bit1   = meta.p32[27:23];
        meta.wordl  = meta.p32[31:27];
        meta.bitl   = meta.p32[26:22];
        meta.b1_idx = meta.slot[10:0] ++ meta.word1;
        meta.bl_idx = meta.slot[10:0] ++ meta.wordl;
    }

    
    action set_mask_b1() { meta.mask_key = meta.bit1; }
    action set_mask_bl() { meta.mask_key = meta.bitl; }

    action act_mask(bit<32> m) { meta.mask = m; }
    action do_b1() { ra_b1.execute(meta.b1_idx); }
    action do_bl() { ra_bl.execute(meta.bl_idx); }

    
    table forward_ipv4 {
        key = { ig_intr_md.ingress_port : exact; }
        actions = { set_egr; nop; } default_action = nop(); size = 2;
    }
    
    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr : lpm; }
        actions = { set_egr; nop; } default_action = nop(); size = 4096;
    }
    
    table tb_pfx   { actions = { do_pfx; }   default_action = do_pfx();   size = 1; }
    table tb_hb    { actions = { do_hb; }    default_action = do_hb();    size = 1; }
    table tb_hp    { actions = { do_hp; }    default_action = do_hp();    size = 1; }
    table tb_split { actions = { do_split; } default_action = do_split(); size = 1; }
    
    table t_mk1    { actions = { set_mask_b1; } default_action = set_mask_b1(); size = 1; }
    table t_mkl    { actions = { set_mask_bl; } default_action = set_mask_bl(); size = 1; }
    
    table tbl_mask {
        key = { meta.mask_key : exact; }
        actions = { act_mask; nop; } default_action = nop(); size = 32;
    }
    table tb_b1    { actions = { do_b1; }    default_action = do_b1();    size = 1; }
    table tb_bl    { actions = { do_bl; }    default_action = do_bl();    size = 1; }

    apply {
        forward_ipv4.apply();
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();               
            tb_pfx.apply();
            tb_hb.apply();
            tb_hp.apply();
            tb_split.apply();
            
            if (meta.p_bit0 == 0) { t_mk1.apply(); }
            else                  { t_mkl.apply(); }
            tbl_mask.apply();
            
            if (meta.p_bit0 == 0) { tb_b1.apply(); }
            else                  { tb_bl.apply(); }
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
