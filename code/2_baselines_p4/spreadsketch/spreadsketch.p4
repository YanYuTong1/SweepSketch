
#include <t2na.p4>
#include "headers.p4"
#include "parser.p4"

control Ingress(
    inout headers_t                                 hdr,
    inout ig_metadata_t                             meta,
    in    ingress_intrinsic_metadata_t              ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md)
{
    
    
    Register<bit<32>, bit<10>>(1024, 32w0)  key_r0;
    Register<bit<8>,  bit<10>>(1024, 8w0)   lvl_r0;
    Register<bit<32>, bit<14>>(16384, 32w0) bm_r0;

    Register<bit<32>, bit<10>>(1024, 32w0)  key_r1;
    Register<bit<8>,  bit<10>>(1024, 8w0)   lvl_r1;
    Register<bit<32>, bit<14>>(16384, 32w0) bm_r1;

    Register<bit<32>, bit<10>>(1024, 32w0)  key_r2;
    Register<bit<8>,  bit<10>>(1024, 8w0)   lvl_r2;
    Register<bit<32>, bit<14>>(16384, 32w0) bm_r2;

    Register<bit<32>, bit<10>>(1024, 32w0)  key_r3;
    Register<bit<8>,  bit<10>>(1024, 8w0)   lvl_r3;
    Register<bit<32>, bit<14>>(16384, 32w0) bm_r3;

    
    
    
    Hash<bit<32>>(HashAlgorithm_t.CRC32) h1;
    Hash<bit<32>>(HashAlgorithm_t.CRC32) h2;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) h_bk0;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) h_bk1;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) h_bk2;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) h_bk3;

    
    
    RegisterAction<bit<8>, bit<10>, bit<8>>(lvl_r0) ra_lvl0 = {
        void apply(inout bit<8> value, out bit<8> rv) {
            rv = value;                                 
            if (meta.lvl > value) { value = meta.lvl; } 
        }
    };
    RegisterAction<bit<32>, bit<10>, void>(key_r0) ra_key0 = {
        void apply(inout bit<32> value) {
            
            if (meta.takeover_r0) { value = meta.src_addr; }
        }
    };
    RegisterAction<bit<32>, bit<14>, void>(bm_r0) ra_bm0 = {
        void apply(inout bit<32> value) { value = value | meta.bm_mask; }   
    };

    
    RegisterAction<bit<8>, bit<10>, bit<8>>(lvl_r1) ra_lvl1 = {
        void apply(inout bit<8> value, out bit<8> rv) {
            rv = value;
            if (meta.lvl > value) { value = meta.lvl; }
        }
    };
    RegisterAction<bit<32>, bit<10>, void>(key_r1) ra_key1 = {
        void apply(inout bit<32> value) {
            if (meta.takeover_r1) { value = meta.src_addr; }
        }
    };
    RegisterAction<bit<32>, bit<14>, void>(bm_r1) ra_bm1 = {
        void apply(inout bit<32> value) { value = value | meta.bm_mask; }
    };

    
    RegisterAction<bit<8>, bit<10>, bit<8>>(lvl_r2) ra_lvl2 = {
        void apply(inout bit<8> value, out bit<8> rv) {
            rv = value;
            if (meta.lvl > value) { value = meta.lvl; }
        }
    };
    RegisterAction<bit<32>, bit<10>, void>(key_r2) ra_key2 = {
        void apply(inout bit<32> value) {
            if (meta.takeover_r2) { value = meta.src_addr; }
        }
    };
    RegisterAction<bit<32>, bit<14>, void>(bm_r2) ra_bm2 = {
        void apply(inout bit<32> value) { value = value | meta.bm_mask; }
    };

    
    RegisterAction<bit<8>, bit<10>, bit<8>>(lvl_r3) ra_lvl3 = {
        void apply(inout bit<8> value, out bit<8> rv) {
            rv = value;
            if (meta.lvl > value) { value = meta.lvl; }
        }
    };
    RegisterAction<bit<32>, bit<10>, void>(key_r3) ra_key3 = {
        void apply(inout bit<32> value) {
            if (meta.takeover_r3) { value = meta.src_addr; }
        }
    };
    RegisterAction<bit<32>, bit<14>, void>(bm_r3) ra_bm3 = {
        void apply(inout bit<32> value) { value = value | meta.bm_mask; }
    };

    
    action nop() {}
    action set_egr(bit<9> egr_port) { ig_tm_md.ucast_egress_port = egr_port; }

    
    action do_h1() {
        meta.src_addr = hdr.ipv4.srcAddr;
        meta.h1 = h1.get({8w0x55, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr});
    }
    action do_h2() {
        meta.h2 = h2.get({8w0x56, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr});
    }

    
    
    action do_split() {
        meta.pos     = meta.h1[31:23];
        meta.bm_word = meta.pos[8:5];      
        meta.bit_idx = meta.pos[4:0];      
        meta.b0      = meta.h2[7:0];       
        meta.b1      = meta.h2[15:8];
        meta.b2      = meta.h2[23:16];
        meta.b3      = meta.h2[31:24];
    }

    
    
    
    
    action act_lvl_tc(bit<8> lvl_v) { meta.lvl = lvl_v; }

    
    action act_mask(bit<32> m) { meta.bm_mask = m; }

    
    
    
    action do_bk0() {
        bit<16> raw = h_bk0.get({16w0x6600, hdr.ipv4.srcAddr});
        meta.bucket_r0 = (bit<10>)(raw & 16w0x3FF);          
    }
    action do_bk1() {
        bit<16> raw = h_bk1.get({16w0x6601, hdr.ipv4.srcAddr});
        meta.bucket_r1 = (bit<10>)(raw & 16w0x3FF);
    }
    action do_bk2() {
        bit<16> raw = h_bk2.get({16w0x6602, hdr.ipv4.srcAddr});
        meta.bucket_r2 = (bit<10>)(raw & 16w0x3FF);
    }
    action do_bk3() {
        bit<16> raw = h_bk3.get({16w0x6603, hdr.ipv4.srcAddr});
        meta.bucket_r3 = (bit<10>)(raw & 16w0x3FF);
    }
    
    action do_bi0() { meta.bm_idx_r0 = meta.bucket_r0 ++ meta.bm_word; }
    action do_bi1() { meta.bm_idx_r1 = meta.bucket_r1 ++ meta.bm_word; }
    action do_bi2() { meta.bm_idx_r2 = meta.bucket_r2 ++ meta.bm_word; }
    action do_bi3() { meta.bm_idx_r3 = meta.bucket_r3 ++ meta.bm_word; }

    
    action do_lvl0() { meta.old_lvl_r0 = ra_lvl0.execute(meta.bucket_r0); }
    action do_lvl1() { meta.old_lvl_r1 = ra_lvl1.execute(meta.bucket_r1); }
    action do_lvl2() { meta.old_lvl_r2 = ra_lvl2.execute(meta.bucket_r2); }
    action do_lvl3() { meta.old_lvl_r3 = ra_lvl3.execute(meta.bucket_r3); }

    
    action do_cmp0() { meta.takeover_r0 = (meta.lvl > meta.old_lvl_r0); }
    action do_cmp1() { meta.takeover_r1 = (meta.lvl > meta.old_lvl_r1); }
    action do_cmp2() { meta.takeover_r2 = (meta.lvl > meta.old_lvl_r2); }
    action do_cmp3() { meta.takeover_r3 = (meta.lvl > meta.old_lvl_r3); }

    
    action do_key0() { ra_key0.execute(meta.bucket_r0); }
    action do_key1() { ra_key1.execute(meta.bucket_r1); }
    action do_key2() { ra_key2.execute(meta.bucket_r2); }
    action do_key3() { ra_key3.execute(meta.bucket_r3); }
    action do_bm0()  { ra_bm0.execute(meta.bm_idx_r0); }
    action do_bm1()  { ra_bm1.execute(meta.bm_idx_r1); }
    action do_bm2()  { ra_bm2.execute(meta.bm_idx_r2); }
    action do_bm3()  { ra_bm3.execute(meta.bm_idx_r3); }

    
    
    table forward_ipv4 {
        key = { ig_intr_md.ingress_port : exact; }
        actions = { set_egr; nop; } default_action = nop(); size = 2;
    }
    
    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr : lpm; }
        actions = { set_egr; nop; } default_action = nop(); size = 4096;
    }
    table tb_h1    { actions = { do_h1; }    default_action = do_h1();    size = 1; }
    table tb_h2    { actions = { do_h2; }    default_action = do_h2();    size = 1; }
    table tb_split { actions = { do_split; } default_action = do_split(); size = 1; }

    
    table tz_tcam {
        key = {
            meta.b3 : ternary;
            meta.b2 : ternary;
            meta.b1 : ternary;
            meta.b0 : ternary;
        }
        actions = { act_lvl_tc; } default_action = act_lvl_tc(8w1); size = 32;
    }

    
    table tbl_mask {
        key = { meta.bit_idx : exact; }
        actions = { act_mask; nop; } default_action = nop(); size = 32;
    }

    
    table tb_bk0  { actions = { do_bk0; }  default_action = do_bk0();  size = 1; }
    table tb_bi0  { actions = { do_bi0; }  default_action = do_bi0();  size = 1; }
    table tb_lvl0 { actions = { do_lvl0; } default_action = do_lvl0(); size = 1; }
    table tb_cmp0 { actions = { do_cmp0; } default_action = do_cmp0(); size = 1; }
    table tb_key0 { actions = { do_key0; } default_action = do_key0(); size = 1; }
    table tb_bm0  { actions = { do_bm0; }  default_action = do_bm0();  size = 1; }

    table tb_bk1  { actions = { do_bk1; }  default_action = do_bk1();  size = 1; }
    table tb_bi1  { actions = { do_bi1; }  default_action = do_bi1();  size = 1; }
    table tb_lvl1 { actions = { do_lvl1; } default_action = do_lvl1(); size = 1; }
    table tb_cmp1 { actions = { do_cmp1; } default_action = do_cmp1(); size = 1; }
    table tb_key1 { actions = { do_key1; } default_action = do_key1(); size = 1; }
    table tb_bm1  { actions = { do_bm1; }  default_action = do_bm1();  size = 1; }

    table tb_bk2  { actions = { do_bk2; }  default_action = do_bk2();  size = 1; }
    table tb_bi2  { actions = { do_bi2; }  default_action = do_bi2();  size = 1; }
    table tb_lvl2 { actions = { do_lvl2; } default_action = do_lvl2(); size = 1; }
    table tb_cmp2 { actions = { do_cmp2; } default_action = do_cmp2(); size = 1; }
    table tb_key2 { actions = { do_key2; } default_action = do_key2(); size = 1; }
    table tb_bm2  { actions = { do_bm2; }  default_action = do_bm2();  size = 1; }

    table tb_bk3  { actions = { do_bk3; }  default_action = do_bk3();  size = 1; }
    table tb_bi3  { actions = { do_bi3; }  default_action = do_bi3();  size = 1; }
    table tb_lvl3 { actions = { do_lvl3; } default_action = do_lvl3(); size = 1; }
    table tb_cmp3 { actions = { do_cmp3; } default_action = do_cmp3(); size = 1; }
    table tb_key3 { actions = { do_key3; } default_action = do_key3(); size = 1; }
    table tb_bm3  { actions = { do_bm3; }  default_action = do_bm3();  size = 1; }

    apply {
        forward_ipv4.apply();
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();               
            
            tb_h1.apply(); tb_h2.apply();
            tb_split.apply();
            
            tz_tcam.apply();
            
            tbl_mask.apply();
            
            tb_bk0.apply(); tb_bi0.apply(); tb_lvl0.apply(); tb_cmp0.apply(); tb_key0.apply(); tb_bm0.apply();
            tb_bk1.apply(); tb_bi1.apply(); tb_lvl1.apply(); tb_cmp1.apply(); tb_key1.apply(); tb_bm1.apply();
            tb_bk2.apply(); tb_bi2.apply(); tb_lvl2.apply(); tb_cmp2.apply(); tb_key2.apply(); tb_bm2.apply();
            tb_bk3.apply(); tb_bi3.apply(); tb_lvl3.apply(); tb_cmp3.apply(); tb_key3.apply(); tb_bm3.apply();
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
