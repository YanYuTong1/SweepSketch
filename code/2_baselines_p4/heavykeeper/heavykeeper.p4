
#include <t2na.p4>
#include "headers.p4"
#include "parser.p4"

#define HK_W 16384        

control Ingress(
    inout headers_t                                 hdr,
    inout ig_metadata_t                             meta,
    in    ingress_intrinsic_metadata_t              ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md)
{
    
    Register<bit<32>, bit<14>>(HK_W, 32w0) fp_r0;
    Register<bit<16>, bit<14>>(HK_W, 16w0) cnt_r0;
    Register<bit<32>, bit<14>>(HK_W, 32w0) fp_r1;
    Register<bit<16>, bit<14>>(HK_W, 16w0) cnt_r1;
    Register<bit<32>, bit<14>>(HK_W, 32w0) fp_r2;
    Register<bit<16>, bit<14>>(HK_W, 16w0) cnt_r2;
    Register<bit<16>, bit<4>>(1, 16w0)   hmin_reg;   

    
    Hash<bit<16>>(HashAlgorithm_t.CRC32) h_col0;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) h_col1;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) h_col2;
    Hash<bit<32>>(HashAlgorithm_t.CRC32) h_dec0;
    Hash<bit<32>>(HashAlgorithm_t.CRC32) h_dec1;
    Hash<bit<32>>(HashAlgorithm_t.CRC32) h_dec2;

    
    
    
    RegisterAction<bit<32>, bit<14>, bit<32>>(fp_r0) ra_fp0 = {
        void apply(inout bit<32> value, out bit<32> rv) {
            rv = value;
            if (value == 32w0) { value = meta.key24; }
        }
    };
    
    RegisterAction<bit<32>, bit<14>, void>(fp_r0) ra_repl0 = {
        void apply(inout bit<32> value) { value = meta.key24; }
    };
    
    RegisterAction<bit<16>, bit<14>, bit<16>>(cnt_r0) ra_cpeek0 = {
        void apply(inout bit<16> value, out bit<16> rv) { rv = value; }
    };
    
    RegisterAction<bit<16>, bit<14>, void>(cnt_r0) ra_set1_0 = {
        void apply(inout bit<16> value) { value = 16w1; }
    };
    RegisterAction<bit<16>, bit<14>, void>(cnt_r0) ra_inc0 = {
        void apply(inout bit<16> value) {
            if (value < 16w255) { value = value + 16w1; }
        }
    };
    RegisterAction<bit<16>, bit<14>, void>(cnt_r0) ra_dec0 = {
        void apply(inout bit<16> value) {
            if (value > 16w1) { value = value - 16w1; }
        }
    };
    
    RegisterAction<bit<32>, bit<14>, bit<32>>(fp_r1) ra_fp1 = {
        void apply(inout bit<32> value, out bit<32> rv) {
            rv = value;
            if (value == 32w0) { value = meta.key24; }
        }
    };
    RegisterAction<bit<32>, bit<14>, void>(fp_r1) ra_repl1 = {
        void apply(inout bit<32> value) { value = meta.key24; }
    };
    RegisterAction<bit<16>, bit<14>, bit<16>>(cnt_r1) ra_cpeek1 = {
        void apply(inout bit<16> value, out bit<16> rv) { rv = value; }
    };
    RegisterAction<bit<16>, bit<14>, void>(cnt_r1) ra_set1_1 = {
        void apply(inout bit<16> value) { value = 16w1; }
    };
    RegisterAction<bit<16>, bit<14>, void>(cnt_r1) ra_inc1 = {
        void apply(inout bit<16> value) {
            if (value < 16w255) { value = value + 16w1; }
        }
    };
    RegisterAction<bit<16>, bit<14>, void>(cnt_r1) ra_dec1 = {
        void apply(inout bit<16> value) {
            if (value > 16w1) { value = value - 16w1; }
        }
    };
    
    RegisterAction<bit<32>, bit<14>, bit<32>>(fp_r2) ra_fp2 = {
        void apply(inout bit<32> value, out bit<32> rv) {
            rv = value;
            if (value == 32w0) { value = meta.key24; }
        }
    };
    RegisterAction<bit<32>, bit<14>, void>(fp_r2) ra_repl2 = {
        void apply(inout bit<32> value) { value = meta.key24; }
    };
    RegisterAction<bit<16>, bit<14>, bit<16>>(cnt_r2) ra_cpeek2 = {
        void apply(inout bit<16> value, out bit<16> rv) { rv = value; }
    };
    RegisterAction<bit<16>, bit<14>, void>(cnt_r2) ra_set1_2 = {
        void apply(inout bit<16> value) { value = 16w1; }
    };
    RegisterAction<bit<16>, bit<14>, void>(cnt_r2) ra_inc2 = {
        void apply(inout bit<16> value) {
            if (value < 16w255) { value = value + 16w1; }
        }
    };
    RegisterAction<bit<16>, bit<14>, void>(cnt_r2) ra_dec2 = {
        void apply(inout bit<16> value) {
            if (value > 16w1) { value = value - 16w1; }
        }
    };
    
    RegisterAction<bit<16>, bit<4>, bit<16>>(hmin_reg) ra_hmin = {
        void apply(inout bit<16> value, out bit<16> rv) { rv = value; }
    };

    
    action nop() {}
    action set_egr(bit<9> egr_port) { ig_tm_md.ucast_egress_port = egr_port; }

    
    
    
    action do_key() {
        meta.key24 = hdr.ipv4.dstAddr & 32w0xFFFFFF00;
    }

    
    action set_in_heap()     { meta.in_heap = 1w1; }
    action set_not_in_heap() { meta.in_heap = 1w0; }

    
    action do_hmin() { meta.hmin = ra_hmin.execute(4w0); }

    
    action do_col0() {
        bit<16> h = h_col0.get({16w0xA100, meta.key24});
        meta.col_r0 = h[13:0];
    }
    action do_col1() {
        bit<16> h = h_col1.get({16w0xA101, meta.key24});
        meta.col_r1 = h[13:0];
    }
    action do_col2() {
        bit<16> h = h_col2.get({16w0xA102, meta.key24});
        meta.col_r2 = h[13:0];
    }

    
    action do_dech0() {
        meta.r_r0 = h_dec0.get({16w0xA200, meta.key24,
                                hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 8w0});
    }
    action do_dech1() {
        meta.r_r1 = h_dec1.get({16w0xA200, meta.key24,
                                hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 8w1});
    }
    action do_dech2() {
        meta.r_r2 = h_dec2.get({16w0xA200, meta.key24,
                                hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 8w2});
    }

    
    action do_fp0()    { meta.rv_r0 = ra_fp0.execute(meta.col_r0); }
    action do_fp1()    { meta.rv_r1 = ra_fp1.execute(meta.col_r1); }
    action do_fp2()    { meta.rv_r2 = ra_fp2.execute(meta.col_r2); }
    action do_cpeek0() { meta.cnt_r0 = ra_cpeek0.execute(meta.col_r0); }
    action do_cpeek1() { meta.cnt_r1 = ra_cpeek1.execute(meta.col_r1); }
    action do_cpeek2() { meta.cnt_r2 = ra_cpeek2.execute(meta.col_r2); }

    
    
    action do_flags0() {
        meta.hit0      = (meta.rv_r0 == meta.key24);
        meta.empty0    = (meta.rv_r0 == 32w0);
        meta.c8_r0     = meta.cnt_r0[7:0];
        meta.cnt_eq1_0 = (meta.cnt_r0 == 16w1);
    }
    action do_flags1() {
        meta.hit1      = (meta.rv_r1 == meta.key24);
        meta.empty1    = (meta.rv_r1 == 32w0);
        meta.c8_r1     = meta.cnt_r1[7:0];
        meta.cnt_eq1_1 = (meta.cnt_r1 == 16w1);
    }
    action do_flags2() {
        meta.hit2      = (meta.rv_r2 == meta.key24);
        meta.empty2    = (meta.rv_r2 == 32w0);
        meta.c8_r2     = meta.cnt_r2[7:0];
        meta.cnt_eq1_2 = (meta.cnt_r2 == 16w1);
    }

    
    
    action do_le0() { meta.le_r0 = (meta.cnt_r0 <= meta.hmin); }
    action do_le1() { meta.le_r1 = (meta.cnt_r1 <= meta.hmin); }
    action do_le2() { meta.le_r2 = (meta.cnt_r2 <= meta.hmin); }

    
    action act_thr0(bit<32> t) { meta.thr_r0 = t; }
    action act_thr1(bit<32> t) { meta.thr_r1 = t; }
    action act_thr2(bit<32> t) { meta.thr_r2 = t; }

    
    action do_cmp0() {
        meta.r_sub0 = meta.r_r0 - meta.thr_r0;
    }
    action do_dfl0() {
        meta.decay0 = (meta.r_sub0[31:31] == 1w1);
    }
    action do_cmp1() {
        meta.r_sub1 = meta.r_r1 - meta.thr_r1;
    }
    action do_dfl1() {
        meta.decay1 = (meta.r_sub1[31:31] == 1w1);
    }
    action do_cmp2() {
        meta.r_sub2 = meta.r_r2 - meta.thr_r2;
    }
    action do_dfl2() {
        meta.decay2 = (meta.r_sub2[31:31] == 1w1);
    }

    
    action do_repl0() { ra_repl0.execute(meta.col_r0); }
    action do_repl1() { ra_repl1.execute(meta.col_r1); }
    action do_repl2() { ra_repl2.execute(meta.col_r2); }
    action do_set1_0() { ra_set1_0.execute(meta.col_r0); }
    action do_set1_1() { ra_set1_1.execute(meta.col_r1); }
    action do_set1_2() { ra_set1_2.execute(meta.col_r2); }
    action do_inc0() { ra_inc0.execute(meta.col_r0); }
    action do_inc1() { ra_inc1.execute(meta.col_r1); }
    action do_inc2() { ra_inc2.execute(meta.col_r2); }
    action do_dec0() { ra_dec0.execute(meta.col_r0); }
    action do_dec1() { ra_dec1.execute(meta.col_r1); }
    action do_dec2() { ra_dec2.execute(meta.col_r2); }

    
    table forward_ipv4 {
        key = { ig_intr_md.ingress_port : exact; }
        actions = { set_egr; nop; } default_action = nop(); size = 2;
    }
    table tb_key { actions = { do_key; } default_action = do_key(); size = 1; }
    table heap_keys {
        key = { meta.key24 : exact; }
        actions = { set_in_heap; set_not_in_heap; }
        default_action = set_not_in_heap(); size = 512;
    }
    table tb_hmin { actions = { do_hmin; } default_action = do_hmin(); size = 1; }

    
    table tb_col0 { actions = { do_col0; }  default_action = do_col0();  size = 1; }
    table tb_dech0 { actions = { do_dech0; } default_action = do_dech0(); size = 1; }
    table tb_fp0 { actions = { do_fp0; }   default_action = do_fp0();   size = 1; }
    table tb_cpeek0 { actions = { do_cpeek0; } default_action = do_cpeek0(); size = 1; }
    table tb_flags0 { actions = { do_flags0; } default_action = do_flags0(); size = 1; }
    table tb_le0 { actions = { do_le0; } default_action = do_le0(); size = 1; }
    table thr_tbl0 {
        key = { meta.c8_r0 : exact; }
        actions = { act_thr0; nop; } default_action = nop(); size = 256;
    }
    table tb_cmp0 { actions = { do_cmp0; }  default_action = do_cmp0();  size = 1; }
    table tb_dfl0 { actions = { do_dfl0; }  default_action = do_dfl0();  size = 1; }
    table tb_repl0 { actions = { do_repl0; } default_action = do_repl0(); size = 1; }
    table tb_set1_0 { actions = { do_set1_0; } default_action = do_set1_0(); size = 1; }
    table tb_inc0 { actions = { do_inc0; }  default_action = do_inc0();  size = 1; }
    table tb_dec0 { actions = { do_dec0; }  default_action = do_dec0();  size = 1; }

    
    table tb_col1 { actions = { do_col1; }  default_action = do_col1();  size = 1; }
    table tb_dech1 { actions = { do_dech1; } default_action = do_dech1(); size = 1; }
    table tb_fp1 { actions = { do_fp1; }   default_action = do_fp1();   size = 1; }
    table tb_cpeek1 { actions = { do_cpeek1; } default_action = do_cpeek1(); size = 1; }
    table tb_flags1 { actions = { do_flags1; } default_action = do_flags1(); size = 1; }
    table tb_le1 { actions = { do_le1; } default_action = do_le1(); size = 1; }
    table thr_tbl1 {
        key = { meta.c8_r1 : exact; }
        actions = { act_thr1; nop; } default_action = nop(); size = 256;
    }
    table tb_cmp1 { actions = { do_cmp1; }  default_action = do_cmp1();  size = 1; }
    table tb_dfl1 { actions = { do_dfl1; }  default_action = do_dfl1();  size = 1; }
    table tb_repl1 { actions = { do_repl1; } default_action = do_repl1(); size = 1; }
    table tb_set1_1 { actions = { do_set1_1; } default_action = do_set1_1(); size = 1; }
    table tb_inc1 { actions = { do_inc1; }  default_action = do_inc1();  size = 1; }
    table tb_dec1 { actions = { do_dec1; }  default_action = do_dec1();  size = 1; }

    
    table tb_col2 { actions = { do_col2; }  default_action = do_col2();  size = 1; }
    table tb_dech2 { actions = { do_dech2; } default_action = do_dech2(); size = 1; }
    table tb_fp2 { actions = { do_fp2; }   default_action = do_fp2();   size = 1; }
    table tb_cpeek2 { actions = { do_cpeek2; } default_action = do_cpeek2(); size = 1; }
    table tb_flags2 { actions = { do_flags2; } default_action = do_flags2(); size = 1; }
    table tb_le2 { actions = { do_le2; } default_action = do_le2(); size = 1; }
    table thr_tbl2 {
        key = { meta.c8_r2 : exact; }
        actions = { act_thr2; nop; } default_action = nop(); size = 256;
    }
    table tb_cmp2 { actions = { do_cmp2; }  default_action = do_cmp2();  size = 1; }
    table tb_dfl2 { actions = { do_dfl2; }  default_action = do_dfl2();  size = 1; }
    table tb_repl2 { actions = { do_repl2; } default_action = do_repl2(); size = 1; }
    table tb_set1_2 { actions = { do_set1_2; } default_action = do_set1_2(); size = 1; }
    table tb_inc2 { actions = { do_inc2; }  default_action = do_inc2();  size = 1; }
    table tb_dec2 { actions = { do_dec2; }  default_action = do_dec2();  size = 1; }

    
    apply {
        forward_ipv4.apply();
        if (hdr.ipv4.isValid()) {
            
            tb_key.apply();
            heap_keys.apply();
            tb_hmin.apply();

            
            tb_col0.apply(); tb_dech0.apply();
            tb_fp0.apply(); tb_cpeek0.apply();
            tb_flags0.apply(); tb_le0.apply();
            thr_tbl0.apply(); tb_cmp0.apply(); tb_dfl0.apply();
            
            if (meta.empty0) { tb_set1_0.apply(); }
            
            if (meta.hit0) {
                if (meta.in_heap == 1w1 || meta.le_r0) { tb_inc0.apply(); }
            }
            
            if (meta.decay0) {
                if (!meta.hit0) {
                    tb_dec0.apply();
                    if (meta.cnt_eq1_0) { tb_repl0.apply(); }
                }
            }

            
            tb_col1.apply(); tb_dech1.apply();
            tb_fp1.apply(); tb_cpeek1.apply();
            tb_flags1.apply(); tb_le1.apply();
            thr_tbl1.apply(); tb_cmp1.apply(); tb_dfl1.apply();
            if (meta.empty1) { tb_set1_1.apply(); }
            if (meta.hit1) {
                if (meta.in_heap == 1w1 || meta.le_r1) { tb_inc1.apply(); }
            }
            if (meta.decay1) {
                if (!meta.hit1) {
                    tb_dec1.apply();
                    if (meta.cnt_eq1_1) { tb_repl1.apply(); }
                }
            }

            
            tb_col2.apply(); tb_dech2.apply();
            tb_fp2.apply(); tb_cpeek2.apply();
            tb_flags2.apply(); tb_le2.apply();
            thr_tbl2.apply(); tb_cmp2.apply(); tb_dfl2.apply();
            if (meta.empty2) { tb_set1_2.apply(); }
            if (meta.hit2) {
                if (meta.in_heap == 1w1 || meta.le_r2) { tb_inc2.apply(); }
            }
            if (meta.decay2) {
                if (!meta.hit2) {
                    tb_dec2.apply();
                    if (meta.cnt_eq1_2) { tb_repl2.apply(); }
                }
            }
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
