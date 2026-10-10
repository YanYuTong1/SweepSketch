






















































#include <t2na.p4>
#include "headers.p4"
#include "parser.p4"





#define COUPER_B   16       
#define COUPER_T   12       
#define COUPER_C   32       
#define L1_CELLS   131072   
#define L2_GROUPS  4096     
#define TSC_LEN    4096     


control Ingress(
    inout headers_t                                 hdr,
    inout cp_meta_t                                 meta,
    in    ingress_intrinsic_metadata_t              ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md)
{
    
    
    
    Register<bit<16>, bit<16>>(L1_CELLS / 2, 16w0) bm_lo;                     
    Register<bit<16>, bit<16>>(L1_CELLS / 2, 16w0) bm_hi;                     
    Register<bit<8>,  bit<16>>(L2_GROUPS * COUPER_C / 2, 8w0) hllreg_lo;      
    Register<bit<8>,  bit<16>>(L2_GROUPS * COUPER_C / 2, 8w0) hllreg_hi;      
    Register<bit<16>, bit<12>>(L2_GROUPS, 16w0) digest;            
    Register<bit<32>, bit<12>>(TSC_LEN, 32w0) tsc_f;               
    Register<bit<16>, bit<12>>(TSC_LEN, 16w0) tsc_d;               

    
    
    Hash<bit<32>>(HashAlgorithm_t.CRC32) h_c1;   
    Hash<bit<32>>(HashAlgorithm_t.CRC32) h_c2;   
    Hash<bit<32>>(HashAlgorithm_t.CRC32) h_q;    
    Hash<bit<32>>(HashAlgorithm_t.CRC32) h_r;    
    Hash<bit<32>>(HashAlgorithm_t.CRC32) h_g1;   
    Hash<bit<32>>(HashAlgorithm_t.CRC32) h_g2;   
    Hash<bit<32>>(HashAlgorithm_t.CRC32) h_i;    
    Hash<bit<32>>(HashAlgorithm_t.CRC32) h_j;    

    
    
    
    
    
    
    RegisterAction<bit<16>, bit<16>, void>(bm_lo) ra_bw1_lo = {
        void apply(inout bit<16> value) { value = value | meta.qmask; }
    };
    RegisterAction<bit<16>, bit<16>, void>(bm_hi) ra_bw1_hi = {
        void apply(inout bit<16> value) { value = value | meta.qmask; }
    };
    RegisterAction<bit<16>, bit<16>, void>(bm_lo) ra_bw2_lo = {
        void apply(inout bit<16> value) { value = value | meta.qmask; }
    };
    RegisterAction<bit<16>, bit<16>, void>(bm_hi) ra_bw2_hi = {
        void apply(inout bit<16> value) { value = value | meta.qmask; }
    };
    
    RegisterAction<bit<8>, bit<16>, bit<8>>(hllreg_lo) ra_hll1_lo = {
        void apply(inout bit<8> value, out bit<8> rv) {
            rv = value;
            if (meta.rho > value) { value = meta.rho; }
        }
    };
    RegisterAction<bit<8>, bit<16>, bit<8>>(hllreg_hi) ra_hll1_hi = {
        void apply(inout bit<8> value, out bit<8> rv) {
            rv = value;
            if (meta.rho > value) { value = meta.rho; }
        }
    };
    RegisterAction<bit<8>, bit<16>, bit<8>>(hllreg_lo) ra_hll2_lo = {
        void apply(inout bit<8> value, out bit<8> rv) {
            rv = value;
            if (meta.rho > value) { value = meta.rho; }
        }
    };
    RegisterAction<bit<8>, bit<16>, bit<8>>(hllreg_hi) ra_hll2_hi = {
        void apply(inout bit<8> value, out bit<8> rv) {
            rv = value;
            if (meta.rho > value) { value = meta.rho; }
        }
    };
    
    
    RegisterAction<bit<16>, bit<12>, void>(digest) ra_dg1w = {
        void apply(inout bit<16> value) {
            if (meta.upd_g == 1) { value = value + meta.delta_g; }
        }
    };
    RegisterAction<bit<16>, bit<12>, void>(digest) ra_dg2w = {
        void apply(inout bit<16> value) {
            if (meta.upd2_g == 1) { value = value + meta.delta2_g; }
        }
    };
    
    RegisterAction<bit<16>, bit<12>, bit<16>>(digest) ra_dg1r = {
        void apply(inout bit<16> value, out bit<16> rv) { rv = value; }
    };
    RegisterAction<bit<16>, bit<12>, bit<16>>(digest) ra_dg2r = {
        void apply(inout bit<16> value, out bit<16> rv) { rv = value; }
    };
    
    RegisterAction<bit<32>, bit<12>, void>(tsc_f) ra_tscf = {
        void apply(inout bit<32> value) { value = meta.f; }
    };
    RegisterAction<bit<16>, bit<12>, void>(tsc_d) ra_tscd = {
        void apply(inout bit<16> value) { value = meta.lam; }
    };

    
    action nop() {}
    action set_egr(bit<9> egr_port) { ig_tm_md.ucast_egress_port = egr_port; }

    
    action do_key() { meta.f = hdr.ipv4.srcAddr; meta.e = hdr.ipv4.dstAddr; }

    
    
    
    
    
    action do_hc1() {
        meta.c1 = (bit<17>)(h_c1.get({16w0x7100, meta.f}) & 32w0x1FFFF);
    }
    action do_hc2() {
        meta.c2 = (bit<17>)(h_c2.get({16w0x7101, meta.f}) & 32w0x1FFFF);
    }
    
    action do_sc() {
        meta.c1_16  = meta.c1[15:0];
        meta.sel_c1 = meta.c1[16:16];
        meta.c2_16  = meta.c2[15:0];
        meta.sel_c2 = meta.c2[16:16];
    }
    
    
    action do_hq()  { meta.q  = (bit<4>)(h_q.get({16w0x7200, meta.f, meta.e}) & 32w15); }
    action do_hr()  { meta.h32 = h_r.get({16w0x7300, meta.f, meta.e}); }
    action do_hg1() { meta.g1 = (bit<12>)(h_g1.get({16w0x7400, meta.f}) & 32w0x0FFF); }
    action do_hg2() { meta.g2 = (bit<12>)(h_g2.get({16w0x7401, meta.f}) & 32w0x0FFF); }
    action do_hi()  { meta.idx_i = (bit<12>)(h_i.get({16w0x7500, meta.f}) & 32w0x0FFF); }
    action do_hj()  { meta.idx_j = (bit<12>)(h_j.get({16w0x7501, meta.f}) & 32w0x0FFF); }

    
    
    
    
    
    action do_rsplit() {
        meta.reg = (bit<6>)(meta.h32 & 32w31);
    }

    
    
    action do_idx1() {
        meta.hidx1  = meta.g1[10:0] ++ meta.reg[4:0];
        meta.sel_g1 = meta.g1[11:11];   
    }
    action do_idx2() {
        meta.hidx2  = meta.g2[10:0] ++ meta.reg[4:0];
        meta.sel_g2 = meta.g2[11:11];
    }

    
    action do_rb1_lo() { meta.bm1 = bm_lo.read(meta.c1_16); }   
    action do_rb1_hi() { meta.bm1 = bm_hi.read(meta.c1_16); }
    action do_rb2_lo() { meta.bm2 = bm_lo.read(meta.c2_16); }
    action do_rb2_hi() { meta.bm2 = bm_hi.read(meta.c2_16); }
    action do_merge() {
        meta.merged = meta.bm1 | meta.bm2;
        meta.m_hi   = meta.merged[15:8];
        meta.m_lo   = meta.merged[7:0];
    }
    action act_pc_hi(bit<4> pc_v) { meta.pc_hi_v = (bit<5>)pc_v; }
    action act_pc_lo(bit<4> pc_v) { meta.pc_lo_v = (bit<5>)pc_v; }
    
    
    
    action act_pcgate(bit<1> v) { meta.l1_path = v; }

    
    action act_qmask(bit<16> m) { meta.qmask = m; }
    action do_bw1_lo() { ra_bw1_lo.execute(meta.c1_16); }
    action do_bw1_hi() { ra_bw1_hi.execute(meta.c1_16); }
    action do_bw2_lo() { ra_bw2_lo.execute(meta.c2_16); }
    action do_bw2_hi() { ra_bw2_hi.execute(meta.c2_16); }

    
    action do_hll1_lo() { meta.rho_old_g1 = ra_hll1_lo.execute(meta.hidx1); }
    action do_hll1_hi() { meta.rho_old_g1 = ra_hll1_hi.execute(meta.hidx1); }
    action do_hll2_lo() { meta.rho_old_g2 = ra_hll2_lo.execute(meta.hidx2); }
    action do_hll2_hi() { meta.rho_old_g2 = ra_hll2_hi.execute(meta.hidx2); }
    
    
    
    
    
    
    action do_upd1_1() {
        meta.upd_g   = 1w1;
        meta.delta_g = (bit<16>)(meta.rho - meta.rho_old_g);
    }
    action do_upd1_0() { meta.upd_g = 1w0; meta.delta_g = 16w0; }
    action do_upd2_1() {
        meta.upd2_g   = 1w1;
        meta.delta2_g = (bit<16>)(meta.rho - meta.rho_old_g);
    }
    action do_upd2_0() { meta.upd2_g = 1w0; meta.delta2_g = 16w0; }
    action do_dg1w() { ra_dg1w.execute(meta.g1); }
    action do_dg1r() { meta.lam1 = ra_dg1r.execute(meta.g1); }
    action do_dg2w() { ra_dg2w.execute(meta.g2); }
    action do_dg2r() { meta.lam2 = ra_dg2r.execute(meta.g2); }
    
    
    action do_lam1() { meta.lam = meta.lam1; }
    action do_lam2() { meta.lam = meta.lam2; }

    
    action do_fi() { meta.fi = tsc_f.read(meta.idx_i); }
    action do_fj() { meta.fj = tsc_f.read(meta.idx_j); }
    action do_di() { meta.di = tsc_d.read(meta.idx_i); }
    action do_dj() { meta.dj = tsc_d.read(meta.idx_j); }
    
    
    
    
    action do_tscdec_a() {   
        meta.need_dig = 1w0; meta.tsc_wr = 1w1; meta.tsc_slot = meta.idx_i;
    }
    action do_tscdec_b() {   
        meta.need_dig = 1w0; meta.tsc_wr = 1w1; meta.tsc_slot = meta.idx_j;
    }
    action do_tscdec_c() {   
        
        meta.need_dig = 1w1; meta.tsc_wr = 1w0; meta.tsc_slot = meta.idx_j;
    }
    
    
    
    
    action a_dec2_i_w0() { meta.choose_i = 1w1; meta.dig_k = meta.di; meta.tsc_slot = meta.idx_i; meta.tsc_wr = 1w0; }
    action a_dec2_i_w1() { meta.choose_i = 1w1; meta.dig_k = meta.di; meta.tsc_slot = meta.idx_i; meta.tsc_wr = 1w1; }
    action a_dec2_j_w0() { meta.choose_i = 1w0; meta.dig_k = meta.dj; meta.tsc_slot = meta.idx_j; meta.tsc_wr = 1w0; }
    action a_dec2_j_w1() { meta.choose_i = 1w0; meta.dig_k = meta.dj; meta.tsc_slot = meta.idx_j; meta.tsc_wr = 1w1; }
    action do_fw() { ra_tscf.execute(meta.tsc_slot); }
    action do_dw() { ra_tscd.execute(meta.tsc_slot); }

    
table forward_ipv4 {
        key = { ig_intr_md.ingress_port : exact; }
        actions = { set_egr; nop; } default_action = nop(); size = 2;
    }
    
    table tb_key { actions = { do_key; } default_action = do_key(); size = 1; }
    table tb_hc1 { actions = { do_hc1; } default_action = do_hc1(); size = 1; }
    table tb_sc { actions = { do_sc; } default_action = do_sc(); size = 1; }
    table tb_hc2 { actions = { do_hc2; } default_action = do_hc2(); size = 1; }
    table tb_hq { actions = { do_hq; }  default_action = do_hq();  size = 1; }
    table tb_hr { actions = { do_hr; }  default_action = do_hr();  size = 1; }
    table tb_hg1 { actions = { do_hg1; } default_action = do_hg1(); size = 1; }
    table tb_hg2 { actions = { do_hg2; } default_action = do_hg2(); size = 1; }
    table tb_hi { actions = { do_hi; }  default_action = do_hi();  size = 1; }
    table tb_hj { actions = { do_hj; }  default_action = do_hj();  size = 1; }

table tb_rsplit { actions = { do_rsplit; } default_action = do_rsplit(); size = 1; }
table tb_idx1   { actions = { do_idx1; }   default_action = do_idx1();   size = 1; }
table tb_idx2   { actions = { do_idx2; }   default_action = do_idx2();   size = 1; }

    

    
table tb_rb1 { key = { meta.sel_c1 : exact; } actions = { do_rb1_lo; do_rb1_hi; } default_action = nop(); size = 2; }
table tb_rb2 { key = { meta.sel_c2 : exact; } actions = { do_rb2_lo; do_rb2_hi; } default_action = nop(); size = 2; }
table tb_merge { actions = { do_merge; } default_action = do_merge(); size = 1; }
    


    
table pc_hi {
        key = { meta.m_hi : exact; }
        actions = { act_pc_hi; } default_action = act_pc_hi(4w0); size = 256;
    }
table pc_lo {
        key = { meta.m_lo : exact; }
        actions = { act_pc_lo; } default_action = act_pc_lo(4w0); size = 256;
    }
    
table tb_pcgate { key = { meta.pc_hi_v : exact; meta.pc_lo_v : exact; }
                  actions = { act_pcgate; } default_action = act_pcgate(1w0); size = 289; }

    
    
table q_mask {
        key = { meta.l1_path : exact; meta.q : exact; }
        actions = { act_qmask; nop; } default_action = nop(); size = 32;
    }

    
table tb_bw1 { key = { meta.l1_path : exact; meta.sel_c1 : exact; } actions = { do_bw1_lo; do_bw1_hi; } default_action = nop(); size = 4; }
table tb_bw2 { key = { meta.l1_path : exact; meta.sel_c2 : exact; } actions = { do_bw2_lo; do_bw2_hi; } default_action = nop(); size = 4; }

    
table tb_hll1 { key = { meta.l1_path : exact; meta.sel_g1 : exact; } actions = { do_hll1_lo; do_hll1_hi; } default_action = nop(); size = 4; }
table tb_hll2 { key = { meta.l1_path : exact; meta.sel_g2 : exact; } actions = { do_hll2_lo; do_hll2_hi; } default_action = nop(); size = 4; }
    
    
    
    action do_updcmp() {
        meta.upd1_ok = (meta.rho > meta.rho_old_g1);
        meta.upd2_ok = (meta.rho > meta.rho_old_g2);
    }
    action do_fi_z() { meta.fi_zero = (meta.fi == 32w0); }
    action do_fi_s() { meta.fi_self = (meta.fi == meta.f); }
    
    action do_fi_ok() { meta.fi_ok = (bit<1>)meta.fi_zero | (bit<1>)meta.fi_self; }
    action do_fj_z() { meta.fj_zero = (meta.fj == 32w0); }
    action do_fj_s() { meta.fj_self = (meta.fj == meta.f); }
    action do_fj_ok() { meta.fj_ok = (bit<1>)meta.fj_zero | (bit<1>)meta.fj_self; }
    
    action do_dcmp() {
        meta.di_le  = (meta.di <= meta.dj);
        meta.di_lam = (meta.di <= meta.lam);
        meta.dj_lam = (meta.dj <= meta.lam);
    }
    action do_lam_cmp() { meta.lam1_le = (bit<1>)(meta.lam1 <= meta.lam2); }
    
table tb_updcmp { actions = { do_updcmp; } default_action = do_updcmp(); size = 1; }
table tb_fi_z { actions = { do_fi_z; } default_action = do_fi_z(); size = 1; }
table tb_fi_s { actions = { do_fi_s; } default_action = do_fi_s(); size = 1; }
table tb_fi_ok { actions = { do_fi_ok; } default_action = do_fi_ok(); size = 1; }
table tb_fj_z { actions = { do_fj_z; } default_action = do_fj_z(); size = 1; }
table tb_fj_s { actions = { do_fj_s; } default_action = do_fj_s(); size = 1; }
table tb_fj_ok { actions = { do_fj_ok; } default_action = do_fj_ok(); size = 1; }
table tb_dcmp { actions = { do_dcmp; } default_action = do_dcmp(); size = 1; }
table tb_lamcmp { actions = { do_lam_cmp; } default_action = do_lam_cmp(); size = 1; }
    
table tb_upd1 { key = { meta.l1_path : exact; meta.upd1_ok : exact; } actions = { do_upd1_0; do_upd1_1; } default_action = nop(); size = 4; }
table tb_upd2 { key = { meta.l1_path : exact; meta.upd2_ok : exact; } actions = { do_upd2_0; do_upd2_1; } default_action = nop(); size = 4; }
table tb_dg1w { key = { meta.l1_path : exact; } actions = { do_dg1w; } default_action = nop(); size = 2; }
table tb_dg1r { actions = { do_dg1r; } default_action = do_dg1r(); size = 1; }
table tb_dg2w { key = { meta.l1_path : exact; } actions = { do_dg2w; } default_action = nop(); size = 2; }
table tb_dg2r { actions = { do_dg2r; } default_action = do_dg2r(); size = 1; }
    
table tb_lam { key = { meta.lam1_le : exact; } actions = { do_lam1; do_lam2; } default_action = nop(); size = 2; }

table tb_fi     { actions = { do_fi; }     default_action = do_fi();     size = 1; }
table tb_fj     { actions = { do_fj; }     default_action = do_fj();     size = 1; }
    
    
table tb_tscdec { key = { meta.fi_ok : exact; meta.fj_ok : exact; } actions = { do_tscdec_a; do_tscdec_b; do_tscdec_c; } default_action = nop(); size = 4; }
table tb_di     { actions = { do_di; }     default_action = do_di();     size = 1; }
table tb_dj     { actions = { do_dj; }     default_action = do_dj();     size = 1; }
    
    
table tb_dec2 { key = { meta.need_dig : exact; meta.di_le : exact; meta.di_lam : exact; meta.dj_lam : exact; }
                actions = { a_dec2_i_w0; a_dec2_i_w1; a_dec2_j_w0; a_dec2_j_w1; } default_action = nop(); size = 16; }
    
table tb_fw { key = { meta.l1_path : exact; meta.tsc_wr : exact; } actions = { do_fw; } default_action = nop(); size = 4; }
table tb_dw { key = { meta.l1_path : exact; meta.tsc_wr : exact; } actions = { do_dw; } default_action = nop(); size = 4; }

    
    
    
    apply {
        forward_ipv4.apply();
        if (hdr.ipv4.isValid()) {
            
            tb_key.apply();
            tb_hc1.apply(); tb_hc2.apply(); tb_hr.apply();
            tb_sc.apply();
            tb_hq.apply(); tb_rsplit.apply();
            tb_hg1.apply(); tb_hg2.apply(); tb_idx1.apply(); tb_idx2.apply();
            tb_hi.apply(); tb_hj.apply();
            
            tb_rb1.apply(); tb_rb2.apply();
            tb_merge.apply();
            pc_hi.apply(); pc_lo.apply();
            tb_pcgate.apply();
            
            q_mask.apply();
            tb_bw1.apply(); tb_bw2.apply();
            
            tb_hll1.apply(); tb_hll2.apply();
            tb_updcmp.apply();
            tb_upd1.apply(); tb_upd2.apply();
            tb_dg1w.apply(); tb_dg2w.apply();
            tb_dg1r.apply(); tb_dg2r.apply();
            tb_lamcmp.apply(); tb_lam.apply();
            tb_fi.apply(); tb_fj.apply();
            tb_fi_z.apply(); tb_fi_s.apply(); tb_fi_ok.apply();
            tb_fj_z.apply(); tb_fj_s.apply(); tb_fj_ok.apply();
            tb_di.apply(); tb_dj.apply();
            tb_tscdec.apply();
            tb_dcmp.apply();
            tb_dec2.apply();
            tb_fw.apply(); tb_dw.apply();
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
