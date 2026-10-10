





















#include <t2na.p4>
#include "headers.p4"
#include "parser.p4"


#define L1_N     8192        
#define L2_N     4096        
#define K_ALARM  8
#define K_ALARM_QUIET 12
#define N_EWMA_QUIET 4
#define K_FLOOD  6
#define D2_MULT  3
#define P_MIN    200
#define H_FP     74
#define LLR_NEW  38
#define LLR_REP  26
#define HLL_M    32


control Ingress(
    inout headers_t                                hdr,
    inout sweep_meta_t                            meta,
    in    ingress_intrinsic_metadata_t             ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t      ig_tm_md)
{
    
    Register<bit<32>, bit<13>>(L1_N, 32w0) l1_key;
    Register<bit<8>,  bit<13>>(L1_N, 8w0)  l1_ep;
    Register<bit<8>,  bit<13>>(L1_N, 8w0)  l1_nn;
    Register<bit<8>,  bit<13>>(L1_N, 8w0)  l1_ne;   
    Register<bit<16>, bit<13>>(L1_N, 16w0) l1_C;
    Register<bit<8>,  bit<13>>(L1_N, 8w0)  l1_pkt;   
    Register<bit<8>,  bit<18>>(L1_N * HLL_M, 8w0) l1_hll;

    Register<bit<32>, bit<12>>(L2_N, 32w0) l2_key;
    Register<bit<8>,  bit<12>>(L2_N, 8w0)  l2_ep;
    Register<bit<8>,  bit<12>>(L2_N, 8w0)  l2_nn;
    Register<bit<16>, bit<12>>(L2_N, 16w0) l2_C;
    Register<bit<8>,  bit<12>>(L2_N, 8w0)  l2_pkt;   
    Register<bit<8>,  bit<17>>(L2_N * HLL_M, 8w0) l2_hll;

    
    Hash<bit<16>>(HashAlgorithm_t.CRC32) h_idx1;   
    Hash<bit<16>>(HashAlgorithm_t.CRC32) h_idx2;   
    Hash<bit<32>>(HashAlgorithm_t.CRC32) h_r;      

    
    action act_clz(bit<5> rho_v, bit<1> done_v) {
        meta.rho = rho_v; meta.rho_done = done_v;
    }
    action act_clz_none() {}
    action act_clz_last() { meta.rho = 27; meta.rho_done = 1; }   

    @stage(2) table clz0 { key = { meta.r_hi : exact; } actions = { act_clz; act_clz_none; }
                 default_action = act_clz_none(); size = 256; }
    @stage(3) table clz1 { key = { meta.r_mid : exact; } actions = { act_clz; act_clz_none; }
                 default_action = act_clz_none(); size = 256; }
    @stage(4) table clz2 { key = { meta.r_lo : exact; } actions = { act_clz; act_clz_none; }
                 default_action = act_clz_none(); size = 256; }
    @stage(5) table clz3 { key = { meta.r_tail : exact; } actions = { act_clz; act_clz_last; }
                 default_action = act_clz_last(); size = 8; }

    
    
    
    
    
    action act_delta(bit<16> d)  { meta.delta_total = d; }
    action act_dnegC()           { meta.delta_total = 16w0 - meta.C_old; }
    action act_dD(bit<16> dc)    { meta.delta_total = dc - meta.C_old; }
    @stage(10) table t1_delta {
        key = { meta.event : exact; meta.claim : exact; meta.rollover : exact; }
        actions = { act_delta; act_dnegC; act_dD; }
        default_action = act_delta(16w0);
        size = 8;
    }

    
    
    RegisterAction<bit<32>, bit<13>, bit<32>>(l1_key) ra1_kr = {
        void apply(inout bit<32> value, out bit<32> rv) { rv = value; }  
    };
    RegisterAction<bit<32>, bit<13>, void>(l1_key) ra1_kw = {
        void apply(inout bit<32> value) { value = meta.pkt_key; }   
    };
    
    RegisterAction<bit<8>, bit<13>, bit<8>>(l1_ep) ra1_ep = {
        void apply(inout bit<8> value, out bit<8> rv) { rv = value; }  
    };
    RegisterAction<bit<8>, bit<13>, void>(l1_ep) ra1_epw = {
        void apply(inout bit<8> value) { value = meta.ep_new; }
    };
    
    RegisterAction<bit<8>, bit<13>, bit<8>>(l1_nn) ra1_nr = {
        void apply(inout bit<8> value, out bit<8> rv) { rv = value; }  
    };
    RegisterAction<bit<8>, bit<13>, void>(l1_nn) ra1_nclr = {
        void apply(inout bit<8> value) { value = 8w0; }
    };
    RegisterAction<bit<8>, bit<13>, void>(l1_nn) ra1_nadd = {
        void apply(inout bit<8> value) { value = value + (bit<8>)meta.event; }
    };
    RegisterAction<bit<8>, bit<13>, bit<8>>(l1_ne) ra1_ner = {
        void apply(inout bit<8> value, out bit<8> rv) { rv = value; }  
    };
    
    
    RegisterAction<bit<16>, bit<13>, void>(l1_C) ra1_Cadd = {
        void apply(inout bit<16> value) { value = value + meta.delta_total; }
    };
    
    RegisterAction<bit<8>, bit<13>, void>(l1_pkt) ra1_pclr = {
        void apply(inout bit<8> value) { value = 8w0; }
    };
    RegisterAction<bit<8>, bit<13>, void>(l1_pkt) ra1_padd = {
        void apply(inout bit<8> value) { value = value + 1; }
    };
    
    
    RegisterAction<bit<8>, bit<18>, bit<8>>(l1_hll) ra1_hlr = {
        void apply(inout bit<8> value, out bit<8> rv) { rv = value; }  
    };
    RegisterAction<bit<8>, bit<18>, void>(l1_hll) ra1_hwt = {
        void apply(inout bit<8> value) { value = meta.hll_new; }
    };

    
    action nop() {}
    action set_egr(bit<9> port) { ig_tm_md.ucast_egress_port = port; }

    action do_h1()  { meta.idx1 = (bit<13>)(h_idx1.get({8w1, hdr.ipv4.dstAddr}) & 16w0x1FFF); }
    action do_h2()  { meta.idx2 = (bit<12>)(h_idx2.get({8w2, hdr.ipv4.dstAddr}) & 16w0x0FFF); }
    action do_hr()  { meta.hr = h_r.get({8w3, hdr.ipv4.dstAddr}); }
    action do_sr()  {
        meta.r      = meta.hr[4:0];
        meta.r_hi   = meta.hr[31:24];
        meta.r_mid  = meta.hr[23:16];
        meta.r_lo   = meta.hr[15:8];
        meta.r_tail = meta.hr[7:5];
    }
    action do_gk() {
        
        
        meta.pkt_key      = hdr.ipv4.dstAddr & 32w0xFFFFFF00;
        meta.global_epoch = ig_prsr_md.global_tstamp[36:32];
    }
    action do_gk2() {
        meta.pkt_key2     = hdr.ipv4.dstAddr & 32w0xFFFF0000;
    }
    
    action do1_rk() {
        bit<32> rv = ra1_kr.execute((bit<13>)meta.idx1);
        meta.key_ok  = (rv == meta.pkt_key);
        meta.key_nz  = (rv != 32w0);
    }
    action do1_rC() {
        bit<16> rv = l1_C.read((bit<13>)meta.idx1);   
        meta.C_old = rv;
        meta.C_lt  = (rv < (bit<16>)H_FP);
    }
    action do1_rp() {
        bit<8> rv = l1_pkt.read((bit<13>)meta.idx1);   
        meta.pkt_old    = rv;
        meta.pkt_ge_min = (rv >= (bit<8>)P_MIN);
    }
    
    action a1_cd1() { meta.cold = 1w1; }
    action a1_cl1() { meta.claim = true; }
    action a1_sk1() { meta.skip = 1w1; }
    action do1_kw()    { ra1_kw.execute((bit<13>)meta.idx1); }
    action do1_ep() {
        meta.ep_old = ra1_ep.execute((bit<13>)meta.idx1);
    }
    action do1_rof() {
        meta.rollover = (meta.ep_old[7:3] != meta.global_epoch);
    }
    
    action act_wn(bit<8> v)  { meta.win_new = v; }
    action act_e1(bit<8> v)  { meta.e1 = v; }
    action act_w5(bit<8> v)  { meta.w5 = v; }
    action act_e12(bit<8> v) { meta.e1_2 = v; }   
    action act_w52(bit<8> v) { meta.w5_2 = v; }   
    action do1_epnew()  { meta.ep_new = meta.e1 | meta.win_new; }
    action do1_epw()    { ra1_epw.execute((bit<13>)meta.idx1); }
    action do1_hlr() {
        meta.hll_rv = ra1_hlr.execute(meta.idx1 ++ meta.r);
    }
    action do1_hlrf() {
        meta.tag_ne = (meta.hll_rv[7:5] != (bit<3>)meta.win_new);
        meta.rho_gt = (meta.hll_rv[4:0] < meta.rho);
    }
    
    action a1_ev1() { meta.event = 1w1; }
    action a1_ev0() { meta.event = 1w0; }
    action do1_hllnew() { meta.hll_new = meta.w5 | (bit<8>)meta.rho; }
    action do1_hwt() { ra1_hwt.execute(meta.idx1 ++ meta.r); }
    action do1_rn() {
        bit<8> rv = ra1_nr.execute((bit<13>)meta.idx1);
        meta.nn_old = rv;
        meta.nn_ge  = (rv >= (bit<8>)K_FLOOD);   
    }
    
    action do1_re()  { meta.ne_old = ra1_ner.execute((bit<13>)meta.idx1); }
    action do1_ne2() { meta.ne2 = meta.ne_old << 1; }   
    action do1_2ne() { meta.nn_ge_2ne = meta.nn_old >= meta.ne2; }   

    

    
    action do1_nclr()  { ra1_nclr.execute((bit<13>)meta.idx1); }
    action do1_pclr()  { ra1_pclr.execute((bit<13>)meta.idx1); }
    action do1_nadd()  { ra1_nadd.execute((bit<13>)meta.idx1); }
    action do1_padd()  { ra1_padd.execute((bit<13>)meta.idx1); }
    action do1_Cadd()  { ra1_Cadd.execute((bit<13>)meta.idx1); }
    
    
    
    
    action a1_ge3() { meta.ge3 = true; }   
    action a1_he1() { meta.held_new = 1w1; }
    action a1_he1b() { }   
    action a1_ev3() { meta.ge3c = true; }   
    action a1_he2() { }                     
    action a2_ge3() { meta.ge3b = true; }  
    action a2_he1() { }                    
    
    action do1_dg() {
        meta.dg_prefix    = meta.pkt_key;
        meta.dg_pkt       = meta.pkt_old;
        meta.dg_n_new     = meta.nn_old;
        meta.dg_event     = meta.event;
        meta.dg_held      = meta.held_new;   
        meta.dg_C         = meta.C_old;
        meta.dg_delta     = meta.delta_total;
        meta.dg_tstamp    = ig_prsr_md.global_tstamp[47:16];
    }

    
    RegisterAction<bit<32>, bit<12>, bit<32>>(l2_key) ra2_kr = {
        void apply(inout bit<32> value, out bit<32> rv) { rv = value; }  
    };
    RegisterAction<bit<32>, bit<12>, void>(l2_key) ra2_kw = {
        void apply(inout bit<32> value) { value = meta.pkt_key2; }   
    };
    RegisterAction<bit<8>, bit<12>, bit<8>>(l2_ep) ra2_ep = {
        void apply(inout bit<8> value, out bit<8> rv) { rv = value; }
    };
    RegisterAction<bit<8>, bit<12>, void>(l2_ep) ra2_epw = {
        void apply(inout bit<8> value) { value = meta.ep_new2; }
    };
    RegisterAction<bit<8>, bit<12>, bit<8>>(l2_nn) ra2_nr = {
        void apply(inout bit<8> value, out bit<8> rv) { rv = value; }  
    };
    RegisterAction<bit<8>, bit<12>, void>(l2_nn) ra2_nclr = {
        void apply(inout bit<8> value) { value = 8w0; }
    };
    RegisterAction<bit<8>, bit<12>, void>(l2_nn) ra2_nadd = {
        void apply(inout bit<8> value) { value = value + (bit<8>)meta.event2; }
    };
    RegisterAction<bit<16>, bit<12>, void>(l2_C) ra2_Cadd = {
        void apply(inout bit<16> value) { value = value + meta.delta2_total; }   
    };
    RegisterAction<bit<8>, bit<12>, void>(l2_pkt) ra2_pclr = {
        void apply(inout bit<8> value) { value = 8w0; }   
    };
    RegisterAction<bit<8>, bit<12>, void>(l2_pkt) ra2_padd = {
        void apply(inout bit<8> value) { value = value + 1; }
    };
    
    RegisterAction<bit<8>, bit<17>, bit<8>>(l2_hll) ra2_hlr = {
        void apply(inout bit<8> value, out bit<8> rv) { rv = value; }  
    };
    RegisterAction<bit<8>, bit<17>, void>(l2_hll) ra2_hwt = {
        void apply(inout bit<8> value) { value = meta.hll_new2; }
    };

    
    action do2_rk() {
        bit<32> rv = ra2_kr.execute((bit<12>)meta.idx2);
        meta.key_ok2  = (rv == meta.pkt_key2);
        meta.key2_nz  = (rv != 32w0);
    }
    action do2_rC() {
        bit<16> rv = l2_C.read((bit<12>)meta.idx2);
        meta.C2_old = rv;
        meta.C2_lt  = (rv < (bit<16>)H_FP);
    }
    action do2_rp() {
        bit<8> rv = l2_pkt.read((bit<12>)meta.idx2);   
        meta.pkt2_old   = rv;                          
        meta.pkt2_ge_min = (rv >= (bit<8>)P_MIN);
    }
    action a2_cd1() { meta.cold2 = 1w1; }
    action a2_cl1() { meta.claim2 = true; }
    action a2_sk1() { meta.skip2 = 1w1; }
    action do2_kw()    { ra2_kw.execute((bit<12>)meta.idx2); }
    action do2_ep() {
        meta.ep2_old = ra2_ep.execute((bit<12>)meta.idx2);
    }
    action do2_rof() {
        meta.rollover2 = (meta.ep2_old[7:3] != meta.global_epoch);
    }
    action act_wn2(bit<8> v) { meta.win2_new = v; }
    action do2_epnew()  { meta.ep_new2 = meta.e1_2 | meta.win2_new; }   
    action do2_epw()    { ra2_epw.execute((bit<12>)meta.idx2); }
    action do2_hlr() {
        meta.hll2_rv = ra2_hlr.execute(meta.idx2 ++ meta.r);
    }
    action do2_hlrf() {
        meta.tag2_ne = (meta.hll2_rv[7:5] != (bit<3>)meta.win2_new);
        meta.rho2_gt = (meta.hll2_rv[4:0] < meta.rho);
    }
    action a2_ev1() { meta.event2 = 1w1; }
    action a2_ev0() { meta.event2 = 1w0; }
    action do2_hllnew() { meta.hll_new2 = meta.w5_2 | (bit<8>)meta.rho; }   
    action do2_hwt() { ra2_hwt.execute(meta.idx2 ++ meta.r); }
    action do2_rn() {
        bit<8> rv = ra2_nr.execute((bit<12>)meta.idx2);
        meta.nn2_old = rv;
    }

    

    action do2_nclr()  { ra2_nclr.execute((bit<12>)meta.idx2); }
    action do2_pclr()  { ra2_pclr.execute((bit<12>)meta.idx2); }
    action do2_nadd()  { ra2_nadd.execute((bit<12>)meta.idx2); }
    action do2_padd()  { ra2_padd.execute((bit<12>)meta.idx2); }
    action do2_Cadd()  { ra2_Cadd.execute((bit<12>)meta.idx2); }
    
    
    action act_delta2(bit<16> d) { meta.delta2_total = d; }
    action act_dnegC2()          { meta.delta2_total = 16w0 - meta.C2_old; }
    action act_dD2(bit<16> dc)   { meta.delta2_total = dc - meta.C2_old; }
    @stage(10) table t2_delta {
        key = { meta.event2 : exact; meta.claim2 : exact; meta.rollover2 : exact; }
        actions = { act_delta2; act_dnegC2; act_dD2; }
        default_action = act_delta2(16w0);
        size = 8;
    }
    
    action do2_dg() {
        meta.dg2_prefix    = meta.pkt_key2;
        meta.dg2_pkt       = meta.pkt2_old;   
        meta.dg2_n_new     = meta.nn2_old;
        meta.dg2_event     = meta.event2;
        meta.dg2_C         = meta.C2_old;
        meta.dg2_delta     = meta.delta_total;
    }

    
    @stage(0) table forward_ipv4 {
        key = { ig_intr_md.ingress_port : exact; }
        actions = { set_egr; nop; } default_action = nop(); size = 2;
    }
    @stage(0) table tb_h1  { actions = { do_h1; }  default_action = do_h1();  size = 1; }
    @stage(0) table tb_h2  { actions = { do_h2; }  default_action = do_h2();  size = 1; }
    @stage(0) table tb_hr  { actions = { do_hr; }  default_action = do_hr();  size = 1; }
    @stage(1) table tb_sr  { actions = { do_sr; }  default_action = do_sr();  size = 1; }
    @stage(0) table tb_gk  { actions = { do_gk; }  default_action = do_gk();  size = 1; }
    @stage(0) table tb_gk2 { actions = { do_gk2; } default_action = do_gk2(); size = 1; }
    
    @stage(1) table tb1_rk { actions = { do1_rk; } default_action = do1_rk(); size = 1; }
    @stage(1) table tb1_rC { actions = { do1_rC; } default_action = do1_rC(); size = 1; }
    @stage(1) table tb1_rp { actions = { do1_rp; } default_action = do1_rp(); size = 1; }
    @stage(2) table t1_cd1 { actions = { a1_cd1; } default_action = a1_cd1(); size = 1; }
    @stage(3) table t1_cl1 { actions = { a1_cl1; } default_action = a1_cl1(); size = 1; }
    @stage(4) table t1_sk1 { actions = { a1_sk1; } default_action = a1_sk1(); size = 1; }
    @stage(5) table tb1_kw { actions = { do1_kw; } default_action = do1_kw(); size = 1; }
    @stage(5) table tb1_ep { actions = { do1_ep; } default_action = do1_ep(); size = 1; }
    @stage(6) table tb1_rof { actions = { do1_rof; } default_action = do1_rof(); size = 1; }
    @stage(7) table tb1_wn1 { key = { meta.ep_old : exact; } actions = { act_wn; } default_action = act_wn(8w0); size = 256; }
    @stage(7) table tb1_wn0 { key = { meta.ep_old : exact; } actions = { act_wn; } default_action = act_wn(8w0); size = 256; }
    @stage(6) table tb1_e1  { key = { meta.global_epoch : exact; } actions = { act_e1; } default_action = act_e1(8w0);  size = 32; }
    @stage(7) table tb1_epnew { actions = { do1_epnew; } default_action = do1_epnew(); size = 1; }
    @stage(8) table tb1_epw  { actions = { do1_epw; }  default_action = do1_epw();  size = 1; }
    @stage(8) table tb1_hlr{ actions = { do1_hlr; } default_action = do1_hlr(); size = 1; }
    @stage(8) table tb1_hlrf{ actions = { do1_hlrf; } default_action = do1_hlrf(); size = 1; }
    @stage(9) table t1_ev1 { actions = { a1_ev1; } default_action = a1_ev1(); size = 1; }
    @stage(9) table t1_ev0 { actions = { a1_ev0; } default_action = a1_ev0(); size = 1; }
    @stage(9) table tb1_w5 { key = { meta.win_new : exact; } actions = { act_w5; } default_action = act_w5(8w0); size = 256; }
    @stage(9) table tb1_hllnew { actions = { do1_hllnew; } default_action = do1_hllnew(); size = 1; }
    @stage(10) table tb1_hwt{ actions = { do1_hwt; } default_action = do1_hwt(); size = 1; }
    @stage(9) table tb1_rn { actions = { do1_rn; } default_action = do1_rn(); size = 1; }
    @stage(9) table tb1_re  { actions = { do1_re; }  default_action = do1_re();  size = 1; }
    @stage(9) table tb1_ne2 { actions = { do1_ne2; } default_action = do1_ne2(); size = 1; }
    @stage(9) table tb1_2ne { actions = { do1_2ne; } default_action = do1_2ne(); size = 1; }
    
    @stage(10) table tb1_nclr { actions = { do1_nclr; } default_action = do1_nclr(); size = 1; }
    @stage(10) table tb1_pclr { actions = { do1_pclr; } default_action = do1_pclr(); size = 1; }
    @stage(11) table tb1_nadd { actions = { do1_nadd; } default_action = do1_nadd(); size = 1; }
    @stage(11) table tb1_padd { actions = { do1_padd; } default_action = do1_padd(); size = 1; }
    @stage(11) table tb1_Cadd { actions = { do1_Cadd; } default_action = do1_Cadd(); size = 1; }
    @stage(9) table tb1_ge3  { actions = { a1_ge3; } default_action = a1_ge3(); size = 1; }
    @stage(10) table t1_he1   { actions = { a1_he1; } default_action = a1_he1(); size = 1; }
    @stage(10) table t1_he1b  { actions = { a1_he1b; } default_action = a1_he1b(); size = 1; }
    @stage(9) table t1_ev3   { actions = { a1_ev3; } default_action = a1_ev3(); size = 1; }
    @stage(10) table t1_he2   { actions = { a1_he2; } default_action = a1_he2(); size = 1; }
    @stage(9) table tb2_ge3  { actions = { a2_ge3; } default_action = a2_ge3(); size = 1; }
    @stage(10) table t2_he1   { actions = { a2_he1; } default_action = a2_he1(); size = 1; }
    @stage(11) table tb1_dg  { actions = { do1_dg; } default_action = do1_dg(); size = 1; }
    
    @stage(1) table tb2_rk { actions = { do2_rk; } default_action = do2_rk(); size = 1; }
    @stage(1) table tb2_rC { actions = { do2_rC; } default_action = do2_rC(); size = 1; }
    @stage(1) table tb2_rp { actions = { do2_rp; } default_action = do2_rp(); size = 1; }
    @stage(2) table t2_cd1 { actions = { a2_cd1; } default_action = a2_cd1(); size = 1; }
    @stage(3) table t2_cl1 { actions = { a2_cl1; } default_action = a2_cl1(); size = 1; }
    @stage(4) table t2_sk1 { actions = { a2_sk1; } default_action = a2_sk1(); size = 1; }
    @stage(5) table tb2_kw { actions = { do2_kw; } default_action = do2_kw(); size = 1; }
    @stage(5) table tb2_ep { actions = { do2_ep; } default_action = do2_ep(); size = 1; }
    @stage(6) table tb2_rof { actions = { do2_rof; } default_action = do2_rof(); size = 1; }
    @stage(7) table tb2_wn1 { key = { meta.ep2_old : exact; } actions = { act_wn2; } default_action = act_wn2(8w0); size = 256; }
    @stage(7) table tb2_wn0 { key = { meta.ep2_old : exact; } actions = { act_wn2; } default_action = act_wn2(8w0); size = 256; }
    @stage(6) table tb2_e1  { key = { meta.global_epoch : exact; } actions = { act_e12; } default_action = act_e12(8w0);  size = 32; }
    @stage(7) table tb2_epnew { actions = { do2_epnew; } default_action = do2_epnew(); size = 1; }
    @stage(8) table tb2_epw  { actions = { do2_epw; }  default_action = do2_epw();  size = 1; }
    @stage(8) table tb2_hlr{ actions = { do2_hlr; } default_action = do2_hlr(); size = 1; }
    @stage(8) table tb2_hlrf{ actions = { do2_hlrf; } default_action = do2_hlrf(); size = 1; }
    @stage(9) table t2_ev1 { actions = { a2_ev1; } default_action = a2_ev1(); size = 1; }
    @stage(9) table t2_ev0 { actions = { a2_ev0; } default_action = a2_ev0(); size = 1; }
    @stage(9) table tb2_w5 { key = { meta.win2_new : exact; } actions = { act_w52; } default_action = act_w52(8w0); size = 256; }
    @stage(9) table tb2_hllnew { actions = { do2_hllnew; } default_action = do2_hllnew(); size = 1; }
    @stage(10) table tb2_hwt{ actions = { do2_hwt; } default_action = do2_hwt(); size = 1; }
    @stage(9) table tb2_rn { actions = { do2_rn; } default_action = do2_rn(); size = 1; }
    
    @stage(10) table tb2_nclr { actions = { do2_nclr; } default_action = do2_nclr(); size = 1; }
    @stage(10) table tb2_pclr { actions = { do2_pclr; } default_action = do2_pclr(); size = 1; }
    @stage(11) table tb2_nadd { actions = { do2_nadd; } default_action = do2_nadd(); size = 1; }
    @stage(11) table tb2_padd { actions = { do2_padd; } default_action = do2_padd(); size = 1; }
    @stage(11) table tb2_Cadd { actions = { do2_Cadd; } default_action = do2_Cadd(); size = 1; }
    @stage(11) table tb2_dg  { actions = { do2_dg; } default_action = do2_dg(); size = 1; }

    apply {
        forward_ipv4.apply();
        if (hdr.ipv4.isValid()) {
            
            
            
            
            
            
            tb_gk.apply(); tb_gk2.apply();
            tb_h1.apply(); tb_h2.apply(); tb_hr.apply();
            
            tb_sr.apply();
            tb1_rk.apply(); tb1_rC.apply(); tb1_rp.apply();
            tb2_rk.apply(); tb2_rC.apply(); tb2_rp.apply();
            
            if (meta.pkt_ge_min) {
                if (meta.C_lt) { t1_cd1.apply(); }
            }
            if (meta.pkt2_ge_min) {
                if (meta.C2_lt) { t2_cd1.apply(); }
            }
            clz0.apply();
            if (meta.rho_done == 0) { clz1.apply(); }
            if (!meta.key_nz) { t1_cl1.apply(); }
            else if (!meta.key_ok) {
                if (meta.cold == 1w1) { t1_cl1.apply(); }
            }
            if (!meta.key2_nz) { t2_cl1.apply(); }
            else if (!meta.key_ok2) {
                if (meta.cold2 == 1w1) { t2_cl1.apply(); }
            }
            if (meta.rho_done == 0) { clz2.apply(); }
            if (!meta.key_ok) {
                if (!meta.claim) { t1_sk1.apply(); }
            }
            if (!meta.key_ok2) {
                if (!meta.claim2) { t2_sk1.apply(); }
            }
            if (meta.rho_done == 0) { clz3.apply(); }
            
            if (meta.claim) { tb1_kw.apply(); }   
            if (meta.claim2) { tb2_kw.apply(); }
            if (meta.skip == 0) { tb1_ep.apply(); }
            if (meta.skip2 == 0) { tb2_ep.apply(); }
            
            if (meta.skip == 0) {
                tb1_rof.apply();
                tb1_e1.apply();
            }
            if (meta.skip2 == 0) {
                tb2_rof.apply();
                tb2_e1.apply();
            }
            
            if (meta.skip == 0) {
                if (meta.rollover || meta.claim) { tb1_wn1.apply(); } else { tb1_wn0.apply(); }
                tb1_epnew.apply();
            }
            if (meta.skip2 == 0) {
                if (meta.rollover2 || meta.claim2) { tb2_wn1.apply(); } else { tb2_wn0.apply(); }
                tb2_epnew.apply();
            }
            
            if (meta.skip == 0) {
                if (meta.rollover || meta.claim) { tb1_epw.apply(); }
                tb1_hlr.apply();
                tb1_hlrf.apply();
            }
            if (meta.skip2 == 0) {
                if (meta.rollover2 || meta.claim2) { tb2_epw.apply(); }
                tb2_hlr.apply();
                tb2_hlrf.apply();
            }
            
            if (meta.skip == 0) {
                if (meta.tag_ne || meta.rho_gt) { t1_ev1.apply(); } else { t1_ev0.apply(); }
                tb1_rn.apply();   
                
                tb1_re.apply();
                tb1_ne2.apply();
                tb1_2ne.apply();
                t1_ev3.apply();
                tb1_ge3.apply();   
                tb1_w5.apply(); tb1_hllnew.apply();
            }
            if (meta.skip2 == 0) {
                if (meta.tag2_ne || meta.rho2_gt) { t2_ev1.apply(); } else { t2_ev0.apply(); }
                tb2_rn.apply();   
                tb2_ge3.apply();  
                tb2_w5.apply(); tb2_hllnew.apply();
            }
            
            if (meta.skip == 0) {
                if (meta.event == 1) { tb1_hwt.apply(); }
                
                if (meta.nn_ge) {
                    if (meta.ge3c) {
                        if (meta.rollover) {
                            if (meta.C_lt) { t1_he2.apply(); }
                        }
                    }
                }
                
                t1_delta.apply();
                if (meta.claim || meta.rollover) { tb1_nclr.apply(); tb1_pclr.apply(); }
                
                
                if (meta.pkt_ge_min) {
                    if (meta.ge3) {
                        if (meta.nn_ge) {
                            if (meta.nn_ge_2ne) { t1_he1.apply(); t1_he1b.apply(); }
                        }
                    }
                }
            }
            if (meta.skip2 == 0) {
                if (meta.event2 == 1) { tb2_hwt.apply(); }
                
                t2_delta.apply();
                if (meta.claim2 || meta.rollover2) { tb2_nclr.apply(); tb2_pclr.apply(); }
                
                if (meta.pkt2_ge_min) {
                    if (meta.ge3b) {
                        if (meta.rollover2) {
                            if (meta.C2_lt) { t2_he1.apply(); }
                        }
                    }
                }
            }
            
            if (meta.skip == 0) {
                tb1_Cadd.apply();
                tb1_nadd.apply(); tb1_padd.apply();
            }
            if (meta.skip2 == 0) {
                tb2_Cadd.apply();
                tb2_nadd.apply(); tb2_padd.apply();
            }
            tb1_dg.apply();   
            tb2_dg.apply();   
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
