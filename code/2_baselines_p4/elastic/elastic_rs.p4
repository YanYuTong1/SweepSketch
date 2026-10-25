
#include <t2na.p4>
#include "headers.p4"
#include "parser.p4"

#define NB        4096
#define LIGHT_N   262144     


#define RS_CLAIM  8w0        
#define RS_SWAP   8w1        
#define RS_LIGHT  8w2        

control Ingress(
    inout headers_t                                hdr,
    inout ig_metadata_t                            meta,
    in    ingress_intrinsic_metadata_t             ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t      ig_tm_md)
{
    
    Register<bit<32>, bit<12>>(NB, 32w0) cellc_0;
    Register<bit<32>, bit<12>>(NB, 32w0) cellc_1;
    Register<bit<32>, bit<12>>(NB, 32w0) cellc_2;
    Register<bit<32>, bit<12>>(NB, 32w0) cellc_3;
    Register<bit<32>, bit<12>>(NB, 32w0) cellc_4;
    Register<bit<32>, bit<12>>(NB, 32w0) cellc_5;
    Register<bit<32>, bit<12>>(NB, 32w0) cellc_6;
    Register<bit<16>, bit<12>>(NB, 16w0) guard;
    Register<bit<8>,  bit<18>>(LIGHT_N, 8w0) light;
    
    

    
    Hash<bit<16>>(HashAlgorithm_t.CRC32) h_bucket;  
    Hash<bit<32>>(HashAlgorithm_t.CRC32) h_light;   

    
    RegisterAction<bit<32>, bit<12>, void>(cellc_0) ra_inc0 = {
        void apply(inout bit<32> value) { value = value + 1; }
    };
    RegisterAction<bit<32>, bit<12>, void>(cellc_1) ra_inc1 = {
        void apply(inout bit<32> value) { value = value + 1; }
    };
    RegisterAction<bit<32>, bit<12>, void>(cellc_2) ra_inc2 = {
        void apply(inout bit<32> value) { value = value + 1; }
    };
    RegisterAction<bit<32>, bit<12>, void>(cellc_3) ra_inc3 = {
        void apply(inout bit<32> value) { value = value + 1; }
    };
    RegisterAction<bit<32>, bit<12>, void>(cellc_4) ra_inc4 = {
        void apply(inout bit<32> value) { value = value + 1; }
    };
    RegisterAction<bit<32>, bit<12>, void>(cellc_5) ra_inc5 = {
        void apply(inout bit<32> value) { value = value + 1; }
    };
    RegisterAction<bit<32>, bit<12>, void>(cellc_6) ra_inc6 = {
        void apply(inout bit<32> value) { value = value + 1; }
    };
    
    RegisterAction<bit<32>, bit<12>, void>(cellc_0) ra_put0 = {
        void apply(inout bit<32> value) { value = meta.newcell; }
    };
    RegisterAction<bit<32>, bit<12>, void>(cellc_1) ra_put1 = {
        void apply(inout bit<32> value) { value = meta.newcell; }
    };
    RegisterAction<bit<32>, bit<12>, void>(cellc_2) ra_put2 = {
        void apply(inout bit<32> value) { value = meta.newcell; }
    };
    RegisterAction<bit<32>, bit<12>, void>(cellc_3) ra_put3 = {
        void apply(inout bit<32> value) { value = meta.newcell; }
    };
    RegisterAction<bit<32>, bit<12>, void>(cellc_4) ra_put4 = {
        void apply(inout bit<32> value) { value = meta.newcell; }
    };
    RegisterAction<bit<32>, bit<12>, void>(cellc_5) ra_put5 = {
        void apply(inout bit<32> value) { value = meta.newcell; }
    };
    RegisterAction<bit<32>, bit<12>, void>(cellc_6) ra_put6 = {
        void apply(inout bit<32> value) { value = meta.newcell; }
    };
    
    RegisterAction<bit<16>, bit<12>, bit<16>>(guard) ra_gpeek = {
        void apply(inout bit<16> value, out bit<16> rv) { rv = value; }
    };
    RegisterAction<bit<16>, bit<12>, void>(guard) ra_gw = {
        void apply(inout bit<16> value) { value = meta.rs_guard_new; }
    };
    
    RegisterAction<bit<8>, bit<18>, void>(light) ra_ladd = {
        void apply(inout bit<8> value) {
            if (value != 8w0xFF) { value = value + 1; }      
        }
    };
    
    
    RegisterAction<bit<8>, bit<18>, bit<8>>(light) ra_lpeek_ev = {
        void apply(inout bit<8> value, out bit<8> rv) { rv = value; }
    };
    
    
    
    
    RegisterAction<bit<8>, bit<18>, void>(light) ra_levaddsat = {
        void apply(inout bit<8> value) {
            if (meta.ovf_ev) { value = 8w0xFF; }
            else { value = value + meta.ev_val8; }
        }
    };
    
    
    
    
    
    
    RegisterAction<bit<8>, bit<18>, void>(light) ra_levmax = {
        void apply(inout bit<8> value) { value = meta.ev_val8; }
    };
    
    
    
    RegisterAction<bit<32>, bit<12>, bit<32>>(cellc_0) ra_rd0 = {
        void apply(inout bit<32> value, out bit<32> rv) { rv = value; }
    };
    
    RegisterAction<bit<32>, bit<12>, bit<32>>(cellc_1) ra_rd1 = {
        void apply(inout bit<32> value, out bit<32> rv) { rv = value; }
    };
    
    RegisterAction<bit<32>, bit<12>, bit<32>>(cellc_2) ra_rd2 = {
        void apply(inout bit<32> value, out bit<32> rv) { rv = value; }
    };
    
    RegisterAction<bit<32>, bit<12>, bit<32>>(cellc_3) ra_rd3 = {
        void apply(inout bit<32> value, out bit<32> rv) { rv = value; }
    };
    
    RegisterAction<bit<32>, bit<12>, bit<32>>(cellc_4) ra_rd4 = {
        void apply(inout bit<32> value, out bit<32> rv) { rv = value; }
    };
    
    RegisterAction<bit<32>, bit<12>, bit<32>>(cellc_5) ra_rd5 = {
        void apply(inout bit<32> value, out bit<32> rv) { rv = value; }
    };
    
    RegisterAction<bit<32>, bit<12>, bit<32>>(cellc_6) ra_rd6 = {
        void apply(inout bit<32> value, out bit<32> rv) { rv = value; }
    };
    
    
    

    
    action nop() {}
    action set_egr(bit<9> egr_port) { ig_tm_md.ucast_egress_port = egr_port; }

    
    
    
    
    
    action do_key() {
        meta.key = hdr.ipv4.dstAddr & 32w0xFFFFFF00;
    }
    action do_kh() {
        bit<16> raw = h_bucket.get({16w0x9100, meta.key});
        meta.bucket = raw[11:0];
    }
    
    action do_rd0() { meta.v0 = ra_rd0.execute(meta.bucket); }
    action do_rdflag0() {
        meta.hit0 = (meta.v0[31:8] == meta.key[31:8]);
        meta.emp0 = (meta.v0 == 32w0);
        meta.sat0 = (meta.v0[6:0] == 7w0x7F);
    }
    action do_rd1() { meta.v1 = ra_rd1.execute(meta.bucket); }
    action do_rdflag1() {
        meta.hit1 = (meta.v1[31:8] == meta.key[31:8]);
        meta.emp1 = (meta.v1 == 32w0);
        meta.sat1 = (meta.v1[6:0] == 7w0x7F);
    }
    action do_rd2() { meta.v2 = ra_rd2.execute(meta.bucket); }
    action do_rdflag2() {
        meta.hit2 = (meta.v2[31:8] == meta.key[31:8]);
        meta.emp2 = (meta.v2 == 32w0);
        meta.sat2 = (meta.v2[6:0] == 7w0x7F);
    }
    action do_rd3() { meta.v3 = ra_rd3.execute(meta.bucket); }
    action do_rdflag3() {
        meta.hit3 = (meta.v3[31:8] == meta.key[31:8]);
        meta.emp3 = (meta.v3 == 32w0);
        meta.sat3 = (meta.v3[6:0] == 7w0x7F);
    }
    action do_rd4() { meta.v4 = ra_rd4.execute(meta.bucket); }
    action do_rdflag4() {
        meta.hit4 = (meta.v4[31:8] == meta.key[31:8]);
        meta.emp4 = (meta.v4 == 32w0);
        meta.sat4 = (meta.v4[6:0] == 7w0x7F);
    }
    action do_rd5() { meta.v5 = ra_rd5.execute(meta.bucket); }
    action do_rdflag5() {
        meta.hit5 = (meta.v5[31:8] == meta.key[31:8]);
        meta.emp5 = (meta.v5 == 32w0);
        meta.sat5 = (meta.v5[6:0] == 7w0x7F);
    }
    action do_rd6() { meta.v6 = ra_rd6.execute(meta.bucket); }
    action do_rdflag6() {
        meta.hit6 = (meta.v6[31:8] == meta.key[31:8]);
        meta.emp6 = (meta.v6 == 32w0);
        meta.sat6 = (meta.v6[6:0] == 7w0x7F);
    }
    action do_inc0() { ra_inc0.execute(meta.bucket); }
    action do_inc1() { ra_inc1.execute(meta.bucket); }
    action do_inc2() { ra_inc2.execute(meta.bucket); }
    action do_inc3() { ra_inc3.execute(meta.bucket); }
    action do_inc4() { ra_inc4.execute(meta.bucket); }
    action do_inc5() { ra_inc5.execute(meta.bucket); }
    action do_inc6() { ra_inc6.execute(meta.bucket); }
    
    
    action set_fe0() { meta.has_empty = 1w1; meta.first_empty = 8w0; }
    action set_fe1() { meta.has_empty = 1w1; meta.first_empty = 8w1; }
    action set_fe2() { meta.has_empty = 1w1; meta.first_empty = 8w2; }
    action set_fe3() { meta.has_empty = 1w1; meta.first_empty = 8w3; }
    action set_fe4() { meta.has_empty = 1w1; meta.first_empty = 8w4; }
    action set_fe5() { meta.has_empty = 1w1; meta.first_empty = 8w5; }
    action set_fe6() { meta.has_empty = 1w1; meta.first_empty = 8w6; }
    action set_fe7() { meta.has_empty = 1w0; meta.first_empty = 8w7; }
    
    action set_w01_0() { meta.w01 = meta.v0; meta.m01 = 8w0; }
    action set_w01_1() { meta.w01 = meta.v1; meta.m01 = 8w1; }
    action set_w23_2() { meta.w23 = meta.v2; meta.m23 = 8w2; }
    action set_w23_3() { meta.w23 = meta.v3; meta.m23 = 8w3; }
    action set_w45_4() { meta.w45 = meta.v4; meta.m45 = 8w4; }
    action set_w45_5() { meta.w45 = meta.v5; meta.m45 = 8w5; }
    action set_w0123_01() { meta.w0123 = meta.w01; meta.m0123 = meta.m01; }
    action set_w0123_23() { meta.w0123 = meta.w23; meta.m0123 = meta.m23; }
    action set_w456_45() { meta.w456 = meta.w45; meta.m456 = meta.m45; }
    action set_w456_6()  { meta.w456 = meta.v6;  meta.m456 = 8w6; }
    action set_wmin_0123() { meta.wmin = meta.w0123; meta.min_i = meta.m0123; }
    action set_wmin_456()  { meta.wmin = meta.w456;  meta.min_i = meta.m456; }
    
    
    action do_minx8() { meta.min_x8 = (bit<10>)(meta.wmin[6:0]) << 3; }  
    
    action do_rg() { meta.guard_old = ra_gpeek.execute(meta.bucket); }
    action do_guard_cmp() { meta.guard_ge = (meta.guard_old >= (bit<16>)meta.min_x8); }
    action do_dec_rs() {
        meta.rs_key      = meta.key[31:8];
        meta.rs_ev_key   = meta.wmin[31:8];
        
        
        
        
    }
    
    action act_evx(bit<8> v, bit<8> f) {
        meta.rs_ev_val  = v;    
        meta.rs_ev_flag = f;    
    }
    
    action set_op_claim() { meta.rs_op = RS_CLAIM; }
    action set_op_swap()  { meta.rs_op = RS_SWAP; }
    action set_op_light() { meta.rs_op = RS_LIGHT; }
    action set_cell_fe()  { meta.rs_cell = meta.first_empty; }
    action set_cell_min() { meta.rs_cell = meta.min_i; }
    action set_guard0()   { meta.rs_guard_new = 16w0; }
    action set_guard1()   { meta.rs_guard_new = meta.guard_old + 1; }
    
    action do_trig() {
        hdr.resubmit.setValid();
        hdr.resubmit.op        = meta.rs_op;
        hdr.resubmit.cell      = meta.rs_cell;
        hdr.resubmit.key       = meta.rs_key;
        hdr.resubmit.ev_key    = meta.rs_ev_key;
        hdr.resubmit.ev_val    = meta.rs_ev_val;
        hdr.resubmit.ev_flag   = meta.rs_ev_flag;
        hdr.resubmit.guard_new = meta.rs_guard_new;
        ig_dprsr_md.resubmit_type = 3w1;   
        
        
        
    }

    
    action do_rs_new() {
        
        hdr.resubmit.setInvalid();
        meta.rs_key32    = (bit<32>)(meta.rs_key) << 8;
        meta.rs_ev_key32 = (bit<32>)(meta.rs_ev_key) << 8;
        meta.ev_val8     = meta.rs_ev_val;
        
    }
    action set_nc_claim() { meta.newcell = meta.rs_key ++ 8w0x01; }
    action set_nc_swap()  { meta.newcell = meta.rs_key ++ 8w0x81; }
    action do_rs_bkt() {
        bit<16> raw = h_bucket.get({16w0x9100, meta.rs_key32});
        meta.bucket = raw[11:0];
    }
    action do_lp2() {
        bit<32> raw = h_light.get({16w0x9200, meta.rs_key32});
        meta.light_pos = raw[17:0];
    }
    action do_lpe2() {
        bit<32> raw = h_light.get({16w0x9200, meta.rs_ev_key32});
        meta.light_pos_ev = raw[17:0];
    }
    action do_gw()  { ra_gw.execute(meta.bucket); }
    action do_ladd()  { ra_ladd.execute(meta.light_pos); }
    action do_lpeek_ev() {
        meta.light_old_ev = ra_lpeek_ev.execute(meta.light_pos_ev);
        meta.lev_lt = (meta.light_old_ev < meta.ev_val8);   
    }
    action do_room() { meta.room_ev = 8w0xFF - meta.ev_val8; }
    action do_ovf() {
        meta.ovf_ev     = (meta.room_ev < meta.light_old_ev);
        meta.not_ovf_ev = (meta.room_ev >= meta.light_old_ev);
    }
    action do_levaddsat() { ra_levaddsat.execute(meta.light_pos_ev); }
    action do_levmax() { ra_levmax.execute(meta.light_pos_ev); }
    action do_put0() { ra_put0.execute(meta.bucket); }
    action do_put1() { ra_put1.execute(meta.bucket); }
    action do_put2() { ra_put2.execute(meta.bucket); }
    action do_put3() { ra_put3.execute(meta.bucket); }
    action do_put4() { ra_put4.execute(meta.bucket); }
    action do_put5() { ra_put5.execute(meta.bucket); }
    action do_put6() { ra_put6.execute(meta.bucket); }

    
    table forward_ipv4 {
        key = { ig_intr_md.ingress_port : exact; }
        actions = { set_egr; nop; } default_action = nop(); size = 2;
    }
    table tb_key   { actions = { do_key; }   default_action = do_key();   size = 1; }
    table tb_kh    { actions = { do_kh; }    default_action = do_kh();    size = 1; }
    table tb_rd0   { actions = { do_rd0; }   default_action = do_rd0();   size = 1; }
    table tb_rd1   { actions = { do_rd1; }   default_action = do_rd1();   size = 1; }
    table tb_rd2   { actions = { do_rd2; }   default_action = do_rd2();   size = 1; }
    table tb_rd3   { actions = { do_rd3; }   default_action = do_rd3();   size = 1; }
    table tb_rd4   { actions = { do_rd4; }   default_action = do_rd4();   size = 1; }
    table tb_rd5   { actions = { do_rd5; }   default_action = do_rd5();   size = 1; }
    table tb_rd6   { actions = { do_rd6; }   default_action = do_rd6();   size = 1; }
    table tb_rdflag0 { actions = { do_rdflag0; } default_action = do_rdflag0(); size = 1; }
    table tb_rdflag1 { actions = { do_rdflag1; } default_action = do_rdflag1(); size = 1; }
    table tb_rdflag2 { actions = { do_rdflag2; } default_action = do_rdflag2(); size = 1; }
    table tb_rdflag3 { actions = { do_rdflag3; } default_action = do_rdflag3(); size = 1; }
    table tb_rdflag4 { actions = { do_rdflag4; } default_action = do_rdflag4(); size = 1; }
    table tb_rdflag5 { actions = { do_rdflag5; } default_action = do_rdflag5(); size = 1; }
    table tb_rdflag6 { actions = { do_rdflag6; } default_action = do_rdflag6(); size = 1; }
    table tb_inc0  { actions = { do_inc0; }  default_action = do_inc0();  size = 1; }
    table tb_inc1  { actions = { do_inc1; }  default_action = do_inc1();  size = 1; }
    table tb_inc2  { actions = { do_inc2; }  default_action = do_inc2();  size = 1; }
    table tb_inc3  { actions = { do_inc3; }  default_action = do_inc3();  size = 1; }
    table tb_inc4  { actions = { do_inc4; }  default_action = do_inc4();  size = 1; }
    table tb_inc5  { actions = { do_inc5; }  default_action = do_inc5();  size = 1; }
    table tb_inc6  { actions = { do_inc6; }  default_action = do_inc6();  size = 1; }
    
    table t_fe0    { actions = { set_fe0; }  default_action = set_fe0();  size = 1; }
    table t_fe1    { actions = { set_fe1; }  default_action = set_fe1();  size = 1; }
    table t_fe2    { actions = { set_fe2; }  default_action = set_fe2();  size = 1; }
    table t_fe3    { actions = { set_fe3; }  default_action = set_fe3();  size = 1; }
    table t_fe4    { actions = { set_fe4; }  default_action = set_fe4();  size = 1; }
    table t_fe5    { actions = { set_fe5; }  default_action = set_fe5();  size = 1; }
    table t_fe6    { actions = { set_fe6; }  default_action = set_fe6();  size = 1; }
    table t_fe7    { actions = { set_fe7; }  default_action = set_fe7();  size = 1; }
    table t_w01_0 { actions = { set_w01_0; } default_action = set_w01_0(); size = 1; }
    table t_w01_1 { actions = { set_w01_1; } default_action = set_w01_1(); size = 1; }
    table t_w23_2 { actions = { set_w23_2; } default_action = set_w23_2(); size = 1; }
    table t_w23_3 { actions = { set_w23_3; } default_action = set_w23_3(); size = 1; }
    table t_w45_4 { actions = { set_w45_4; } default_action = set_w45_4(); size = 1; }
    table t_w45_5 { actions = { set_w45_5; } default_action = set_w45_5(); size = 1; }
    table t_w0123_01 { actions = { set_w0123_01; } default_action = set_w0123_01(); size = 1; }
    table t_w0123_23 { actions = { set_w0123_23; } default_action = set_w0123_23(); size = 1; }
    table t_w456_45 { actions = { set_w456_45; } default_action = set_w456_45(); size = 1; }
    table t_w456_6  { actions = { set_w456_6; }  default_action = set_w456_6();  size = 1; }
    table t_wmin_0123 { actions = { set_wmin_0123; } default_action = set_wmin_0123(); size = 1; }
    table t_wmin_456  { actions = { set_wmin_456; }  default_action = set_wmin_456();  size = 1; }
    table tb_minx8  { actions = { do_minx8; }   default_action = do_minx8();   size = 1; }
    table tb_rg    { actions = { do_rg; }    default_action = do_rg();    size = 1; }
    table tb_guard_cmp { actions = { do_guard_cmp; } default_action = do_guard_cmp(); size = 1; }
    table tb_dec_rs{ actions = { do_dec_rs; } default_action = do_dec_rs(); size = 1; }
    table tb_evx { key = { meta.wmin[7:0] : exact; } actions = { act_evx; } default_action = act_evx(8w0, 8w0); size = 256; }
    
    table t_op_claim { actions = { set_op_claim; } default_action = set_op_claim(); size = 1; }
    table t_op_swap  { actions = { set_op_swap; }  default_action = set_op_swap();  size = 1; }
    table t_op_light { actions = { set_op_light; } default_action = set_op_light(); size = 1; }
    table t_cell_fe  { actions = { set_cell_fe; }  default_action = set_cell_fe();  size = 1; }
    table t_cell_min { actions = { set_cell_min; } default_action = set_cell_min(); size = 1; }
    table t_guard0   { actions = { set_guard0; }   default_action = set_guard0();   size = 1; }
    table t_guard1   { actions = { set_guard1; }   default_action = set_guard1();   size = 1; }
    table tb_trig  { actions = { do_trig; }  default_action = do_trig();  size = 1; }
    table tb_rs_new { actions = { do_rs_new; } default_action = do_rs_new(); size = 1; }
    
    table t_nc_claim { actions = { set_nc_claim; } default_action = set_nc_claim(); size = 1; }
    table t_nc_swap  { actions = { set_nc_swap; }  default_action = set_nc_swap();  size = 1; }
    table tb_rs_bkt { actions = { do_rs_bkt; } default_action = do_rs_bkt(); size = 1; }
    table tb_put0  { actions = { do_put0; }  default_action = do_put0();  size = 1; }
    table tb_put1  { actions = { do_put1; }  default_action = do_put1();  size = 1; }
    table tb_put2  { actions = { do_put2; }  default_action = do_put2();  size = 1; }
    table tb_put3  { actions = { do_put3; }  default_action = do_put3();  size = 1; }
    table tb_put4  { actions = { do_put4; }  default_action = do_put4();  size = 1; }
    table tb_put5  { actions = { do_put5; }  default_action = do_put5();  size = 1; }
    table tb_put6  { actions = { do_put6; }  default_action = do_put6();  size = 1; }
    table tb_gw    { actions = { do_gw; }    default_action = do_gw();    size = 1; }
    table tb_lp2   { actions = { do_lp2; }   default_action = do_lp2();   size = 1; }
    table tb_lpe2  { actions = { do_lpe2; }  default_action = do_lpe2();  size = 1; }
    table tb_ladd  { actions = { do_ladd; }  default_action = do_ladd();  size = 1; }
    table tb_lpeek_ev { actions = { do_lpeek_ev; } default_action = do_lpeek_ev(); size = 1; }
    table tb_room  { actions = { do_room; }  default_action = do_room();  size = 1; }
    table tb_ovf   { actions = { do_ovf; }   default_action = do_ovf();   size = 1; }
    table tb_levaddsat { actions = { do_levaddsat; } default_action = do_levaddsat(); size = 1; }
    table tb_levmax { actions = { do_levmax; } default_action = do_levmax(); size = 1; }

    apply {
        forward_ipv4.apply();
        if (ig_intr_md.resubmit_flag == 1) {
            
            tb_rs_new.apply();
            if (meta.rs_op == RS_CLAIM) { t_nc_claim.apply(); }
            else { t_nc_swap.apply(); }
            tb_rs_bkt.apply();
            
            
            if (meta.rs_op == RS_CLAIM || meta.rs_op == RS_SWAP) {
                if (meta.rs_cell == 8w0) { tb_put0.apply(); }
                else if (meta.rs_cell == 8w1) { tb_put1.apply(); }
                else if (meta.rs_cell == 8w2) { tb_put2.apply(); }
                else if (meta.rs_cell == 8w3) { tb_put3.apply(); }
                else if (meta.rs_cell == 8w4) { tb_put4.apply(); }
                else if (meta.rs_cell == 8w5) { tb_put5.apply(); }
                else { tb_put6.apply(); }
            }
            if (meta.rs_op == RS_SWAP || meta.rs_op == RS_LIGHT) {
                tb_gw.apply();          
            }
            
            
            
            
            if (meta.rs_op == RS_LIGHT) {
                tb_lp2.apply();         
            }
            if (meta.rs_op == RS_LIGHT) {
                tb_ladd.apply();        
            }
            if (meta.rs_op == RS_SWAP) {
                tb_lpe2.apply();        
            }
            if (meta.rs_op == RS_SWAP) {
                tb_lpeek_ev.apply();
            }
            if (meta.rs_op == RS_SWAP) {
                if (meta.rs_ev_flag == 8w1) {
                    tb_room.apply();
                }
            }
            if (meta.rs_op == RS_SWAP) {
                if (meta.rs_ev_flag == 8w1) {
                    tb_ovf.apply();
                }
            }
            if (meta.rs_op == RS_SWAP) {
                if (meta.rs_ev_flag == 8w1) {
                    tb_levaddsat.apply();
                }
            }
            if (meta.rs_op == RS_SWAP) {
                if (meta.rs_ev_flag == 8w0) {
                    if (meta.lev_lt) { tb_levmax.apply(); }
                }
            }
        } else if (hdr.ipv4.isValid()) {
            
            tb_key.apply();
            tb_kh.apply();
            
            
            tb_rd0.apply(); tb_rd1.apply(); tb_rd2.apply(); tb_rd3.apply();
            tb_rd4.apply(); tb_rd5.apply(); tb_rd6.apply();
            tb_rdflag0.apply(); tb_rdflag1.apply(); tb_rdflag2.apply(); tb_rdflag3.apply();
            tb_rdflag4.apply(); tb_rdflag5.apply(); tb_rdflag6.apply();
            if (meta.hit0 && !meta.sat0) { tb_inc0.apply(); }
            if (meta.hit1 && !meta.sat1) { tb_inc1.apply(); }
            if (meta.hit2 && !meta.sat2) { tb_inc2.apply(); }
            if (meta.hit3 && !meta.sat3) { tb_inc3.apply(); }
            if (meta.hit4 && !meta.sat4) { tb_inc4.apply(); }
            if (meta.hit5 && !meta.sat5) { tb_inc5.apply(); }
            if (meta.hit6 && !meta.sat6) { tb_inc6.apply(); }
            if (!meta.hit0 && !meta.hit1 && !meta.hit2 && !meta.hit3
                && !meta.hit4 && !meta.hit5 && !meta.hit6) {
                                        
                                        
                                        if (meta.emp0) { t_fe0.apply(); }
                                        else if (meta.emp1) { t_fe1.apply(); }
                                        else if (meta.emp2) { t_fe2.apply(); }
                                        else if (meta.emp3) { t_fe3.apply(); }
                                        else if (meta.emp4) { t_fe4.apply(); }
                                        else if (meta.emp5) { t_fe5.apply(); }
                                        else if (meta.emp6) { t_fe6.apply(); }
                                        else { t_fe7.apply(); }
                                        if (meta.v1[6:0] < meta.v0[6:0]) { t_w01_1.apply(); } else { t_w01_0.apply(); }
                                        if (meta.v3[6:0] < meta.v2[6:0]) { t_w23_3.apply(); } else { t_w23_2.apply(); }
                                        if (meta.v5[6:0] < meta.v4[6:0]) { t_w45_5.apply(); } else { t_w45_4.apply(); }
                                        if (meta.w23[6:0] < meta.w01[6:0]) { t_w0123_23.apply(); } else { t_w0123_01.apply(); }
                                        if (meta.v6[6:0] < meta.w45[6:0]) { t_w456_6.apply(); } else { t_w456_45.apply(); }
                                        if (meta.w456[6:0] < meta.w0123[6:0]) { t_wmin_456.apply(); } else { t_wmin_0123.apply(); }
                                        tb_minx8.apply();
                                        tb_rg.apply();
                                        tb_dec_rs.apply();
            tb_evx.apply();
                                        
                                        
                                        
                                        tb_guard_cmp.apply();
                                        if (meta.has_empty == 1w1) { t_op_claim.apply(); }
                                        else if (meta.guard_ge) { t_op_swap.apply(); }
                                        else { t_op_light.apply(); }
                                        
                                        if (meta.has_empty == 1w1) { t_cell_fe.apply(); }
                                        else { t_cell_min.apply(); }
                                        if (meta.guard_ge) { t_guard0.apply(); }
                                        else { t_guard1.apply(); }
                                        tb_trig.apply();
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
