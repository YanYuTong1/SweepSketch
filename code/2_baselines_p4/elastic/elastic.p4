
#include <t2na.p4>
#include "headers.p4"
#include "parser.p4"

#define NB        4096
#define LIGHT_N   262144     

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
        void apply(inout bit<32> value) {
            if (((value & 32w0x7F) != 32w0x7F)) { value = value + 1; }
        }
    };
    RegisterAction<bit<32>, bit<12>, void>(cellc_1) ra_inc1 = {
        void apply(inout bit<32> value) {
            if (((value & 32w0x7F) != 32w0x7F)) { value = value + 1; }
        }
    };
    RegisterAction<bit<32>, bit<12>, void>(cellc_2) ra_inc2 = {
        void apply(inout bit<32> value) {
            if (((value & 32w0x7F) != 32w0x7F)) { value = value + 1; }
        }
    };
    RegisterAction<bit<32>, bit<12>, void>(cellc_3) ra_inc3 = {
        void apply(inout bit<32> value) {
            if (((value & 32w0x7F) != 32w0x7F)) { value = value + 1; }
        }
    };
    RegisterAction<bit<32>, bit<12>, void>(cellc_4) ra_inc4 = {
        void apply(inout bit<32> value) {
            if (((value & 32w0x7F) != 32w0x7F)) { value = value + 1; }
        }
    };
    RegisterAction<bit<32>, bit<12>, void>(cellc_5) ra_inc5 = {
        void apply(inout bit<32> value) {
            if (((value & 32w0x7F) != 32w0x7F)) { value = value + 1; }
        }
    };
    RegisterAction<bit<32>, bit<12>, void>(cellc_6) ra_inc6 = {
        void apply(inout bit<32> value) {
            if (((value & 32w0x7F) != 32w0x7F)) { value = value + 1; }
        }
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
    
    RegisterAction<bit<16>, bit<12>, void>(guard) ra_ginc = {
        void apply(inout bit<16> value) {
            if (value != 16w0xFFFF) { value = value + 1; }   
        }
    };
    RegisterAction<bit<16>, bit<12>, void>(guard) ra_gzero = {
        void apply(inout bit<16> value) { value = 16w0; }
    };
    
    RegisterAction<bit<8>, bit<18>, void>(light) ra_ladd = {
        void apply(inout bit<8> value) {
            if (value != 8w0xFF) { value = value + 1; }      
        }
    };
    RegisterAction<bit<8>, bit<18>, void>(light) ra_levadd = {
        void apply(inout bit<8> value) {
            
            
            value = value + meta.ev_val8;
            if (value < meta.ev_val8) { value = 8w0xFF; }
        }
    };
    RegisterAction<bit<8>, bit<18>, void>(light) ra_levmax = {
        void apply(inout bit<8> value) {
            if (value < meta.ev_val8) { value = meta.ev_val8; }
        }
    };

    
    action nop() {}
    action set_egr(bit<9> egr_port) { ig_tm_md.ucast_egress_port = egr_port; }

    action do_kh() {
        
        meta.key = (hdr.ipv4.dstAddr >> 8) << 8;
        bit<16> raw = h_bucket.get({16w0x9100, meta.key});
        meta.bucket = raw[11:0];
    }
    action do_lp() {
        
        bit<32> raw = h_light.get({16w0x9200, meta.key});
        meta.light_pos = raw[17:0];
    }
    action do_lpe() {
        
        bit<32> raw = h_light.get({16w0x9200, meta.ev_key32});
        meta.light_pos_ev = raw[17:0];
    }
    action do_new() {
        
        meta.newcell = meta.key[31:8] ++ 8w0x81;
    }
    
    action do_rd0() {
        meta.v0   = cellc_0.read(meta.bucket);
        meta.hit0 = ((meta.v0[31:8] == meta.key[31:8]) ? 1w1 : 1w0);
    }
    action do_rd1() {
        meta.v1   = cellc_1.read(meta.bucket);
        meta.hit1 = ((meta.v1[31:8] == meta.key[31:8]) ? 1w1 : 1w0);
    }
    action do_rd2() {
        meta.v2   = cellc_2.read(meta.bucket);
        meta.hit2 = ((meta.v2[31:8] == meta.key[31:8]) ? 1w1 : 1w0);
    }
    action do_rd3() {
        meta.v3   = cellc_3.read(meta.bucket);
        meta.hit3 = ((meta.v3[31:8] == meta.key[31:8]) ? 1w1 : 1w0);
    }
    action do_rd4() {
        meta.v4   = cellc_4.read(meta.bucket);
        meta.hit4 = ((meta.v4[31:8] == meta.key[31:8]) ? 1w1 : 1w0);
    }
    action do_rd5() {
        meta.v5   = cellc_5.read(meta.bucket);
        meta.hit5 = ((meta.v5[31:8] == meta.key[31:8]) ? 1w1 : 1w0);
    }
    action do_rd6() {
        meta.v6   = cellc_6.read(meta.bucket);
        meta.hit6 = ((meta.v6[31:8] == meta.key[31:8]) ? 1w1 : 1w0);
    }
    
    action do_inc0() { ra_inc0.execute(meta.bucket); }
    action do_inc1() { ra_inc1.execute(meta.bucket); }
    action do_inc2() { ra_inc2.execute(meta.bucket); }
    action do_inc3() { ra_inc3.execute(meta.bucket); }
    action do_inc4() { ra_inc4.execute(meta.bucket); }
    action do_inc5() { ra_inc5.execute(meta.bucket); }
    action do_inc6() { ra_inc6.execute(meta.bucket); }
    
    action do_cmp01() {
        meta.w01 = (meta.v0[6:0] <= meta.v1[6:0]) ? meta.v0 : meta.v1;
        meta.m01 = (meta.v0[6:0] <= meta.v1[6:0]) ? 3w0 : 3w1;
    }
    action do_cmp23() {
        meta.w23 = (meta.v2[6:0] <= meta.v3[6:0]) ? meta.v2 : meta.v3;
        meta.m23 = (meta.v2[6:0] <= meta.v3[6:0]) ? 3w2 : 3w3;
    }
    action do_cmp45() {
        meta.w45 = (meta.v4[6:0] <= meta.v5[6:0]) ? meta.v4 : meta.v5;
        meta.m45 = (meta.v4[6:0] <= meta.v5[6:0]) ? 3w4 : 3w5;
    }
    action do_cmp0123() {
        meta.w0123 = (meta.w01[6:0] <= meta.w23[6:0]) ? meta.w01 : meta.w23;
        meta.m0123 = (meta.w01[6:0] <= meta.w23[6:0]) ? meta.m01 : meta.m23;
    }
    action do_cmp456() {
        meta.w456 = (meta.w45[6:0] <= meta.v6[6:0]) ? meta.w45 : meta.v6;
        meta.m456 = (meta.w45[6:0] <= meta.v6[6:0]) ? meta.m45 : 3w6;
    }
    action do_cmpfinal() {
        bit<16> c0123 = (bit<16>)(meta.w0123[6:0]);
        bit<16> c456  = (bit<16>)(meta.w456[6:0]);
        meta.wmin  = (c0123 <= c456) ? meta.w0123 : meta.w456;
        meta.min_i = (c0123 <= c456) ? meta.m0123 : meta.m456;
        bit<16> mc = (bit<16>)(meta.wmin[6:0]);
        meta.min_x8 = (bit<10>)(mc << 3);
    }
    
    action do_ev() {
        meta.ev_key32 = meta.wmin & 32w0xFFFFFF00;
        meta.ev_val   = (bit<7>)(meta.wmin[6:0]);
        meta.ev_flag  = meta.wmin[7];
        meta.ev_val8  = (bit<8>)meta.ev_val;
    }
    
    action do_rg()  { meta.guard_old = guard.read(meta.bucket); }
    action do_dec() {
        bit<16> mx8 = (bit<16>)meta.min_x8;
        
        meta.do_swap = (meta.guard_old >= mx8) ? 1w1 : 1w0;
    }
    action do_ginc()  { ra_ginc.execute(meta.bucket); }
    action do_gzero() { ra_gzero.execute(meta.bucket); }
    action do_ladd()  { ra_ladd.execute(meta.light_pos); }
    action do_levadd() { ra_levadd.execute(meta.light_pos_ev); }
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
    table tb_kh    { actions = { do_kh; }    default_action = do_kh();    size = 1; }
    table tb_lp    { actions = { do_lp; }    default_action = do_lp();    size = 1; }
    table tb_lpe   { actions = { do_lpe; }   default_action = do_lpe();   size = 1; }
    table tb_new   { actions = { do_new; }   default_action = do_new();   size = 1; }
    table tb_rd0   { actions = { do_rd0; }   default_action = do_rd0();   size = 1; }
    table tb_rd1   { actions = { do_rd1; }   default_action = do_rd1();   size = 1; }
    table tb_rd2   { actions = { do_rd2; }   default_action = do_rd2();   size = 1; }
    table tb_rd3   { actions = { do_rd3; }   default_action = do_rd3();   size = 1; }
    table tb_rd4   { actions = { do_rd4; }   default_action = do_rd4();   size = 1; }
    table tb_rd5   { actions = { do_rd5; }   default_action = do_rd5();   size = 1; }
    table tb_rd6   { actions = { do_rd6; }   default_action = do_rd6();   size = 1; }
    table tb_inc0  { actions = { do_inc0; }  default_action = do_inc0();  size = 1; }
    table tb_inc1  { actions = { do_inc1; }  default_action = do_inc1();  size = 1; }
    table tb_inc2  { actions = { do_inc2; }  default_action = do_inc2();  size = 1; }
    table tb_inc3  { actions = { do_inc3; }  default_action = do_inc3();  size = 1; }
    table tb_inc4  { actions = { do_inc4; }  default_action = do_inc4();  size = 1; }
    table tb_inc5  { actions = { do_inc5; }  default_action = do_inc5();  size = 1; }
    table tb_inc6  { actions = { do_inc6; }  default_action = do_inc6();  size = 1; }
    table tb_cmp01 { actions = { do_cmp01; } default_action = do_cmp01(); size = 1; }
    table tb_cmp23 { actions = { do_cmp23; } default_action = do_cmp23(); size = 1; }
    table tb_cmp45 { actions = { do_cmp45; } default_action = do_cmp45(); size = 1; }
    table tb_cmp0123 { actions = { do_cmp0123; } default_action = do_cmp0123(); size = 1; }
    table tb_cmp456  { actions = { do_cmp456; }  default_action = do_cmp456();  size = 1; }
    table tb_cmpfinal{ actions = { do_cmpfinal; } default_action = do_cmpfinal(); size = 1; }
    table tb_ev    { actions = { do_ev; }    default_action = do_ev();    size = 1; }
    table tb_rg    { actions = { do_rg; }    default_action = do_rg();    size = 1; }
    table tb_dec   { actions = { do_dec; }   default_action = do_dec();   size = 1; }
    table tb_put0  { actions = { do_put0; }  default_action = do_put0();  size = 1; }
    table tb_put1  { actions = { do_put1; }  default_action = do_put1();  size = 1; }
    table tb_put2  { actions = { do_put2; }  default_action = do_put2();  size = 1; }
    table tb_put3  { actions = { do_put3; }  default_action = do_put3();  size = 1; }
    table tb_put4  { actions = { do_put4; }  default_action = do_put4();  size = 1; }
    table tb_put5  { actions = { do_put5; }  default_action = do_put5();  size = 1; }
    table tb_put6  { actions = { do_put6; }  default_action = do_put6();  size = 1; }
    table tb_ginc  { actions = { do_ginc; }  default_action = do_ginc();  size = 1; }
    table tb_gzero { actions = { do_gzero; } default_action = do_gzero(); size = 1; }
    table tb_ladd  { actions = { do_ladd; }  default_action = do_ladd();  size = 1; }
    table tb_levadd { actions = { do_levadd; } default_action = do_levadd(); size = 1; }
    table tb_levmax { actions = { do_levmax; } default_action = do_levmax(); size = 1; }

    apply {
        forward_ipv4.apply();
        if (hdr.ipv4.isValid()) {
            tb_kh.apply();
            tb_lp.apply();
            tb_new.apply();
            
            tb_rd0.apply();
            if (meta.hit0 == 1) { tb_inc0.apply(); }
            else {
                tb_rd1.apply();
                if (meta.hit1 == 1) { tb_inc1.apply(); }
                else {
                    tb_rd2.apply();
                    if (meta.hit2 == 1) { tb_inc2.apply(); }
                    else {
                        tb_rd3.apply();
                        if (meta.hit3 == 1) { tb_inc3.apply(); }
                        else {
                            tb_rd4.apply();
                            if (meta.hit4 == 1) { tb_inc4.apply(); }
                            else {
                                tb_rd5.apply();
                                if (meta.hit5 == 1) { tb_inc5.apply(); }
                                else {
                                    tb_rd6.apply();
                                    if (meta.hit6 == 1) { tb_inc6.apply(); }
                                    else {
                                        
                                        tb_cmp01.apply();
                                        tb_cmp23.apply();
                                        tb_cmp45.apply();
                                        tb_cmp0123.apply();
                                        tb_cmp456.apply();
                                        tb_cmpfinal.apply();
                                        tb_ev.apply();
                                        tb_rg.apply();
                                        tb_dec.apply();
                                        if (meta.do_swap == 1) {
                                            
                                            
                                            tb_lpe.apply();
                                            if (meta.min_i == 3w0) { tb_put0.apply(); }
                                            else if (meta.min_i == 3w1) { tb_put1.apply(); }
                                            else if (meta.min_i == 3w2) { tb_put2.apply(); }
                                            else if (meta.min_i == 3w3) { tb_put3.apply(); }
                                            else if (meta.min_i == 3w4) { tb_put4.apply(); }
                                            else if (meta.min_i == 3w5) { tb_put5.apply(); }
                                            else { tb_put6.apply(); }
                                            tb_gzero.apply();
                                            if (meta.ev_flag == 1) { tb_levadd.apply(); }
                                            else { tb_levmax.apply(); }
                                        } else {
                                            
                                            tb_ginc.apply();
                                            tb_ladd.apply();
                                        }
                                    }
                                }
                            }
                        }
                    }
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
