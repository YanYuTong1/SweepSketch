
#include <t2na.p4>
#include "headers.p4"
#include "parser.p4"


const bit<16> SALT_LV   = 0x8100;
const bit<16> SALT_SLOT = 0x8200;

control Ingress(
    inout headers_t                                 hdr,
    inout ig_metadata_t                             meta,
    in    ingress_intrinsic_metadata_t              ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md)
{
    
    Register<bit<32>, bit<13>>(8192, 32w0) key0;
    Register<bit<32>, bit<13>>(8192, 32w0) key1;
    Register<bit<32>, bit<13>>(8192, 32w0) key2;
    Register<bit<32>, bit<13>>(8192, 32w0) key3;
    Register<bit<32>, bit<13>>(8192, 32w0) cnt0;
    Register<bit<32>, bit<13>>(8192, 32w0) cnt1;
    Register<bit<32>, bit<13>>(8192, 32w0) cnt2;
    Register<bit<32>, bit<13>>(8192, 32w0) cnt3;
    Register<bit<32>, bit<1>>(1, 32w0) base0;
    Register<bit<32>, bit<1>>(1, 32w0) base1;
    Register<bit<32>, bit<1>>(1, 32w0) base2;
    Register<bit<32>, bit<1>>(1, 32w0) base3;

    
    Hash<bit<16>>(HashAlgorithm_t.CRC32) h_lv;     
    Hash<bit<16>>(HashAlgorithm_t.CRC32) h_slot;   

    
    
    RegisterAction<bit<32>, bit<13>, bit<32>>(key0) ra_key_peek0 = {
        void apply(inout bit<32> value, out bit<32> rv) { rv = value; }
    };
    RegisterAction<bit<32>, bit<13>, void>(key0) ra_key_claim0 = {
        void apply(inout bit<32> value) { value = meta.item; }   
    };
    RegisterAction<bit<32>, bit<13>, bit<32>>(cnt0) ra_cnt_peek0 = {
        void apply(inout bit<32> value, out bit<32> rv) { rv = value; }
    };
    
    
    RegisterAction<bit<32>, bit<13>, void>(cnt0) ra_cnt_upd0 = {
        void apply(inout bit<32> value) {
            if (meta.key_match) {
                if (value < 32w0xFFFFFFFF) { value = value + 32w1; }
            } else { value = meta.nc2; }
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(base0) ra_base_peek0 = {
        void apply(inout bit<32> value, out bit<32> rv) { rv = value; }
    };
    RegisterAction<bit<32>, bit<1>, void>(base0) ra_base_inc0 = {
        void apply(inout bit<32> value) {
            if (meta.key_miss) {
                if (value < 32w0xFFFFFFFF) { value = value + 32w1; }
            }
        }
    };
    
    RegisterAction<bit<32>, bit<13>, bit<32>>(key1) ra_key_peek1 = {
        void apply(inout bit<32> value, out bit<32> rv) { rv = value; }
    };
    RegisterAction<bit<32>, bit<13>, void>(key1) ra_key_claim1 = {
        void apply(inout bit<32> value) { value = meta.item; }
    };
    RegisterAction<bit<32>, bit<13>, bit<32>>(cnt1) ra_cnt_peek1 = {
        void apply(inout bit<32> value, out bit<32> rv) { rv = value; }
    };
    RegisterAction<bit<32>, bit<13>, void>(cnt1) ra_cnt_upd1 = {
        void apply(inout bit<32> value) {
            if (meta.key_match) {
                if (value < 32w0xFFFFFFFF) { value = value + 32w1; }
            } else { value = meta.nc2; }
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(base1) ra_base_peek1 = {
        void apply(inout bit<32> value, out bit<32> rv) { rv = value; }
    };
    RegisterAction<bit<32>, bit<1>, void>(base1) ra_base_inc1 = {
        void apply(inout bit<32> value) {
            if (meta.key_miss) {
                if (value < 32w0xFFFFFFFF) { value = value + 32w1; }
            }
        }
    };
    
    RegisterAction<bit<32>, bit<13>, bit<32>>(key2) ra_key_peek2 = {
        void apply(inout bit<32> value, out bit<32> rv) { rv = value; }
    };
    RegisterAction<bit<32>, bit<13>, void>(key2) ra_key_claim2 = {
        void apply(inout bit<32> value) { value = meta.item; }
    };
    RegisterAction<bit<32>, bit<13>, bit<32>>(cnt2) ra_cnt_peek2 = {
        void apply(inout bit<32> value, out bit<32> rv) { rv = value; }
    };
    RegisterAction<bit<32>, bit<13>, void>(cnt2) ra_cnt_upd2 = {
        void apply(inout bit<32> value) {
            if (meta.key_match) {
                if (value < 32w0xFFFFFFFF) { value = value + 32w1; }
            } else { value = meta.nc2; }
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(base2) ra_base_peek2 = {
        void apply(inout bit<32> value, out bit<32> rv) { rv = value; }
    };
    RegisterAction<bit<32>, bit<1>, void>(base2) ra_base_inc2 = {
        void apply(inout bit<32> value) {
            if (meta.key_miss) {
                if (value < 32w0xFFFFFFFF) { value = value + 32w1; }
            }
        }
    };
    
    RegisterAction<bit<32>, bit<13>, bit<32>>(key3) ra_key_peek3 = {
        void apply(inout bit<32> value, out bit<32> rv) { rv = value; }
    };
    RegisterAction<bit<32>, bit<13>, void>(key3) ra_key_claim3 = {
        void apply(inout bit<32> value) { value = meta.item; }
    };
    RegisterAction<bit<32>, bit<13>, bit<32>>(cnt3) ra_cnt_peek3 = {
        void apply(inout bit<32> value, out bit<32> rv) { rv = value; }
    };
    RegisterAction<bit<32>, bit<13>, void>(cnt3) ra_cnt_upd3 = {
        void apply(inout bit<32> value) {
            if (meta.key_match) {
                if (value < 32w0xFFFFFFFF) { value = value + 32w1; }
            } else { value = meta.nc2; }
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(base3) ra_base_peek3 = {
        void apply(inout bit<32> value, out bit<32> rv) { rv = value; }
    };
    RegisterAction<bit<32>, bit<1>, void>(base3) ra_base_inc3 = {
        void apply(inout bit<32> value) {
            if (meta.key_miss) {
                if (value < 32w0xFFFFFFFF) { value = value + 32w1; }
            }
        }
    };

    
    action nop() {}
    action set_egr(bit<9> egr_port) { ig_tm_md.ucast_egress_port = egr_port; }

    
    action do_hash_lv() {
        
        meta.lv = (bit<2>)(h_lv.get({SALT_LV, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr}) & 16w0x0003);
    }

    
    action act_mask(bit<32> m) { meta.item = hdr.ipv4.dstAddr & m; }

    
    action do_slot() {
        meta.slot = (bit<13>)(h_slot.get({SALT_SLOT, meta.item}) & 16w0x1FFF);
    }

    
    action do_key_peek0()  { meta.rkey = ra_key_peek0.execute(meta.slot); }
    action do_key_claim0() { ra_key_claim0.execute(meta.slot); }
    action do_cnt_peek0()  { meta.rcnt = ra_cnt_peek0.execute(meta.slot); }
    action do_base_peek0() { meta.basev = ra_base_peek0.execute(1w0); }
    action do_flags0() {
        meta.key_match = (meta.rkey == meta.item);   
        meta.key_miss  = (meta.rkey != meta.item);
    }
    action do_nc2_0() { meta.nc2 = meta.basev + 32w2; }
    action do_cnt_upd0() { ra_cnt_upd0.execute(meta.slot); }
    action do_base_inc0() { ra_base_inc0.execute(1w0); }

    action do_key_peek1()  { meta.rkey = ra_key_peek1.execute(meta.slot); }
    action do_key_claim1() { ra_key_claim1.execute(meta.slot); }
    action do_cnt_peek1()  { meta.rcnt = ra_cnt_peek1.execute(meta.slot); }
    action do_base_peek1() { meta.basev = ra_base_peek1.execute(1w0); }
    action do_flags1() {
        meta.key_match = (meta.rkey == meta.item);
        meta.key_miss  = (meta.rkey != meta.item);
    }
    action do_nc2_1() { meta.nc2 = meta.basev + 32w2; }
    action do_cnt_upd1() { ra_cnt_upd1.execute(meta.slot); }
    action do_base_inc1() { ra_base_inc1.execute(1w0); }

    action do_key_peek2()  { meta.rkey = ra_key_peek2.execute(meta.slot); }
    action do_key_claim2() { ra_key_claim2.execute(meta.slot); }
    action do_cnt_peek2()  { meta.rcnt = ra_cnt_peek2.execute(meta.slot); }
    action do_base_peek2() { meta.basev = ra_base_peek2.execute(1w0); }
    action do_flags2() {
        meta.key_match = (meta.rkey == meta.item);
        meta.key_miss  = (meta.rkey != meta.item);
    }
    action do_nc2_2() { meta.nc2 = meta.basev + 32w2; }
    action do_cnt_upd2() { ra_cnt_upd2.execute(meta.slot); }
    action do_base_inc2() { ra_base_inc2.execute(1w0); }

    action do_key_peek3()  { meta.rkey = ra_key_peek3.execute(meta.slot); }
    action do_key_claim3() { ra_key_claim3.execute(meta.slot); }
    action do_cnt_peek3()  { meta.rcnt = ra_cnt_peek3.execute(meta.slot); }
    action do_base_peek3() { meta.basev = ra_base_peek3.execute(1w0); }
    action do_flags3() {
        meta.key_match = (meta.rkey == meta.item);
        meta.key_miss  = (meta.rkey != meta.item);
    }
    action do_nc2_3() { meta.nc2 = meta.basev + 32w2; }
    action do_cnt_upd3() { ra_cnt_upd3.execute(meta.slot); }
    action do_base_inc3() { ra_base_inc3.execute(1w0); }

    
    
    table forward_ipv4 {
        key = { ig_intr_md.ingress_port : exact; }
        actions = { set_egr; nop; } default_action = nop(); size = 2;
    }
    
    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr : lpm; }
        actions = { set_egr; nop; } default_action = nop(); size = 4096;
    }
    
    @stage(1) table tb_hash_lv { actions = { do_hash_lv; } default_action = do_hash_lv(); size = 1; }
    @stage(2) table tbl_mask {
        key = { meta.lv : ternary; }               
        actions = { act_mask; nop; } default_action = nop(); size = 4;
    }
    @stage(3) table tb_slot { actions = { do_slot; } default_action = do_slot(); size = 1; }

    
    
    
    
    
    @stage(4) table tb_kpk0  { actions = { do_key_peek0; }  default_action = do_key_peek0();  size = 1; }
    @stage(4) table tb_kcl0  { actions = { do_key_claim0; } default_action = do_key_claim0(); size = 1; }
    @stage(4) table tb_kpk1  { actions = { do_key_peek1; }  default_action = do_key_peek1();  size = 1; }
    @stage(4) table tb_kcl1  { actions = { do_key_claim1; } default_action = do_key_claim1(); size = 1; }
    @stage(5) table tb_bpk0  { actions = { do_base_peek0; } default_action = do_base_peek0(); size = 1; }
    @stage(5) table tb_flg0  { actions = { do_flags0; }     default_action = do_flags0();     size = 1; }
    @stage(5) table tb_nc20  { actions = { do_nc2_0; }      default_action = do_nc2_0();      size = 1; }
    @stage(5) table tb_binc0 { actions = { do_base_inc0; }  default_action = do_base_inc0();  size = 1; }
    @stage(5) table tb_bpk1  { actions = { do_base_peek1; } default_action = do_base_peek1(); size = 1; }
    @stage(5) table tb_flg1  { actions = { do_flags1; }     default_action = do_flags1();     size = 1; }
    @stage(5) table tb_nc21  { actions = { do_nc2_1; }      default_action = do_nc2_1();      size = 1; }
    @stage(5) table tb_binc1 { actions = { do_base_inc1; }  default_action = do_base_inc1();  size = 1; }
    @stage(6) table tb_cpk0  { actions = { do_cnt_peek0; }  default_action = do_cnt_peek0();  size = 1; }
    @stage(6) table tb_cupd0 { actions = { do_cnt_upd0; }   default_action = do_cnt_upd0();   size = 1; }
    @stage(6) table tb_cpk1  { actions = { do_cnt_peek1; }  default_action = do_cnt_peek1();  size = 1; }
    @stage(6) table tb_cupd1 { actions = { do_cnt_upd1; }   default_action = do_cnt_upd1();   size = 1; }

    @stage(7) table tb_kpk2  { actions = { do_key_peek2; }  default_action = do_key_peek2();  size = 1; }
    @stage(7) table tb_kcl2  { actions = { do_key_claim2; } default_action = do_key_claim2(); size = 1; }
    @stage(7) table tb_kpk3  { actions = { do_key_peek3; }  default_action = do_key_peek3();  size = 1; }
    @stage(7) table tb_kcl3  { actions = { do_key_claim3; } default_action = do_key_claim3(); size = 1; }
    @stage(8) table tb_bpk2  { actions = { do_base_peek2; } default_action = do_base_peek2(); size = 1; }
    @stage(8) table tb_flg2  { actions = { do_flags2; }     default_action = do_flags2();     size = 1; }
    @stage(8) table tb_nc22  { actions = { do_nc2_2; }      default_action = do_nc2_2();      size = 1; }
    @stage(8) table tb_binc2 { actions = { do_base_inc2; }  default_action = do_base_inc2();  size = 1; }
    @stage(8) table tb_bpk3  { actions = { do_base_peek3; } default_action = do_base_peek3(); size = 1; }
    @stage(8) table tb_flg3  { actions = { do_flags3; }     default_action = do_flags3();     size = 1; }
    @stage(8) table tb_nc23  { actions = { do_nc2_3; }      default_action = do_nc2_3();      size = 1; }
    @stage(8) table tb_binc3 { actions = { do_base_inc3; }  default_action = do_base_inc3();  size = 1; }
    @stage(9) table tb_cpk2  { actions = { do_cnt_peek2; }  default_action = do_cnt_peek2();  size = 1; }
    @stage(9) table tb_cupd2 { actions = { do_cnt_upd2; }   default_action = do_cnt_upd2();   size = 1; }
    @stage(9) table tb_cpk3  { actions = { do_cnt_peek3; }  default_action = do_cnt_peek3();  size = 1; }
    @stage(9) table tb_cupd3 { actions = { do_cnt_upd3; }   default_action = do_cnt_upd3();   size = 1; }

    
    apply {
        forward_ipv4.apply();
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();               
            
            tb_hash_lv.apply();
            tbl_mask.apply();
            tb_slot.apply();
            
            
            if (meta.lv == 2w0) {
                tb_kpk0.apply(); tb_kcl0.apply(); tb_cpk0.apply(); tb_bpk0.apply();
                tb_flg0.apply(); tb_nc20.apply(); tb_cupd0.apply(); tb_binc0.apply();
            } else if (meta.lv == 2w1) {
                tb_kpk1.apply(); tb_kcl1.apply(); tb_cpk1.apply(); tb_bpk1.apply();
                tb_flg1.apply(); tb_nc21.apply(); tb_cupd1.apply(); tb_binc1.apply();
            } else if (meta.lv == 2w2) {
                tb_kpk2.apply(); tb_kcl2.apply(); tb_cpk2.apply(); tb_bpk2.apply();
                tb_flg2.apply(); tb_nc22.apply(); tb_cupd2.apply(); tb_binc2.apply();
            } else {
                tb_kpk3.apply(); tb_kcl3.apply(); tb_cpk3.apply(); tb_bpk3.apply();
                tb_flg3.apply(); tb_nc23.apply(); tb_cupd3.apply(); tb_binc3.apply();
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
