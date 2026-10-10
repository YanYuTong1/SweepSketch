






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
    
    Register<bit<32>, bit<6>>(64, 32w0)  bucket_key0;
    Register<bit<16>, bit<6>>(64, 16w0)  subnet_bm0;
    Register<bit<32>, bit<6>>(64, 32w0)  bucket_cnt0;
    Register<bit<32>, bit<9>>(512, 32w0) host_bm0;

    Register<bit<32>, bit<6>>(64, 32w0)  bucket_key1;
    Register<bit<16>, bit<6>>(64, 16w0)  subnet_bm1;
    Register<bit<32>, bit<6>>(64, 32w0)  bucket_cnt1;
    Register<bit<32>, bit<9>>(512, 32w0) host_bm1;

    Register<bit<32>, bit<6>>(64, 32w0)  bucket_key2;
    Register<bit<16>, bit<6>>(64, 16w0)  subnet_bm2;
    Register<bit<32>, bit<6>>(64, 32w0)  bucket_cnt2;
    Register<bit<32>, bit<9>>(512, 32w0) host_bm2;

    
    
    Hash<bit<16>>(HashAlgorithm_t.CRC32) h_col0;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) h_col1;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) h_col2;
    
    Hash<bit<16>>(HashAlgorithm_t.CRC16) h_s1;
    Hash<bit<16>>(HashAlgorithm_t.CRC16) h_s2;
    Hash<bit<16>>(HashAlgorithm_t.CRC16) h_s3;
    Hash<bit<16>>(HashAlgorithm_t.CRC16) h_host;

    
    RegisterAction<bit<32>, bit<6>, bit<32>>(bucket_key0) ra_key0 = {
        void apply(inout bit<32> value, out bit<32> rv) {
            if (value == 0) { value = meta.src_addr; }
            rv = value;
        }
    };
    RegisterAction<bit<16>, bit<6>, void>(subnet_bm0) ra_sbm0 = {
        void apply(inout bit<16> value) { value = value | (bit<16>)meta.mask3; }
    };
    RegisterAction<bit<32>, bit<6>, void>(bucket_cnt0) ra_cnt0 = {
        void apply(inout bit<32> value) { value = value + 1; }
    };
    RegisterAction<bit<32>, bit<9>, void>(host_bm0) ra_hbm0 = {
        void apply(inout bit<32> value) { value = value | meta.host_bm_mask; }
    };

    RegisterAction<bit<32>, bit<6>, bit<32>>(bucket_key1) ra_key1 = {
        void apply(inout bit<32> value, out bit<32> rv) {
            if (value == 0) { value = meta.src_addr; }
            rv = value;
        }
    };
    RegisterAction<bit<16>, bit<6>, void>(subnet_bm1) ra_sbm1 = {
        void apply(inout bit<16> value) { value = value | (bit<16>)meta.mask3; }
    };
    RegisterAction<bit<32>, bit<6>, void>(bucket_cnt1) ra_cnt1 = {
        void apply(inout bit<32> value) { value = value + 1; }
    };
    RegisterAction<bit<32>, bit<9>, void>(host_bm1) ra_hbm1 = {
        void apply(inout bit<32> value) { value = value | meta.host_bm_mask; }
    };

    RegisterAction<bit<32>, bit<6>, bit<32>>(bucket_key2) ra_key2 = {
        void apply(inout bit<32> value, out bit<32> rv) {
            if (value == 0) { value = meta.src_addr; }
            rv = value;
        }
    };
    RegisterAction<bit<16>, bit<6>, void>(subnet_bm2) ra_sbm2 = {
        void apply(inout bit<16> value) { value = value | (bit<16>)meta.mask3; }
    };
    RegisterAction<bit<32>, bit<6>, void>(bucket_cnt2) ra_cnt2 = {
        void apply(inout bit<32> value) { value = value + 1; }
    };
    RegisterAction<bit<32>, bit<9>, void>(host_bm2) ra_hbm2 = {
        void apply(inout bit<32> value) { value = value | meta.host_bm_mask; }
    };

    
    action nop() {}
    action set_egr(bit<9> egr_port) { ig_tm_md.ucast_egress_port = egr_port; }

    action do_col0() {
        meta.src_addr = hdr.ipv4.srcAddr;
        meta.col_r0 = (bit<8>)(h_col0.get({
            8w0, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol,
            meta.transport_src_port, meta.transport_dst_port}) % 64);
    }
    action do_col1() {
        meta.col_r1 = (bit<8>)(h_col1.get({
            8w1, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol,
            meta.transport_src_port, meta.transport_dst_port}) % 64);
    }
    action do_col2() {
        meta.col_r2 = (bit<8>)(h_col2.get({
            8w2, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol,
            meta.transport_src_port, meta.transport_dst_port}) % 64);
    }

    action do_s1() { meta.hash_s1 = (bit<1>)(h_s1.get({hdr.user.dst_byte_1}) & 16w1); }
    action do_s2() { meta.hash_s2 = (bit<1>)(h_s2.get({hdr.user.dst_byte_2}) & 16w1); }
    action do_s3() { meta.hash_s3 = (bit<1>)(h_s3.get({hdr.user.dst_byte_3}) & 16w1); }
    action do_host() {
        meta.host_bm_byte = (bit<8>)(h_host.get({hdr.ipv4.dstAddr}) & 16w0xFF);
    }
    action do_host_split() {
        meta.host_bm_word = meta.host_bm_byte[7:5];
        meta.host_bm_bit  = meta.host_bm_byte[4:0];
    }
    action do_hidx() {
        meta.host_bm_index    = meta.col_r0[5:0] ++ meta.host_bm_word;
        meta.host_bm_index_r1 = meta.col_r1[5:0] ++ meta.host_bm_word;
        meta.host_bm_index_r2 = meta.col_r2[5:0] ++ meta.host_bm_word;
    }

    action act_m1(bit<8> m)    { meta.mask1 = m; }
    action act_m2(bit<8> m)    { meta.mask2 = m; }
    action act_m3(bit<8> m)    { meta.mask3 = m; }
    action act_hmask(bit<32> m){ meta.host_bm_mask = m; }

    action do_key0()    { meta.r0_key = ra_key0.execute((bit<6>)meta.col_r0); }
    action do_key1()    { meta.r1_key = ra_key1.execute((bit<6>)meta.col_r1); }
    action do_key2()    { meta.r2_key = ra_key2.execute((bit<6>)meta.col_r2); }
    action set_active0(){ meta.active_r0 = (meta.r0_key == meta.src_addr); }
    action set_active1(){ meta.active_r1 = (meta.r1_key == meta.src_addr); }
    action set_active2(){ meta.active_r2 = (meta.r2_key == meta.src_addr); }
    action do_sbm0()    { ra_sbm0.execute((bit<6>)meta.col_r0); }
    action do_sbm1()    { ra_sbm1.execute((bit<6>)meta.col_r1); }
    action do_sbm2()    { ra_sbm2.execute((bit<6>)meta.col_r2); }
    action do_cnt0()    { ra_cnt0.execute((bit<6>)meta.col_r0); }
    action do_cnt1()    { ra_cnt1.execute((bit<6>)meta.col_r1); }
    action do_cnt2()    { ra_cnt2.execute((bit<6>)meta.col_r2); }
    action do_hbm0()    { ra_hbm0.execute(meta.host_bm_index); }
    action do_hbm1()    { ra_hbm1.execute(meta.host_bm_index_r1); }
    action do_hbm2()    { ra_hbm2.execute(meta.host_bm_index_r2); }

    
    table forward_ipv4 {
        key = { ig_intr_md.ingress_port : exact; }
        actions = { set_egr; nop; } default_action = nop(); size = 2;
    }
    
    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr : lpm; }
        actions = { set_egr; nop; } default_action = nop(); size = 4096;
    }
    
    table acl {
        key = {
            hdr.ethernet.dstAddr : ternary;
            hdr.ethernet.srcAddr : ternary;
        }
        actions = { set_egr; nop; } default_action = nop(); size = 512;
    }
    table tb_col0 { actions = { do_col0; } default_action = do_col0(); size = 1; }
    table tb_col1 { actions = { do_col1; } default_action = do_col1(); size = 1; }
    table tb_col2 { actions = { do_col2; } default_action = do_col2(); size = 1; }
    table tb_s1   { actions = { do_s1; }   default_action = do_s1();   size = 1; }
    table tb_s2   { actions = { do_s2; }   default_action = do_s2();   size = 1; }
    table tb_s3   { actions = { do_s3; }   default_action = do_s3();   size = 1; }
    table tb_host { actions = { do_host; } default_action = do_host(); size = 1; }
    table tb_host_split { actions = { do_host_split; } default_action = do_host_split(); size = 1; }
    table tb_hidx { actions = { do_hidx; } default_action = do_hidx(); size = 1; }

    table tbl_mask1 {
        key = { meta.hash_s1 : exact; }
        actions = { act_m1; nop; } default_action = nop(); size = 2;
    }
    table tbl_mask2 {
        key = { meta.hash_s1 : exact; meta.hash_s2 : exact; }
        actions = { act_m2; nop; } default_action = nop(); size = 4;
    }
    table tbl_mask3 {
        key = { meta.hash_s1 : exact; meta.hash_s2 : exact; meta.hash_s3 : exact; }
        actions = { act_m3; nop; } default_action = nop(); size = 8;
    }
    table tbl_hmask {
        key = { meta.host_bm_bit : exact; }
        actions = { act_hmask; nop; } default_action = nop(); size = 32;
    }

    table tb_key0 { actions = { do_key0; } default_action = do_key0(); size = 1; }
    table tb_key1 { actions = { do_key1; } default_action = do_key1(); size = 1; }
    table tb_key2 { actions = { do_key2; } default_action = do_key2(); size = 1; }
    table tb_active0 { actions = { set_active0; } default_action = set_active0(); size = 1; }
    table tb_active1 { actions = { set_active1; } default_action = set_active1(); size = 1; }
    table tb_active2 { actions = { set_active2; } default_action = set_active2(); size = 1; }
    table tb_sbm0 { actions = { do_sbm0; } default_action = do_sbm0(); size = 1; }
    table tb_sbm1 { actions = { do_sbm1; } default_action = do_sbm1(); size = 1; }
    table tb_sbm2 { actions = { do_sbm2; } default_action = do_sbm2(); size = 1; }
    table tb_cnt0 { actions = { do_cnt0; } default_action = do_cnt0(); size = 1; }
    table tb_cnt1 { actions = { do_cnt1; } default_action = do_cnt1(); size = 1; }
    table tb_cnt2 { actions = { do_cnt2; } default_action = do_cnt2(); size = 1; }
    table tb_hbm0 { actions = { do_hbm0; } default_action = do_hbm0(); size = 1; }
    table tb_hbm1 { actions = { do_hbm1; } default_action = do_hbm1(); size = 1; }
    table tb_hbm2 { actions = { do_hbm2; } default_action = do_hbm2(); size = 1; }

    apply {
        forward_ipv4.apply();
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();               
            
            tb_col0.apply(); tb_col1.apply(); tb_col2.apply();
            
            tb_s1.apply(); tb_s2.apply(); tb_s3.apply();
            tb_host.apply(); tb_host_split.apply();
            
            tbl_mask1.apply(); tbl_mask2.apply(); tbl_mask3.apply();
            tbl_hmask.apply();
            tb_hidx.apply();
            
            tb_key0.apply(); tb_key1.apply(); tb_key2.apply();
            tb_active0.apply(); tb_active1.apply(); tb_active2.apply();
            
            if (meta.active_r0) { tb_sbm0.apply(); tb_cnt0.apply(); tb_hbm0.apply(); }
            if (meta.active_r1) { tb_sbm1.apply(); tb_cnt1.apply(); tb_hbm1.apply(); }
            if (meta.active_r2) { tb_sbm2.apply(); tb_cnt2.apply(); tb_hbm2.apply(); }
        }
        acl.apply();                        
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
