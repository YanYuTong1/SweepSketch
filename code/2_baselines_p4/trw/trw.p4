
























#include <t2na.p4>
#include "headers.p4"
#include "parser.p4"


#define TRW_N     65536       
#define PB_WORDS  65536       
#define D_NEW_Q   355         
#define ETA1_Q    1280        

control Ingress(
    inout headers_t                                hdr,
    inout trw_meta_t                               meta,
    in    ingress_intrinsic_metadata_t             ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t      ig_tm_md)
{
    
    Register<bit<32>, bit<16>>(TRW_N, 32w0)     trw_src;   
    Register<bit<16>, bit<16>>(TRW_N, 16w0)     trw_lam;   
    Register<bit<32>, bit<16>>(PB_WORDS, 32w0)  pair_bm;   

    
    Hash<bit<16>>(HashAlgorithm_t.CRC32) h_slot;   
    Hash<bit<32>>(HashAlgorithm_t.CRC32) h_pair;   

    
    
    
    
    
    
    
    RegisterAction<bit<32>, bit<16>, bit<32>>(pair_bm) ra_bm_rset = {
        void apply(inout bit<32> value, out bit<32> rv) {
            rv = value;
            value = value | meta.mask;
        }
    };
    
    
    
    RegisterAction<bit<32>, bit<16>, bit<32>>(trw_src) ra_src_rc = {
        void apply(inout bit<32> value, out bit<32> rv) {
            rv = value;
            if (meta.bm_clear) { value = meta.src; }            
        }
    };
    
    
    
    RegisterAction<bit<16>, bit<16>, bit<16>>(trw_lam) ra_lam_add = {
        void apply(inout bit<16> value, out bit<16> rv) {
            rv = value;
            if (meta.bm_clear) { value = value + (bit<16>)D_NEW_Q; }
        }
    };
    RegisterAction<bit<16>, bit<16>, bit<16>>(trw_lam) ra_lam_claim = {
        void apply(inout bit<16> value, out bit<16> rv) {
            rv = value;
            if (meta.bm_clear) { value = (bit<16>)D_NEW_Q; }
        }
    };

    
    action nop() {}
    action set_egr(bit<9> egr_port) { ig_tm_md.ucast_egress_port = egr_port; }

    action do_src() {
        meta.src = hdr.ipv4.srcAddr;
        meta.dst = hdr.ipv4.dstAddr;
    }
    action do_hslot() {
        
        meta.slot = h_slot.get({16w0x0100, hdr.ipv4.srcAddr});
    }
    action do_hpair() {
        meta.pair_hash = h_pair.get({16w0x0200, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr});
    }
    action do_split() {
        meta.pair_word = meta.pair_hash[20:5];   
        meta.pair_bit  = meta.pair_hash[4:0];    
    }
    action act_mask(bit<32> m) { meta.mask = m; }
    action do_bmr()  { meta.bm_old = ra_bm_rset.execute(meta.pair_word); }
    action do_bmc()  {
        meta.bm_masked = meta.bm_old & meta.mask;      
    }
    
    
    action do_bmc2() {
        meta.bm_clear = (meta.bm_masked == 32w0);      
        
    }
    action do_srcr() { meta.key_old = ra_src_rc.execute(meta.slot); }
    
    action do_cmp() {
        meta.key_eq = meta.key_old ^ meta.src;      
    }
    
    
    
    action do_lam_add()   { meta.lam_now = ra_lam_add.execute(meta.slot); }
    action do_lam_claim() { meta.lam_now = ra_lam_claim.execute(meta.slot); }
    
    action do_dg() {
        
        meta.alerted   = 1;
        meta.dg_src    = meta.src;
        meta.dg_dst    = meta.dst;
        meta.dg_lam    = meta.lam_now;
        
        meta.dg_epoch  = ig_prsr_md.global_tstamp[39:32];
        meta.dg_tstamp = ig_prsr_md.global_tstamp[47:16];
        meta.dg_reason = 8w1;          
    }

    
    
    
    
    
    
    
    
    
    table forward_ipv4 {
        key = { ig_intr_md.ingress_port : exact; }
        actions = { set_egr; nop; } default_action = nop(); size = 2;
    }
    
    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr : lpm; }
        actions = { set_egr; nop; } default_action = nop(); size = 4096;
    }
    @stage(1) table tb_src   { actions = { do_src; }   default_action = do_src();   size = 1; }
    @stage(1) table tb_hslot { actions = { do_hslot; } default_action = do_hslot(); size = 1; }
    @stage(1) table tb_hpair { actions = { do_hpair; } default_action = do_hpair(); size = 1; }
    @stage(1) table tb_split { actions = { do_split; } default_action = do_split(); size = 1; }
    @stage(1) table tbl_mask {                            
        key = { meta.pair_bit : exact; }
        actions = { act_mask; nop; } default_action = nop(); size = 32;
    }
    @stage(2) table tb_bmr { actions = { do_bmr; } default_action = do_bmr(); size = 1; }
    @stage(3) table tb_bmc  { actions = { do_bmc; }  default_action = do_bmc();  size = 1; }
    @stage(3) table tb_bmc2 { actions = { do_bmc2; } default_action = do_bmc2(); size = 1; }
    @stage(4) table tb_srcr { actions = { do_srcr; } default_action = do_srcr(); size = 1; }
    @stage(5) table tb_cmp  { actions = { do_cmp; }  default_action = do_cmp();  size = 1; }
    @stage(6) table tb_lam_add   { actions = { do_lam_add; }   default_action = do_lam_add();   size = 1; }
    @stage(6) table tb_lam_claim { actions = { do_lam_claim; } default_action = do_lam_claim(); size = 1; }
    @stage(7) table tb_dg    { actions = { do_dg; }    default_action = do_dg();    size = 1; }

    apply {
        forward_ipv4.apply();
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();               
            
            tb_src.apply();
            tb_hslot.apply();
            tb_hpair.apply();
            tb_split.apply();
            tbl_mask.apply();
            
            tb_bmr.apply();
            tb_bmc.apply(); tb_bmc2.apply();
            tb_srcr.apply();
            tb_cmp.apply();
            
            
            if (meta.key_eq == 32w0) { tb_lam_add.apply(); }
            else { tb_lam_claim.apply(); }
            
            
            if (meta.alerted == 0) {
                if (meta.bm_masked == 32w0) {
                    if (meta.lam_now >= (bit<16>)ETA1_Q) {
                        tb_dg.apply();
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

Pipeline(TrwParser(), Ingress(), TrwDeparser(),
         EgressParser(), Egress(), EgressDeparser()) pipe;

Switch(pipe) main;
