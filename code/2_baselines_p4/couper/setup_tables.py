import sys
COUPER_T = 12
try:
    p4 = bfrt.couper.pipe.Ingress
except NameError:
    pass
    sys.exit(1)
DEV_PORT_MAP = {392: 400, 400: 392}

def popcount8(c):
    return bin(c).count('1')
pass
for ingress_port, egress_port in DEV_PORT_MAP.items():
    added = False
    for key_name in ('ingress_port', 'ig_intr_md.ingress_port', 'ig_intr_md_ingress_port'):
        if added:
            break
        try:
            p4.forward_ipv4.add_with_set_egr(**{key_name: ingress_port}, egr_port=egress_port)
            added = True
            pass
        except Exception as e:
            if 'exists' in str(e).lower():
                added = True
                pass
pass
for c in range(256):
    pc = popcount8(c)
    p4.pc_hi.add_with_act_pc_hi(m_hi=c, pc_v=pc)
    p4.pc_lo.add_with_act_pc_lo(m_lo=c, pc_v=pc)
pass
for q in range(16):
    p4.q_mask.add_with_act_qmask(l1_path=1, q=q, m=1 << q)
pass
for hi in range(17):
    for lo in range(17):
        v = 1 if hi + lo < COUPER_T else 0
        p4.tb_pcgate.add_with_act_pcgate(pc_hi_v=hi, pc_lo_v=lo, v=v)
pass
p4.tb_rb1.add_with_do_rb1_lo(sel_c1=0)
p4.tb_rb1.add_with_do_rb1_hi(sel_c1=1)
p4.tb_rb2.add_with_do_rb2_lo(sel_c2=0)
p4.tb_rb2.add_with_do_rb2_hi(sel_c2=1)
pass
p4.tb_bw1.add_with_do_bw1_lo(l1_path=1, sel_c1=0)
p4.tb_bw1.add_with_do_bw1_hi(l1_path=1, sel_c1=1)
p4.tb_bw2.add_with_do_bw2_lo(l1_path=1, sel_c2=0)
p4.tb_bw2.add_with_do_bw2_hi(l1_path=1, sel_c2=1)
pass
p4.tb_hll1.add_with_do_hll1_lo(l1_path=0, sel_g1=0)
p4.tb_hll1.add_with_do_hll1_hi(l1_path=0, sel_g1=1)
p4.tb_hll2.add_with_do_hll2_lo(l1_path=0, sel_g2=0)
p4.tb_hll2.add_with_do_hll2_hi(l1_path=0, sel_g2=1)
pass
p4.tb_upd1.add_with_do_upd1_0(l1_path=0, upd1_ok=0)
p4.tb_upd1.add_with_do_upd1_1(l1_path=0, upd1_ok=1)
p4.tb_upd2.add_with_do_upd2_0(l1_path=0, upd2_ok=0)
p4.tb_upd2.add_with_do_upd2_1(l1_path=0, upd2_ok=1)
pass
p4.tb_dg1w.add_with_do_dg1w(l1_path=0)
p4.tb_dg2w.add_with_do_dg2w(l1_path=0)
pass
p4.tb_lam.add_with_do_lam1(lam1_le=1)
p4.tb_lam.add_with_do_lam2(lam1_le=0)
pass
p4.tb_tscdec.add_with_do_tscdec_a(fi_ok=1, fj_ok=0)
p4.tb_tscdec.add_with_do_tscdec_a(fi_ok=1, fj_ok=1)
p4.tb_tscdec.add_with_do_tscdec_b(fi_ok=0, fj_ok=1)
p4.tb_tscdec.add_with_do_tscdec_c(fi_ok=0, fj_ok=0)
pass
p4.tb_dec2.add_with_a_dec2_i_w1(need_dig=1, di_le=1, di_lam=1, dj_lam=0)
p4.tb_dec2.add_with_a_dec2_i_w1(need_dig=1, di_le=1, di_lam=1, dj_lam=1)
p4.tb_dec2.add_with_a_dec2_i_w0(need_dig=1, di_le=1, di_lam=0, dj_lam=0)
p4.tb_dec2.add_with_a_dec2_i_w0(need_dig=1, di_le=1, di_lam=0, dj_lam=1)
p4.tb_dec2.add_with_a_dec2_j_w1(need_dig=1, di_le=0, di_lam=0, dj_lam=1)
p4.tb_dec2.add_with_a_dec2_j_w1(need_dig=1, di_le=0, di_lam=1, dj_lam=1)
p4.tb_dec2.add_with_a_dec2_j_w0(need_dig=1, di_le=0, di_lam=0, dj_lam=0)
p4.tb_dec2.add_with_a_dec2_j_w0(need_dig=1, di_le=0, di_lam=1, dj_lam=0)
pass
p4.tb_fw.add_with_do_fw(l1_path=0, tsc_wr=1)
p4.tb_dw.add_with_do_dw(l1_path=0, tsc_wr=1)
print()
pass
