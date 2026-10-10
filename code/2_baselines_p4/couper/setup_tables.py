
import sys

COUPER_T = 12   

try:
    p4 = bfrt.couper.pipe.Ingress
except NameError:
    print("must run inside bfshell: $SDE_DIR/run_bfshell.sh -b setup_tables.py")
    sys.exit(1)

DEV_PORT_MAP = {392: 400, 400: 392}

def popcount8(c):
    return bin(c).count("1")

print("[1/13] forward_ipv4 (port forwarding) ...")
for ingress_port, egress_port in DEV_PORT_MAP.items():
    added = False
    for key_name in ("ingress_port", "ig_intr_md.ingress_port", "ig_intr_md_ingress_port"):
        if added:
            break
        try:
            p4.forward_ipv4.add_with_set_egr(**{key_name: ingress_port}, egr_port=egress_port)
            added = True
            print("  ✓ ingress {} → egress {} (key={})".format(ingress_port, egress_port, key_name))
        except Exception as e:
            if "exists" in str(e).lower():
                added = True
                print("  ✓ ingress {} → egress {} (already exists)".format(ingress_port, egress_port))

print("[2/13] pc_hi / pc_lo (256 entries each) ...")
for c in range(256):
    pc = popcount8(c)
    p4.pc_hi.add_with_act_pc_hi(m_hi=c, pc_v=pc)
    p4.pc_lo.add_with_act_pc_lo(m_lo=c, pc_v=pc)

print("[3/13] q_mask (the 16 entries with l1_path=1) ...")
for q in range(16):
    p4.q_mask.add_with_act_qmask(l1_path=1, q=q, m=(1 << q))

print("[4/13] tb_pcgate (17×17 = 289 entries) ...")
for hi in range(17):
    for lo in range(17):
        v = 1 if (hi + lo) < COUPER_T else 0
        p4.tb_pcgate.add_with_act_pcgate(pc_hi_v=hi, pc_lo_v=lo, v=v)

print("[5/13] tb_rb1 / tb_rb2 (2 entries each) ...")
p4.tb_rb1.add_with_do_rb1_lo(sel_c1=0)
p4.tb_rb1.add_with_do_rb1_hi(sel_c1=1)
p4.tb_rb2.add_with_do_rb2_lo(sel_c2=0)
p4.tb_rb2.add_with_do_rb2_hi(sel_c2=1)

print("[6/13] tb_bw1 / tb_bw2 (2 entries each, l1_path=1) ...")
p4.tb_bw1.add_with_do_bw1_lo(l1_path=1, sel_c1=0)
p4.tb_bw1.add_with_do_bw1_hi(l1_path=1, sel_c1=1)
p4.tb_bw2.add_with_do_bw2_lo(l1_path=1, sel_c2=0)
p4.tb_bw2.add_with_do_bw2_hi(l1_path=1, sel_c2=1)

print("[7/13] tb_hll1 / tb_hll2 (2 entries each, l1_path=0) ...")
p4.tb_hll1.add_with_do_hll1_lo(l1_path=0, sel_g1=0)
p4.tb_hll1.add_with_do_hll1_hi(l1_path=0, sel_g1=1)
p4.tb_hll2.add_with_do_hll2_lo(l1_path=0, sel_g2=0)
p4.tb_hll2.add_with_do_hll2_hi(l1_path=0, sel_g2=1)

print("[8/13] tb_upd1 / tb_upd2 (2 entries each, l1_path=0) ...")
p4.tb_upd1.add_with_do_upd1_0(l1_path=0, upd1_ok=0)
p4.tb_upd1.add_with_do_upd1_1(l1_path=0, upd1_ok=1)
p4.tb_upd2.add_with_do_upd2_0(l1_path=0, upd2_ok=0)
p4.tb_upd2.add_with_do_upd2_1(l1_path=0, upd2_ok=1)

print("[9/13] tb_dg1w / tb_dg2w (1 entry each, l1_path=0) ...")
p4.tb_dg1w.add_with_do_dg1w(l1_path=0)
p4.tb_dg2w.add_with_do_dg2w(l1_path=0)

print("[10/13] tb_lam (2 entries) ...")
p4.tb_lam.add_with_do_lam1(lam1_le=1)
p4.tb_lam.add_with_do_lam2(lam1_le=0)

print("[11/13] tb_tscdec (4 entries; first-match = elif semantics) ...")
p4.tb_tscdec.add_with_do_tscdec_a(fi_ok=1, fj_ok=0)
p4.tb_tscdec.add_with_do_tscdec_a(fi_ok=1, fj_ok=1)
p4.tb_tscdec.add_with_do_tscdec_b(fi_ok=0, fj_ok=1)
p4.tb_tscdec.add_with_do_tscdec_c(fi_ok=0, fj_ok=0)

print("[12/13] tb_dec2 (need_dig=1 8 entries; on ties the lowest i wins) ...")
p4.tb_dec2.add_with_a_dec2_i_w1(need_dig=1, di_le=1, di_lam=1, dj_lam=0)
p4.tb_dec2.add_with_a_dec2_i_w1(need_dig=1, di_le=1, di_lam=1, dj_lam=1)
p4.tb_dec2.add_with_a_dec2_i_w0(need_dig=1, di_le=1, di_lam=0, dj_lam=0)
p4.tb_dec2.add_with_a_dec2_i_w0(need_dig=1, di_le=1, di_lam=0, dj_lam=1)
p4.tb_dec2.add_with_a_dec2_j_w1(need_dig=1, di_le=0, di_lam=0, dj_lam=1)
p4.tb_dec2.add_with_a_dec2_j_w1(need_dig=1, di_le=0, di_lam=1, dj_lam=1)
p4.tb_dec2.add_with_a_dec2_j_w0(need_dig=1, di_le=0, di_lam=0, dj_lam=0)
p4.tb_dec2.add_with_a_dec2_j_w0(need_dig=1, di_le=0, di_lam=1, dj_lam=0)

print("[13/13] tb_fw / tb_dw (1 entry each: l1_path=0, tsc_wr=1) ...")
p4.tb_fw.add_with_do_fw(l1_path=0, tsc_wr=1)
p4.tb_dw.add_with_do_dw(l1_path=0, tsc_wr=1)

print()
print("setup_tables done: forward 2 + pc 512 + qmask 16 + pcgate 289 + rb 4 + "
      "bw 4 + hll 4 + upd 4 + dg 2 + lam 2 + tscdec 4 + dec2 8 + fw/dw 2 = 853 entries")
