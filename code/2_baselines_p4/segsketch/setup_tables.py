import sys
try:
    p4 = bfrt.SegSketch.pipe.Ingress
except NameError:
    pass
    pass
    sys.exit(1)
DEV_PORT_MAP = {392: 400, 400: 392}
pass
TABLES_TO_CLEAR = ['tbl_mask1', 'tbl_mask2', 'tbl_mask3', 'tbl_hmask', 'forward_ipv4']
for tname in TABLES_TO_CLEAR:
    try:
        getattr(p4, tname).clear()
        pass
    except Exception as e:
        pass
pass
p4.tbl_mask1.add_with_act_m1(hash_s1=0, m=240)
p4.tbl_mask1.add_with_act_m1(hash_s1=1, m=15)
pass
pass
p4.tbl_mask2.add_with_act_m2(hash_s1=0, hash_s2=0, m=192)
p4.tbl_mask2.add_with_act_m2(hash_s1=0, hash_s2=1, m=48)
p4.tbl_mask2.add_with_act_m2(hash_s1=1, hash_s2=0, m=12)
p4.tbl_mask2.add_with_act_m2(hash_s1=1, hash_s2=1, m=3)
pass
pass
MASK3 = [(0, 0, 0, 128), (0, 0, 1, 64), (0, 1, 0, 32), (0, 1, 1, 16), (1, 0, 0, 8), (1, 0, 1, 4), (1, 1, 0, 2), (1, 1, 1, 1)]
for s1, s2, s3, m in MASK3:
    p4.tbl_mask3.add_with_act_m3(hash_s1=s1, hash_s2=s2, hash_s3=s3, m=m)
pass
pass
for b in range(32):
    p4.tbl_hmask.add_with_act_hmask(host_bm_bit=b, m=1 << b)
pass
pass
for ingress_port, egress_port in DEV_PORT_MAP.items():
    added = False
    for key_name in ('ingress_port', 'ig_intr_md.ingress_port', 'ig_intr_md_ingress_port'):
        if added:
            break
        try:
            p4.forward_ipv4.add_with_set_egr(**{key_name: ingress_port}, egr_port=egress_port)
            pass
            added = True
        except Exception as e:
            if 'exists' in str(e).lower():
                pass
                added = True
                break
    if not added:
        pass
pass
for ingress_port in DEV_PORT_MAP.keys():
    found = False
    for key_name in ('ingress_port', 'ig_intr_md.ingress_port', 'ig_intr_md_ingress_port'):
        try:
            resp = p4.forward_ipv4.get(**{key_name: ingress_port}, print_ents=False)
            found = True
            pass
            break
        except Exception:
            continue
    if not found:
        pass
pass
