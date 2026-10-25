import sys
try:
    p4 = bfrt.mrb.pipe.Ingress
except NameError:
    pass
    pass
    sys.exit(1)
DEV_PORT_MAP = {392: 400, 400: 392}
pass
TABLES_TO_CLEAR = ['tbl_mask', 'forward_ipv4']
for tname in TABLES_TO_CLEAR:
    try:
        getattr(p4, tname).clear()
        pass
    except Exception as e:
        pass
pass
for b in range(32):
    p4.tbl_mask.add_with_act_mask(mask_key=b, m=1 << b)
pass
pass
for ingress_port, egress_port in DEV_PORT_MAP.items():
    added = False
    for key_name in ('ingress_port', 'ig_intr_md.ingress_port', 'ig_intr_md_ingress_port'):
        if added:
            break
        try:
            p4.forward_ipv4.add_with_set_egr(**{key_name: ingress_port}, port=egress_port)
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
            p4.forward_ipv4.get(**{key_name: ingress_port}, print_ents=False)
            found = True
            pass
            break
        except Exception:
            continue
    if not found:
        pass
pass
