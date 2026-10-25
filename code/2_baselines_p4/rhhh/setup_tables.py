import sys
import bfrt_grpc.client as gc
try:
    p4 = bfrt.rhhh.pipe.Ingress
except NameError:
    pass
    pass
    sys.exit(1)
DEV_PORT_MAP = {392: 400, 400: 392}
pass
for tname in ('tbl_mask', 'forward_ipv4'):
    try:
        getattr(p4, tname).clear()
        pass
    except Exception as e:
        pass
pass
for lv, mask in ((0, 4294967295), (1, 4294967040), (2, 4294901760), (3, 4278190080)):
    p4.tbl_mask.entry_add(p4.tbl_mask.make_key([gc.KeyTuple('$MATCH_PRIORITY', 0), gc.KeyTuple('lv', lv, 3)]), p4.tbl_mask.make_data([gc.DataTuple('m', mask)], 'act_mask'))
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
try:
    resp = p4.tbl_mask.dump()
    pass
except Exception as e:
    pass
pass
pass
