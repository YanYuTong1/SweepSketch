import sys
import bfrt_grpc.client as gc
try:
    p4 = bfrt.spreadsketch.pipe.Ingress
except NameError:
    pass
    pass
    sys.exit(1)
DEV_PORT_MAP = {392: 400, 400: 392}
pass
for tname in ('tz_tcam', 'tbl_mask', 'forward_ipv4'):
    try:
        getattr(p4, tname).clear()
        pass
    except Exception as e:
        pass
pass
tbl = p4.tz_tcam
for i in range(32):

    def _seg(i, lo, hi):
        if i < lo:
            return (0, 0)
        if i >= hi - 1:
            full = (1 << hi - lo) - 1
            return (full, full)
        pat = (1 << i - lo + 1) - 1
        return (pat, pat)
    v0, m0 = _seg(i, 0, 8)
    v1, m1 = _seg(i, 8, 16)
    v2, m2 = _seg(i, 16, 24)
    v3, m3 = _seg(i, 24, 32)
    tbl.entry_add(tbl.make_key([gc.KeyTuple('$MATCH_PRIORITY', i), gc.KeyTuple('b0', v0, m0), gc.KeyTuple('b1', v1, m1), gc.KeyTuple('b2', v2, m2), gc.KeyTuple('b3', v3, m3)]), tbl.make_data([gc.DataTuple('lvl_v', i + 2)], 'act_lvl_tc'))
pass
pass
for b in range(32):
    p4.tbl_mask.add_with_act_mask(bit_idx=b, m=1 << b)
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
pass
