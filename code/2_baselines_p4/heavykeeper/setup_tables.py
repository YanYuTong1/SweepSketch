import math
import sys
try:
    p4 = bfrt.heavykeeper.pipe.Ingress
except NameError:
    pass
    sys.exit(1)
ROWS = 3
W = 16384
DECAY = 1.0 / 1.08
DEV_PORT_MAP = {392: 400, 400: 392}
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
for r in range(ROWS):
    tbl = getattr(p4, 'thr_tbl%d' % r)
    try:
        tbl.clear()
    except Exception as e:
        pass
    key_name = 'c8_r%d' % r
    act_name = 'act_thr%d' % r
    for c in range(256):
        thr = min(int(math.floor(2 ** 32 * DECAY ** c)), 4294967295)
        add_fn = getattr(tbl, 'add_with_%s' % act_name)
        add_fn(**{key_name: c}, t=thr)
    pass
pass
try:
    p4.heap_keys.clear()
    pass
except Exception as e:
    pass
try:
    p4.hmin_reg.mod(REGISTER_INDEX=0, f1=0)
    pass
except Exception as e:
    pass
if '--reset' in sys.argv:
    pass
    for r in range(ROWS):
        for kind in ('fp', 'cnt'):
            reg = getattr(p4, '%s_r%d' % (kind, r))
            for i in range(W):
                try:
                    reg.mod(REGISTER_INDEX=i, f1=0)
                except Exception:
                    pass
                if i % 4096 == 0:
                    print(f' {kind}_r{r}: {i}/{W}')
        pass
else:
    pass
pass
