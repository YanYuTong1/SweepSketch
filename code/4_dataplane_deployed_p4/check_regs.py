import sys
try:
    p4 = bfrt.sweepsketch.pipe.Ingress
except NameError:
    pass
    sys.exit(1)

def read_reg(tbl, n=8192):
    total = 0
    nonzero = []
    for i in range(n):
        if i % 1024 == 0:
            pass
        try:
            r = tbl.get(REGISTER_INDEX=i, from_hw=True, print_ents=False)
            d = r.data if hasattr(r, 'data') else r if isinstance(r, dict) else {}
        except Exception:
            d = {}
        for k, v in d.items():
            if isinstance(v, list) and len(v) > 3:
                val = int(v[3])
            elif isinstance(v, list) and v:
                val = max((int(x) for x in v))
            elif isinstance(v, int):
                val = int(v)
            else:
                val = 0
            if val:
                total += val
                nonzero.append((i, val))
    return (total, nonzero)
for name in ('l1_pkt', 'l1_nn', 'l1_key', 'l1_C'):
    print('=' * 60)
    pass
    tbl = getattr(p4, name)
    total, nonzero = read_reg(tbl)
    pass
    pass
    for i, v in nonzero[:20]:
        print('    idx={} cnt={}'.format(i, v))
print('=' * 60)
