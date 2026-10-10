
import sys

try:
    p4 = bfrt.sweepsketch.pipe.Ingress
except NameError:
    print("must run inside bfshell: $SDE_DIR/run_bfshell.sh -b check_regs.py")
    sys.exit(1)


def read_reg(tbl, n=8192):
    total = 0
    nonzero = []
    for i in range(n):
        if i % 1024 == 0:
            print("  reading bucket {}/{} ...".format(i, n))
        try:
            r = tbl.get(REGISTER_INDEX=i, from_hw=True, print_ents=False)
            d = r.data if hasattr(r, "data") else (r if isinstance(r, dict) else {})
        except Exception:
            d = {}
        
        for k, v in d.items():
            if isinstance(v, list) and len(v) > 3:
                
                val = int(v[3])
            elif isinstance(v, list) and v:
                val = max(int(x) for x in v)
            elif isinstance(v, int):
                val = int(v)
            else:
                val = 0
            if val:
                total += val
                nonzero.append((i, val))
    return total, nonzero


for name in ("l1_pkt", "l1_nn", "l1_key", "l1_C"):
    print("=" * 60)
    print("register {} :".format(name))
    tbl = getattr(p4, name)
    total, nonzero = read_reg(tbl)
    print("  non-zero buckets = {}".format(len(nonzero)))
    print("  bucket totals (pipe3) = {}  (pkt/nn/C should equal the injected packet count; key should be 0)".format(total))
    for i, v in nonzero[:20]:
        print("    idx={} cnt={}".format(i, v))
print("=" * 60)
