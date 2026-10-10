

import sys
import math




THETA     = float(sys.argv[1]) if len(sys.argv) > 1 else 100.0
IDX_START = int(sys.argv[2]) if len(sys.argv) > 2 else 0
IDX_END   = int(sys.argv[3]) if len(sys.argv) > 3 else 8192

N_LEVELS = 4
C        = 8192            
MASKS    = (0xFFFFFFFF, 0xFFFFFF00, 0xFFFF0000, 0xFF000000)   
PLENS    = (32, 24, 16, 8)
Z        = 4               
TOP_K    = 30              

PARTIAL = (IDX_START != 0) or (IDX_END != C)




try:
    p4 = bfrt.rhhh.pipe.Ingress
except NameError:
    print("Error: bfrt unavailable. This script must run inside bfshell.")
    print("Usage: $SDE_DIR/run_bfshell.sh -b query_rhhh.py [theta] [start] [end]")
    sys.exit(1)

KEY_REGS = ["key0", "key1", "key2", "key3"]
CNT_REGS = ["cnt0", "cnt1", "cnt2", "cnt3"]
BASE_REGS = ["base0", "base1", "base2", "base3"]





def _extract_value(resp):
    
    try:
        d = resp.data
    except AttributeError:
        d = resp if isinstance(resp, dict) else {}

    best = 0
    for k, v in d.items():
        if isinstance(v, list):
            for item in v:
                if isinstance(item, int):
                    best = max(best, int(item) & 0xFFFFFFFF)
        elif isinstance(v, int):
            best = max(best, int(v) & 0xFFFFFFFF)
    return best


def reg_dump(name, n_indices, start=0):
    
    tbl = getattr(p4, name)
    out = {}
    for i in range(start, n_indices):
        try:
            r = tbl.get(REGISTER_INDEX=i, from_hw=True, print_ents=False)
            out[i] = _extract_value(r)
        except Exception:
            out[i] = 0
    return out


print("=" * 72)
print(f" RHHH data-plane query  (theta={THETA}, slot range [{IDX_START}, {IDX_END}))")
if PARTIAL:
    print(" ⚠ partial scan: report/entity scores cover only thisslotrange and are incomplete")
print("=" * 72)




print("[read registers] base×4 + key/cnt×8×%d (one get each; a full run takes ~20–40 min)..."
      % (IDX_END - IDX_START))

base = [0] * N_LEVELS
for i in range(N_LEVELS):
    base[i] = reg_dump(BASE_REGS[i], 1).get(0, 0)

keys = []
cnts = []
for i in range(N_LEVELS):
    keys.append(reg_dump(KEY_REGS[i], IDX_END, IDX_START))
    cnts.append(reg_dump(CNT_REGS[i], IDX_END, IDX_START))
    print(f"  ✓ layer {i} (/{(32 - 8*i):2d})  read done  base={base[i]}")





levels = [dict() for _ in range(N_LEVELS)]
occupied = [0] * N_LEVELS
for i in range(N_LEVELS):
    for s in range(IDX_START, IDX_END):
        k = keys[i].get(s, 0)
        c = cnts[i].get(s, 0)
        if k == 0 and c == 0:
            continue                    
        item = k if k != 0 else 0       
        levels[i][item] = c
        occupied[i] += 1

print()
print("=" * 72)
print(" slot occupancy statistics (evidence of direct-mapped slots vs Python dict collision noise)")
print("=" * 72)
for i in range(N_LEVELS):
    n = IDX_END - IDX_START
    print(f"  layer{i} (/{(32 - 8*i):2d}): non-empty slots {occupied[i]:>4} / {n}  "
          f"occupancy {occupied[i] * 100.0 / n:.2f}%  base={base[i]}")




def _report(levels, base, theta):
    
    adj = theta / 4.0
    child_sum = [dict() for _ in range(N_LEVELS)]
    reported = []
    for i in range(N_LEVELS):
        for item, c in levels[i].items():
            eff = c - base[i]
            s = child_sum[i].get(item, 0.0)
            if eff - s + 2 * Z * math.sqrt(max(2 * eff, 0.0)) >= adj:
                lower = max(0.0, eff - base[i])      
                reported.append((i, item, eff, lower))
                if i + 1 < N_LEVELS:
                    p = item & MASKS[i + 1]
                    child_sum[i + 1][p] = child_sum[i + 1].get(p, 0.0) + lower
    return reported


def fmt_ip(x):
    return "%d.%d.%d.%d" % ((x >> 24) & 0xFF, (x >> 16) & 0xFF,
                            (x >> 8) & 0xFF, x & 0xFF)


print()
print("=" * 72)
print(f" hierarchy report ({N_LEVELS} layers, z={Z}, criterion count−s+2z√(2·count) ≥ {THETA}/4)")
print("=" * 72)
reported = _report(levels, base, THETA)
if not reported:
    print("  (no hits)")
else:
    reported.sort(key=lambda r: (-r[2], r[0]))    
    print(f"{'layer':>2} {'prefix':>16} {'item':>15} {'eff':>10} {'lower':>10} {'c(absolute)':>10}")
    print("-" * 72)
    for i, item, eff, lower in reported:
        pref = "%s/%d" % (fmt_ip(item & MASKS[i]), PLENS[i])
        print(f"{i:>2} {pref:>16} {fmt_ip(item):>15} {eff:>10} {lower:>10.1f} "
              f"{levels[i].get(item, 0):>10}")




print()
print("=" * 72)
print(f" entity-level scores (/24-level eff, Python RHHH.query() convention) — Top {TOP_K}")
print("=" * 72)
scores = [(item, c - base[1]) for item, c in levels[1].items()]
scores.sort(key=lambda x: -x[1])
if not scores:
    print("  (no entities)")
else:
    for item, eff in scores[:TOP_K]:
        print(f"  {fmt_ip(item):>15} /24 eff = {eff}")

print()
print("Query done.")
