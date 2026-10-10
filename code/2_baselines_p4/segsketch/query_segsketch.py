

import sys
import math




THRESHOLD     = 100
ROWS          = 3
COLS          = 64
HOST_BM_WORDS = 8           
HOST_BM_BITS  = 256
HBM_TOTAL     = COLS * HOST_BM_WORDS   
SHOW_ZEROES   = False




try:
    p4 = bfrt.SegSketch.pipe.Ingress
except NameError:
    print("Error: bfrt unavailable. This script must run inside bfshell.")
    sys.exit(1)

REG_NAMES = {
    "key": ["bucket_key0", "bucket_key1", "bucket_key2"],
    "sbm": ["subnet_bm0",  "subnet_bm1",  "subnet_bm2"],
    "cnt": ["bucket_cnt0", "bucket_cnt1", "bucket_cnt2"],
    "hbm": ["host_bm0",    "host_bm1",    "host_bm2"],
}





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


def reg_dump(name, n_indices):
    
    tbl = getattr(p4, name)
    out = {}
    for i in range(n_indices):
        try:
            r = tbl.get(REGISTER_INDEX=i, from_hw=True, print_ents=False)
            out[i] = _extract_value(r)
        except Exception as e:
            out[i] = 0
    return out


print("=" * 72)
print(" SegSketch data-plane query")
print("=" * 72)





print("[read registers] reading 12 registers (one get each; ~15s)...")
state = {}
for kind, names in REG_NAMES.items():
    state[kind] = []
    for n in names:
        n_idx = HBM_TOTAL if kind == "hbm" else COLS
        d = reg_dump(n, n_idx)
        state[kind].append(d)
        nz = sum(1 for v in d.values() if v != 0)
        print(f"  ✓ {n:14s}  non-zero entries = {nz:>3} / {len(d)}")





def linear_count(host_bm_256bit):
    z = 256 - bin(host_bm_256bit).count("1")
    if z == 0:
        return float("inf")
    if z == 256:
        return 0.0
    return -256.0 * math.log(z / 256.0)


def assemble_host_bm(row, col):
    bm = 0
    base = col * HOST_BM_WORDS
    hbm_dict = state["hbm"][row]
    for w in range(HOST_BM_WORDS):
        word = hbm_dict.get(base + w, 0) & 0xFFFFFFFF
        bm |= (word << (w * 32))
    return bm






print()
print("=" * 72)
print(f" per-row non-zero bucket analysis  (m={HOST_BM_BITS}, threshold={THRESHOLD})")
print("=" * 72)
print(f"{'row':>3} {'col':>3} {'src_key':>15} {'sbm':>6} {'pkt_cnt':>8} {'set_bits':>9} {'n_hat':>10}")
print("-" * 72)

est = {}
nonempty = 0
for r in range(ROWS):
    for c in range(COLS):
        key = state["key"][r].get(c, 0)
        sbm = state["sbm"][r].get(c, 0)
        cnt = state["cnt"][r].get(c, 0)
        if key == 0 and cnt == 0 and sbm == 0:
            if not SHOW_ZEROES:
                continue
        bm256    = assemble_host_bm(r, c)
        set_bits = bin(bm256).count("1")
        n_hat    = linear_count(bm256)
        ip_str   = f"{(key>>24)&0xff}.{(key>>16)&0xff}.{(key>>8)&0xff}.{key&0xff}"
        n_str    = f"{n_hat:.2f}" if n_hat != float("inf") else "INF"
        print(f"{r:>3} {c:>3} {ip_str:>15} 0x{sbm:04X} {cnt:>8} {set_bits:>9} {n_str:>10}")
        nonempty += 1
        est.setdefault(key, {})[r] = n_hat

print("-" * 72)
print(f" non-empty buckets total: {nonempty} / {ROWS * COLS}")





print()
print("=" * 72)
print(f" superspreader detection (cardinality ≥ {THRESHOLD})")
print("=" * 72)
hits = []
for key, rowmap in est.items():
    if key == 0:
        continue
    if len(rowmap) < ROWS:
        continue
    n_min = min(rowmap.values())
    if n_min >= THRESHOLD:
        hits.append((key, n_min, rowmap))

if not hits:
    print("  (no superspreader)")
else:
    hits.sort(key=lambda x: -x[1])
    for key, n_min, rowmap in hits:
        ip = f"{(key>>24)&0xff}.{(key>>16)&0xff}.{(key>>8)&0xff}.{key&0xff}"
        per_row = " ".join(f"r{r}={v:.1f}" for r, v in sorted(rowmap.items()))
        print(f"  [SUPER] {ip:>15}  n_min = {n_min:>8.2f}   ({per_row})")

print()
print("Query done.")
