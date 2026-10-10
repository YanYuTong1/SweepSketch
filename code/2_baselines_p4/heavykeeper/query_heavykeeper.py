
import sys
import time


ROWS = 3
W = 16384                        
K = 512                          
MAX_INDEX = W
SHOW_TOP = 20
WRITE = True

for arg in sys.argv[1:]:
    if arg.startswith("--max-index="):
        MAX_INDEX = min(int(arg.split("=")[1]), W)
    elif arg.startswith("--top-k="):
        K = int(arg.split("=")[1])
    elif arg.startswith("--show-top="):
        SHOW_TOP = int(arg.split("=")[1])
    elif arg == "--no-write":
        WRITE = False
    else:
        print(f"unknown argument: {arg}(ignored)")


try:
    p4 = bfrt.heavykeeper.pipe.Ingress
except NameError:
    print("Error: bfrt unavailable. This script must run inside bfshell.")
    print("Usage: $SDE_DIR/run_bfshell.sh -b query_heavykeeper.py [--max-index N]")
    sys.exit(1)



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


def reg_scan(name, n_indices):
    
    tbl = getattr(p4, name)
    out = {}
    for i in range(n_indices):
        try:
            r = tbl.get(REGISTER_INDEX=i, from_hw=True, print_ents=False)
            out[i] = _extract_value(r)
        except Exception:
            out[i] = 0
        if i % 2048 == 0:
            print(f"    {name}: {i}/{n_indices}", flush=True)
    return out



print("=" * 72)
print(f" HeavyKeeper data-plane query (max_index={MAX_INDEX}, top-k={K})")
print("=" * 72)

t0 = time.time()


print("[read registers] per-index .get(from_hw=True) + max across pipes ...")
fp = {}
cnt = {}
for r in range(ROWS):
    fp[r] = reg_scan("fp_r%d" % r, MAX_INDEX)
    cnt[r] = reg_scan("cnt_r%d" % r, MAX_INDEX)
print(f"  register read done, elapsed {time.time() - t0:.0f}s")


print("[aggregate] per /24 key, take the max cnt over 3 rows ...")
agg = {}                          
for i in range(MAX_INDEX):
    for r in range(ROWS):
        k = fp[r].get(i, 0)
        if k:                     
            c = cnt[r].get(i, 0)
            if c > agg.get(k, 0):
                agg[k] = c
print(f"  aggregated non-zero buckets: {len(agg)} /24 keys")


top = sorted(agg.items(), key=lambda kv: -kv[1])[:K]
hmin = top[K - 1][1] if len(top) >= K else 0   
print(f"  top-{K}: actual {len(top)}  keys; hmin = {hmin}")

if WRITE:
    print("[write-back] rewrite heap_keys + hmin_reg ...")
    p4.heap_keys.clear()
    for k, c in top:
        
        p4.heap_keys.add_with_set_in_heap(key24=k)
    p4.hmin_reg.mod(REGISTER_INDEX=0, f1=hmin)   
    print(f"  ✓ heap_keys: {len(top)} entries rewritten; hmin_reg = {hmin}")
else:
    print("[--no-write] skip heap write-back (dry run)")


print()
print(f"{'rank':>4} {'/24 keys':>18} {'cnt':>8}")
print("-" * 34)
for i, (k, c) in enumerate(top[:SHOW_TOP]):
    ip = f"{(k >> 24) & 0xFF}.{(k >> 16) & 0xFF}.{(k >> 8) & 0xFF}.0"
    print(f"{i + 1:>4} {ip:>18} {c:>8}")

print()
print(f"query done, elapsed {time.time() - t0:.0f}s.")














