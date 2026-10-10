
import math
import sys




ROWS      = 4        
W         = 1024     
BM_WORDS  = 16       
M         = 512      
THRESHOLD = 1000     
MODE      = "resident"   
READ_ALL_BM = False      


def _arg(name, conv=int):
    
    for a in sys.argv[1:]:
        if a.startswith(name + "="):
            return conv(a.split("=", 1)[1])
    return globals()[name]


ROWS       = _arg("ROWS")
W          = _arg("W")
BM_WORDS   = _arg("BM_WORDS")
M          = _arg("M")
THRESHOLD  = _arg("THRESHOLD")
MODE       = _arg("MODE", str)
READ_ALL_BM = bool(_arg("READ_ALL_BM", int))

BM_TOTAL = W * BM_WORDS   




try:
    p4 = bfrt.spreadsketch.pipe.Ingress
except NameError:
    print("Error: bfrt unavailable. This script must run inside bfshell.")
    sys.exit(1)

REG_NAMES = {
    "key": [f"key_r{i}" for i in range(ROWS)],
    "lvl": [f"lvl_r{i}" for i in range(ROWS)],
    "bm":  [f"bm_r{i}"  for i in range(ROWS)],
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


def reg_get(name, idx):
    
    try:
        r = getattr(p4, name).get(REGISTER_INDEX=idx, from_hw=True, print_ents=False)
        return _extract_value(r)
    except Exception:
        return 0


def reg_dump(name, n_indices, progress=None):
    
    out = {}
    for i in range(n_indices):
        out[i] = reg_get(name, i)
        if progress and (i + 1) % progress == 0:
            print(f"    {name}: {i + 1}/{n_indices}", file=sys.stderr)
    return out





def lc_estimate(ones):
    z = M - ones
    if z <= 0:
        z = 1
    return M * math.log(M / z)


def assemble_and_popcount(bm_dict_row, bucket):
    
    base = bucket * BM_WORDS
    ones = 0
    for w in range(BM_WORDS):
        word = bm_dict_row.get(base + w, 0) & 0xFFFFFFFF
        ones += bin(word).count("1")
    return ones





def _crc32_t2na(data_bytes):
    
    crc = 0xFFFFFFFF
    for byte in data_bytes:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xEDB88320 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def _row_bucket(k, i):
    
    salt = 0x6600 + i
    data = salt.to_bytes(2, "big") + (k & 0xFFFFFFFF).to_bytes(4, "big")
    return _crc32_t2na(data) & 0x3FF





print("=" * 72)
print(f" SpreadSketch data-plane query  (d={ROWS} × w={W} × m={M}, MODE={MODE})")
print("=" * 72)


print("[read registers 1/2] key/lvl (per-slot get + max across pipes)...")
state = {"key": [], "lvl": [], "bm": []}
for i in range(ROWS):
    state["key"].append(reg_dump(REG_NAMES["key"][i], W, progress=256))
    state["lvl"].append(reg_dump(REG_NAMES["lvl"][i], W, progress=256))


print("[read registers 2/2] bm bitmap...")
nonzero_buckets = [
    {b for b in range(W) if state["key"][i].get(b, 0) != 0}
    for i in range(ROWS)
]
if READ_ALL_BM:
    for i in range(ROWS):
        state["bm"].append(reg_dump(REG_NAMES["bm"][i], BM_TOTAL, progress=2048))
        print(f"  ✓ bm_r{i}: full {BM_TOTAL} slots read")
else:
    for i in range(ROWS):
        d = {}
        nb = nonzero_buckets[i]
        for j, b in enumerate(sorted(nb)):
            for w in range(BM_WORDS):
                d[b * BM_WORDS + w] = reg_get(REG_NAMES["bm"][i], b * BM_WORDS + w)
            if (j + 1) % 32 == 0:
                print(f"    bm_r{i}: {j + 1}/{len(nb)} buckets", file=sys.stderr)
        state["bm"].append(d)
        print(f"  ✓ bm_r{i}: {len(nb)}  non-zero key buckets' bitmaps read ({len(nb)*BM_WORDS} slots)")


print()
print("=" * 72)
print(" per-row non-zero bucket analysis (LC: n̂ = m·ln(m/z))")
print("=" * 72)
print(f"{'row':>3} {'col':>5} {'src_key':>15} {'lvl':>4} {'set_bits':>9} {'n_hat':>10}")
print("-" * 72)

est = [[0.0] * W for _ in range(ROWS)]   
key_bucket = [{} for _ in range(ROWS)]   
for i in range(ROWS):
    for b in nonzero_buckets[i]:
        key = state["key"][i].get(b, 0)
        lvl = state["lvl"][i].get(b, 0)
        ones = assemble_and_popcount(state["bm"][i], b)
        n_hat = lc_estimate(ones)
        est[i][b] = n_hat
        key_bucket[i][key] = b
        ip_str = f"{(key>>24)&0xff}.{(key>>16)&0xff}.{(key>>8)&0xff}.{key&0xff}"
        print(f"{i:>3} {b:>5} {ip_str:>15} {lvl:>4} {ones:>9} {n_hat:>10.2f}")

n_nonempty = sum(len(nb) for nb in nonzero_buckets)
print("-" * 72)
print(f" non-empty buckets total: {n_nonempty} / {ROWS * W}")


print()
print("=" * 72)
print(f" PointQuery (min LC over rows, threshold = {THRESHOLD})")
print("=" * 72)

keys = set()
for i in range(ROWS):
    keys |= {v for v in state["key"][i].values() if v != 0}

hits = []
for k in sorted(keys):
    row_ests = []
    for i in range(ROWS):
        b = key_bucket[i].get(k)
        if b is not None:
            row_ests.append(est[i][b])
        elif MODE == "crc32":
            b = _row_bucket(k, i)            
            row_ests.append(est[i][b] if b < W else 0.0)
        
    if not row_ests:
        continue
    n_min = min(row_ests)
    if n_min >= THRESHOLD:
        hits.append((k, n_min, len(row_ests)))

if not hits:
    print("  (no superspreader)")
else:
    hits.sort(key=lambda x: -x[1])
    for k, n_min, n_rows in hits:
        ip = f"{(k>>24)&0xff}.{(k>>16)&0xff}.{(k>>8)&0xff}.{k&0xff}"
        tag = "" if n_rows == ROWS else f"  [only {n_rows}row residency]"
        print(f"  [SUPER] {ip:>15}  n_min = {n_min:>10.2f}{tag}")

print()
print("Query done.")
