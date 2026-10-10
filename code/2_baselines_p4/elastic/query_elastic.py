

import struct
import sys
import zlib


NB = 4096            
CELLS = 7            
LIGHT_N = 1 << 18    
SALT_BUCKET = 0x9100  
SALT_LIGHT = 0x9200   


def _crc_candidates(key32, salt16):
    
    s_le, s_be = struct.pack("<H", salt16), struct.pack(">H", salt16)
    k_le, k_be = struct.pack("<I", key32), struct.pack(">I", key32)
    return {
        "le_le": zlib.crc32(s_le + k_le) & 0xFFFFFFFF,
        "be_be": zlib.crc32(s_be + k_be) & 0xFFFFFFFF,
        "le_be": zlib.crc32(s_le + k_be) & 0xFFFFFFFF,
        "be_le": zlib.crc32(s_be + k_le) & 0xFFFFFFFF,
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


def _find_ingress():
    
    for name in ("elastic_rs", "elastic"):
        try:
            return getattr(bfrt, name).pipe.Ingress  # noqa: F821(bfshell  environment)
        except (NameError, AttributeError):
            continue
    return None


def _get_reg(tbl, idx):
    
    try:
        return _extract_value(tbl.get(REGISTER_INDEX=idx, from_hw=True,
                                      print_ents=False))  # noqa: F821
    except Exception:
        return 0


def parse_args(argv):
    d = {"bucket_range": (0, NB), "guard_range": (0, 0), "n_packets": 0,
         "threshold": None, "calibrate": False, "light_crc": "le_le",
         "topk": 0}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--bucket-range":
            lo, hi = argv[i + 1].split(":")
            d["bucket_range"] = (int(lo), int(hi))
            i += 2
        elif a == "--guard-range":
            lo, hi = argv[i + 1].split(":")
            d["guard_range"] = (int(lo), int(hi))
            i += 2
        elif a == "--n-packets":
            d["n_packets"] = int(argv[i + 1])
            i += 2
        elif a == "--threshold":
            d["threshold"] = float(argv[i + 1])
            i += 2
        elif a == "--calibrate":
            d["calibrate"] = True
            i += 1
        elif a == "--light-crc":
            d["light_crc"] = argv[i + 1]
            i += 2
        elif a == "--topk":
            d["topk"] = int(argv[i + 1])
            i += 2
        else:
            i += 1
    if d["threshold"] is None:
        d["threshold"] = 0.005 * d["n_packets"] if d["n_packets"] else 0.0
    return d


def main():
    p4 = _find_ingress()
    if p4 is None:
        print("Error: bfrt unavailable. This script must run inside bfshell.")
        print("Usage: $SDE_DIR/run_bfshell.sh -b query_elastic.py")
        sys.exit(1)

    args = parse_args(sys.argv[1:])
    b_lo, b_hi = args["bucket_range"]
    g_lo, g_hi = args["guard_range"]
    crc_name = args["light_crc"]

    cell_tbls = [getattr(p4, "cellc_%d" % i) for i in range(CELLS)]

    
    
    
    print("=" * 72)
    print(f" ElasticSketch data-plane query  bucket range [{b_lo}, {b_hi})")
    print("=" * 72)
    found = {}   
    calib = {k: 0 for k in ("le_le", "be_be", "le_be", "be_le")}
    n_cells = 0
    for b in range(b_lo, b_hi):
        for i in range(CELLS):
            v = _get_reg(cell_tbls[i], b)
            if v == 0:
                continue
            n_cells += 1
            key32 = (v >> 8) << 8          
            if key32 not in found:         
                found[key32] = {
                    "val": v & 0xFF,
                    "flag": (v >> 7) & 1,
                    "bucket": b,
                }
    print(f"non-empty cells = {n_cells}, dedup key = {len(found)}")

    
    
    crc_hits = dict(calib)
    for key32, info in found.items():
        for name, crc in _crc_candidates(key32, SALT_BUCKET).items():
            if crc % NB == info["bucket"]:
                crc_hits[name] += 1
    print("\n[CRC32 calibration] bucket-hash candidate hit statistics (observed bucket id vs candidate convention):")
    for name in ("le_le", "be_be", "le_be", "be_le"):
        print(f"  {name:6s} hits {crc_hits[name]:>5}/{len(found)}")
    best = max(crc_hits, key=crc_hits.get)
    if len(found) > 0 and crc_hits[best] == 0:
        print("  ⚠ no candidate matched: the data-plane CRC32 convention is not in the candidate set (fields may be"
              " container-aligned or bit-reversed). Light-part readings will be unreliable — recompute on the bfrt  side"
              " or check the p4c hash  documentation.")
    if args["calibrate"]:
        crc_name = best
        print(f"  calibration result: using {crc_name}(hits {crc_hits[best]}/{len(found)})")
    else:
        print(f"  not calibrated: use --light-crc= for the light part{crc_name}(TODO-verify, "
              f"run on hardware first: --calibrate)")

    
    light_tbl = getattr(p4, "light")
    scores = []
    for key32, info in found.items():
        cnt = info["val"] & 0x7F
        score = cnt
        if info["flag"]:
            pos = _crc_candidates(key32, SALT_LIGHT)[crc_name] % LIGHT_N
            score += _get_reg(light_tbl, pos)
        scores.append((key32, score, cnt, info["flag"], info["bucket"]))

    
    theta = args["threshold"]
    ip = lambda k: "%d.%d.%d.%d" % ((k >> 24) & 0xFF, (k >> 16) & 0xFF,
                                    (k >> 8) & 0xFF, k & 0xFF)
    heavy = [(k, s, c, f, b) for (k, s, c, f, b) in scores if s >= theta]
    heavy.sort(key=lambda x: -x[1])
    if args["topk"]:
        heavy = heavy[:args["topk"]]

    print("\n" + "=" * 72)
    print(f" score ranking (threshold θ = {theta:g})  duplicate-flow count = {len(heavy)}")
    print("=" * 72)
    print(f"{'key':>18} {'bucket':>6} {'heavy':>6} {'light+':>7} {'score':>6}")
    print("-" * 72)
    for k, s, c, f, b in heavy:
        print(f"{ip(k):>18} {b:>6} {c:>6} {'yes' if f else 'no ':>7} {s:>6}")
    if not heavy:
        print("  (no keys above threshold)")

    
    if g_hi > g_lo:
        print("\n[guard] non-zero entries:")
        guard_tbl = getattr(p4, "guard")
        nz = 0
        for b in range(g_lo, g_hi):
            g = _get_reg(guard_tbl, b)
            if g:
                print(f"  bucket {b}: guard = {g}")
                nz += 1
        if not nz:
            print("  (none)")

    print("\nQuery done.")


if __name__ == "__main__":
    main()
