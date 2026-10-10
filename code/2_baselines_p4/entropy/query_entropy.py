

import math
import os
import sys




NB = int(os.environ.get("ENT_NB", 2048))     
Z  = int(os.environ.get("ENT_Z", 64))        
G  = int(os.environ.get("ENT_G", 3))         


def _argv(args, name, default):
    
    for i, a in enumerate(args):
        if a == "--" + name and i + 1 < len(args):
            return args[i + 1]
    env = os.environ.get("ENT_" + name.upper().replace("-", "_"))
    return env if env is not None else default


def _int(args, name, default):
    return int(_argv(args, name, default))


ARGS = sys.argv[1:]
SLOT_START = _int(ARGS, "slot-start", 0)
SLOT_END   = _int(ARGS, "slot-end", NB)
TOP        = _int(ARGS, "top", 20)




try:
    p4 = bfrt.entropy.pipe.Ingress
except NameError:
    print("Error: bfrt unavailable. This script must run inside bfshell.")
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


def reg_get(reg_name, index):
    
    try:
        r = getattr(p4, reg_name).get(
            REGISTER_INDEX=index, from_hw=True, print_ents=False)
        return _extract_value(r)
    except Exception:
        return 0





def score(ctrs):
    
    m = sum(ctrs) / G                      
    if m <= 0:
        return 0.0
    gz = G / Z
    s = sum((c - m * gz) ** 2 for c in ctrs)
    fhat = s / (m * m * G * (1.0 - gz))
    fhat = min(max(fhat, 1.0 / 2 ** 16), 1.0)   
    return -math.log2(fhat)


def fhat_of(ctrs, m):
    
    gz = G / Z
    s = sum((c - m * gz) ** 2 for c in ctrs)
    fhat = s / (m * m * G * (1.0 - gz))
    return min(max(fhat, 1.0 / 2 ** 16), 1.0)





def main():
    n_gets = (SLOT_END - SLOT_START) * Z
    print("=" * 72)
    print(f" EntropySketch data-plane query (z={Z}, g={G})")
    print("=" * 72)
    print(f"[scan] slot range [{SLOT_START}, {SLOT_END}), per slot {Z} gets get, "
          f"about {n_gets} times (full run ~25 min; TODO-verify measured rate)...")
    print(f"{'slot':>5} {'m':>10} {'fhat':>12} {'score':>10}")
    print("-" * 72)

    results = []      
    n_nonzero = 0
    for slot in range(SLOT_START, SLOT_END):
        ctrs = []
        base = slot * Z
        for p in range(Z):
            ctrs.append(reg_get("ctr", base + p))
        if sum(ctrs) == 0:
            
            pass
        else:
            sc = score(ctrs)
            m = sum(ctrs) / G
            fhat = fhat_of(ctrs, m)
            results.append((sc, slot, m, fhat))
            n_nonzero += 1
            print(f"{slot:>5} {m:>10.2f} {fhat:>12.6f} {sc:>10.4f}")
        if (slot - SLOT_START) % 64 == 63:
            print(f"  ... scanned {slot - SLOT_START + 1} slot", flush=True)

    
    results.sort(key=lambda x: -x[0])
    print()
    print("=" * 72)
    print(f" non-zero slots total: {n_nonzero} / {SLOT_END - SLOT_START}")
    print(f" top scores: {min(TOP, len(results))} slot:")
    print("=" * 72)
    print(f"{'rank':>4} {'slot':>5} {'score':>10} {'m':>10} {'fhat':>12}")
    for rank, (sc, slot, m, fhat) in enumerate(results[:TOP], 1):
        print(f"{rank:>4} {slot:>5} {sc:>10.4f} {m:>10.2f} {fhat:>12.6f}")

    print()
    print("Query done.")
    print("Note: the pfx→slot mapping must be supplied by the caller as a P4 CRC32 reproduction value (bfshell has no hash-reproduction API,")
    print("    detection-threshold convention matches Python query()'s {pfx: est}.)")


main()
