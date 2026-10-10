

import math
import os
import sys




NB       = int(os.environ.get("MRB_NB", 2048))      
B        = int(os.environ.get("MRB_B", 512))        
LASTB    = int(os.environ.get("MRB_LASTB", 1024))   
B_WORDS  = B // 32                                  
LASTB_WORDS = LASTB // 32                           
C        = 3                                        
RATIO    = 0.93105                                  


def _argv(args, name, default):
    
    for i, a in enumerate(args):
        if a == "--" + name and i + 1 < len(args):
            return args[i + 1]
    env = os.environ.get("MRB_" + name.upper().replace("-", "_"))
    return env if env is not None else default


def _int(args, name, default):
    return int(_argv(args, name, default))


ARGS = sys.argv[1:]
SLOT_START = _int(ARGS, "slot-start", 0)
SLOT_END   = _int(ARGS, "slot-end", NB)
TOP        = _int(ARGS, "top", 20)




try:
    p4 = bfrt.mrb.pipe.Ingress
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






def zeros_b1(slot):
    
    ones = 0
    base = slot * B_WORDS
    for w in range(B_WORDS):
        ones += bin(reg_get("b1w", base + w) & 0xFFFFFFFF).count("1")
    return B - ones


def zeros_bl(slot):
    
    ones = 0
    base = slot * LASTB_WORDS
    for w in range(LASTB_WORDS):
        ones += bin(reg_get("blw", base + w) & 0xFFFFFFFF).count("1")
    return LASTB - ones





def est_one(z1, zl):
    
    setmax = int(B * RATIO + 0.5)
    factor, base = 1, 0
    zs = [B, z1]                      
    for base in range(C - 1):
        z = zs[base]
        if B - z <= setmax:
            break
        factor *= 2
    m, pos = 0.0, base - 1
    for i in range(base, C - 1):
        z = zs[i]
        if z == 0 or B - z > setmax:
            pos, m = i, 0.0
        else:
            m += B * (math.log(B) - math.log(z))
    factor *= 1 << (pos - base + 1)
    z = zl
    m += LASTB * (math.log(LASTB) - (math.log(z) if z else 0.0))
    return factor * m





def main():
    n_gets = (SLOT_END - SLOT_START) * (B_WORDS + LASTB_WORDS)
    print("=" * 72)
    print(" MRB data-plane query (b=%d, lastb=%d, RATIO=%.5f)" % (B, LASTB, RATIO))
    print("=" * 72)
    print(f"[scan] slot range [{SLOT_START}, {SLOT_END}), per slot {B_WORDS + LASTB_WORDS} gets get, "
          f"about {n_gets} times (full run ~20 min; TODO-verify measured rate)...")
    print(f"{'slot':>5} {'z1':>5} {'zl':>5} {'ones1':>6} {'onesl':>6} {'est':>12}")
    print("-" * 72)

    results = []      
    n_nonzero = 0
    for slot in range(SLOT_START, SLOT_END):
        z1 = zeros_b1(slot)
        zl = zeros_bl(slot)
        ones1 = B - z1
        onesl = LASTB - zl
        if ones1 == 0 and onesl == 0:
            
            pass
        else:
            e = est_one(z1, zl)
            results.append((e, slot, z1, zl, ones1, onesl))
            n_nonzero += 1
            print(f"{slot:>5} {z1:>5} {zl:>5} {ones1:>6} {onesl:>6} {e:>12.2f}")
        if (slot - SLOT_START) % 64 == 63:
            print(f"  ... scanned {slot - SLOT_START + 1} slot", flush=True)

    
    results.sort(key=lambda x: -x[0])
    print()
    print("=" * 72)
    print(f" non-zero slots total: {n_nonzero} / {SLOT_END - SLOT_START}")
    print(f" top estimates: {min(TOP, len(results))} slot:")
    print("=" * 72)
    print(f"{'rank':>4} {'slot':>5} {'est':>12} {'z1':>5} {'zl':>5}")
    for rank, (e, slot, z1, zl, ones1, onesl) in enumerate(results[:TOP], 1):
        print(f"{rank:>4} {slot:>5} {e:>12.2f} {z1:>5} {zl:>5}")

    print()
    print("Query done.")
    print("Note: the pfx→slot mapping must be supplied by the caller as a P4 CRC32 reproduction value (bfshell has no hash-reproduction API,")
    print("    detection-threshold convention matches Python query()'s {pfx: est}.)")


main()
