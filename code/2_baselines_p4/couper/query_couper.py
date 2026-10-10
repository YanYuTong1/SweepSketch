

import math
import os
import sys





B = int(os.environ.get("COUPER_B", 16))
T = int(os.environ.get("COUPER_T", 12))
C = int(os.environ.get("COUPER_C", 32))
L1 = int(os.environ.get("COUPER_L1", 131072))        
L2 = int(os.environ.get("COUPER_L2", 4096))          
TSC_LEN = int(os.environ.get("COUPER_TSC_LEN", 4096))


def _argv(args, name, default):
    
    for i, a in enumerate(args):
        if a == "--" + name and i + 1 < len(args):
            return args[i + 1]
    env = os.environ.get("COUPER_" + name.upper().replace("-", "_"))
    return env if env is not None else default


def _int(args, name, default):
    return int(_argv(args, name, default))


def _flag(args, name):
    return any(a == "--" + name for a in args)


ARGS = sys.argv[1:]




try:
    p4 = bfrt.couper.pipe.Ingress
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


def reg_get(name, idx):
    
    try:
        r = getattr(p4, name).get(REGISTER_INDEX=idx, from_hw=True,
                                  print_ents=False)
        return _extract_value(r)
    except Exception:
        return 0


def reg_dump(name, start, end):
    
    out = {}
    for i in range(start, end):
        out[i] = reg_get(name, i)
    return out





def _pop16(v):
    return bin(v & 0xFFFF).count("1")


def _hll_est(regs):
    
    m = len(regs)
    s = sum(2.0 ** -r for r in regs if r > 0) + (m - sum(1 for r in regs if r > 0))
    res = (0.7213 / (1 + 1.079 / m)) * m * m / s
    if res < 2.5 * m:
        z = sum(1 for r in regs if r == 0)
        res = m * math.log(m / max(z, 1))
    return res


def estimate_src(f_str, c1, c2, g1, g2):
    
    bm1 = reg_get("bm", c1) & 0xFFFF
    bm2 = reg_get("bm", c2) & 0xFFFF
    merged = bm1 | bm2
    coupon = _pop16(merged)
    base = B * math.log(B / max(B - T, 1))
    if coupon < T:
        return B * math.log(B / max(B - coupon, 1))
    fgm = []
    for i in range(C):
        fgm.append(max(reg_get("hllreg", g1 * C + i),
                       reg_get("hllreg", g2 * C + i)))
    bm2b = 0
    for r in range(C):
        if fgm[r] > 0:
            bm2b |= 1 << (r % B)
    tmp = _pop16(merged & bm2b)
    omega = min(B * math.log(B / max(B - tmp, 1)), base)
    return _hll_est(fgm) + base - omega


def _ip(v):
    return f"{(v >> 24) & 0xff}.{(v >> 16) & 0xff}.{(v >> 8) & 0xff}.{v & 0xff}"





def dump_tsc(start, end):
    print(f"[dump-tsc] tsc_f / tsc_d [{start}, {end}) ...")
    n = 0
    for i in range(start, end):
        f = reg_get("tsc_f", i)
        if f:
            d = reg_get("tsc_d", i)
            print(f"  [{i:>4}] flow={_ip(f):>15}  λ={d}")
            n += 1
    print(f"[dump-tsc] non-zero candidates {n}")


def dump_bm(start, end):
    print(f"[dump-bm] bm [{start}, {end}) ...")
    n = 0
    for i in range(start, end):
        v = reg_get("bm", i)
        if v:
            print(f"  [{i:>6}] bm=0x{v & 0xFFFF:04X}  popcount={_pop16(v)}")
            n += 1
    print(f"[dump-bm] non-zero cells {n}")


def dump_hll_g(g):
    print(f"[dump-hll-g] group {g} {C} registers + digest ...")
    vals = [reg_get("hllreg", g * C + i) for i in range(C)]
    print(f"  regs = {vals}")
    print(f"  digest[{g}] = {reg_get('digest', g)}")


def dump_digest(start, end):
    print(f"[dump-digest] digest [{start}, {end}) ...")
    n = 0
    for i in range(start, end):
        v = reg_get("digest", i)
        if v:
            print(f"  [{i:>4}] digest={v}")
            n += 1
    print(f"[dump-digest] non-zero groups {n}")





def main():
    print("=" * 72)
    print(" Couper data-plane query  (B=%d, T=%d, C=%d, L1=%d, L2=%d, TSC=%d)"
          % (B, T, C, L1, L2, TSC_LEN))
    print("=" * 72)

    if _flag(ARGS, "dump-bm"):
        dump_bm(_int(ARGS, "bm-start", 0), _int(ARGS, "bm-end", min(1024, L1)))
        return
    if _flag(ARGS, "dump-hll-g"):
        dump_hll_g(_int(ARGS, "dump-hll-g", 0))
        return
    if _flag(ARGS, "dump-digest"):
        dump_digest(_int(ARGS, "digest-start", 0),
                    _int(ARGS, "digest-end", L2))
        return
    if _flag(ARGS, "estimate"):
        f_str = _argv(ARGS, "est-src", None)
        c1 = _int(ARGS, "c1", -1)
        c2 = _int(ARGS, "c2", -1)
        g1 = _int(ARGS, "g1", -1)
        g2 = _int(ARGS, "g2", -1)
        if f_str is None or min(c1, c2, g1, g2) < 0:
            print("estimate mode needs --est-src SRC_IP and --c1 --c2 --g1 --g2 "
                  "(P4 hash reproduction values)")
            return
        print(f"[estimate] src={f_str}  c1={c1} c2={c2} g1={g1} g2={g2}")
        bm1 = reg_get("bm", c1) & 0xFFFF
        bm2 = reg_get("bm", c2) & 0xFFFF
        print(f"  merged=0x{(bm1 | bm2):04X}  coupon={_pop16(bm1 | bm2)}")
        print(f"  cardinality estimate = {estimate_src(f_str, c1, c2, g1, g2):.2f}")
        return
    
    dump_tsc(_int(ARGS, "tsc-start", 0), _int(ARGS, "tsc-end", TSC_LEN))


main()
