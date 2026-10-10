
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "..", "1_reference_implementation"))
from common import make_sketch, EXP4_TARGETS  # noqa: E402
from sweepsketch import config  # noqa: E402

P4_N1, P4_N2 = 8192, 4096    


def expected_states():
    
    sk = make_sketch(config.THETA0, 512)   
    
    total = (P4_N1 + P4_N2)
    from sweepsketch.sketch import Level
    sk.l1 = Level(P4_N1, lambda d: (d >> 8) << 8, 0x11)
    sk.l2 = Level(P4_N2, lambda d: (d >> 16) << 16, 0x22)
    from sweepsketch.digest import Collector
    col = Collector()
    ts = 0.0
    CDN, OFF, ATK = 0xC6330000, 0x0A640000, 0x7F000100
    for e in range(8):
        t0 = e * 4.3
        for i in range(1024):
            sk.process(0, CDN + (i % 256), t0 + (i % 1024) * 1e-6, col)
        for i in range(500):
            sk.process(0, OFF + 5, t0 + 1.0 + i * 1e-6, col)
        for i in range(100):
            sk.process(0, OFF + 10 + (i % 5), t0 + 2.0 + i * 1e-6, col)
        if e >= 3:
            for i in range(2048):
                sk.process(0, ATK + (i % 256), t0 + 3.0 + i * 1e-6, col)
    out = {"l1": {}, "l2": {}, "alerts": []}
    for i, b in enumerate(sk.l1.buckets):
        if b is not None:
            out["l1"][str(i)] = {
                "key": b.key, "ep": (b.epoch << 3) | b.win,
                "nn": b.n_new, "ne": b.n_ewma, "C": b.C,
                "pkt": b.pkt, "pe": b.pkt_ewma, "held": int(b.d2_held),
                "hll": [b.hll[r] for r in range(32)],
            }
    for i, b in enumerate(sk.l2.buckets):
        if b is not None:
            out["l2"][str(i)] = {
                "key": b.key, "ep": (b.epoch << 3) | b.win,
                "nn": b.n_new, "ne": b.n_ewma, "C": b.C,
                "pkt": b.pkt, "pe": b.pkt_ewma, "held": int(b.d2_held),
                "hll": [b.hll[r] for r in range(32)],
            }
    for a in col.alerts:
        out["alerts"].append({"level": a.level, "key": a.key,
                              "epoch": a.epoch, "reason": a.reason, "ts": a.ts})
    return out


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


def collect_hardware():
    
    try:
        p4 = bfrt.sweepsketch.pipe.Ingress
    except NameError:
        raise SystemExit("must run inside bfshell")
    out = {"l1": {}, "l2": {}}
    
    
    regs1 = [("l1_key", 32), ("l1_ep", 8), ("l1_nn", 8), ("l1_ne", 8),
             ("l1_C", 16), ("l1_pkt", 16)]
    regs2 = [("l2_key", 32), ("l2_ep", 8), ("l2_nn", 8),
             ("l2_C", 16), ("l2_pkt", 16)]
    for name, _w in regs1:
        tbl = getattr(p4, name)
        out["l1"][name] = {}
        for i in range(P4_N1):
            r = tbl.get(REGISTER_INDEX=i, from_hw=True, print_ents=False)
            out["l1"][name][str(i)] = _extract_value(r)
    for name, _w in regs2:
        tbl = getattr(p4, name)
        out["l2"][name] = {}
        for i in range(P4_N2):
            r = tbl.get(REGISTER_INDEX=i, from_hw=True, print_ents=False)
            out["l2"][name][str(i)] = _extract_value(r)
    
    for lvl, (name, n_buckets) in (("l1", ("l1_hll", P4_N1)),
                                   ("l2", ("l2_hll", P4_N2))):
        tbl = getattr(p4, name)
        out[lvl][name] = {}
        for i in range(n_buckets * 32):
            r = tbl.get(REGISTER_INDEX=i, from_hw=True, print_ents=False)
            out[lvl][name][str(i)] = _extract_value(r)
    return out


def compare(expected, hw):
    
    mism = 0
    
    for i, b in expected["l1"].items():
        for name, exp_val in (("key", "l1_key"), ("ep", "l1_ep"), ("nn", "l1_nn"),
                              ("ne", "l1_ne"), ("C", "l1_C"), ("pkt", "l1_pkt")):
            got = hw["l1"].get(name, {}).get(i)
            if got != b[name]:
                print("MISMATCH l1[%s].%s: python=%r hw=%r" % (i, name, b[name], got))
                mism += 1
        for r in range(32):
            got = hw["l1"].get("l1_hll", {}).get(str(int(i) * 32 + r))
            if got != b["hll"][r]:
                print("MISMATCH l1_hll[%s*32+%d]: python=%r hw=%r" %
                      (i, r, b["hll"][r], got))
                mism += 1
    
    for i, b in expected["l2"].items():
        for name, reg in (("key", "l2_key"), ("ep", "l2_ep"), ("nn", "l2_nn"),
                          ("C", "l2_C"), ("pkt", "l2_pkt")):
            got = hw["l2"].get(reg, {}).get(i)
            if got != b[name]:
                print("MISMATCH l2[%s].%s: python=%r hw=%r" % (i, name, b[name], got))
                mism += 1
        for r in range(32):
            got = hw["l2"].get("l2_hll", {}).get(str(int(i) * 32 + r))
            if got != b["hll"][r]:
                print("MISMATCH l2_hll[%s*32+%d]: python=%r hw=%r" %
                      (i, r, b["hll"][r], got))
                mism += 1
    print("equivalence: %s (%d mismatches)" %
          ("bit-identical ✓" if mism == 0 else "mismatch ✗", mism))
    return mism


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump-expected", action="store_true")
    ap.add_argument("--compare", default=None, help="path to the hardware-captured JSON")
    args = ap.parse_args()
    if args.dump_expected:
        with open("expected_states.json", "w") as fh:
            json.dump(expected_states(), fh)
        print("expected_states.json written (%d alarm anchors)"
              % len(expected_states()["alerts"]))
    elif args.compare:
        with open("expected_states.json") as fh:
            exp = json.load(fh)
        with open(args.compare) as fh:
            hw = json.load(fh)
        sys.exit(compare(exp, hw))
    else:
        print("Usage: --dump-expected (local) | --compare hw_states.json (testbed)")
