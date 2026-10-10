
import csv
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from baselines.step02_baselines import DST_METHODS, _build
from baselines._support import eval_static
from sweepsketch import pcapio

RES = os.path.join(HERE, "..", "..", "results", "csv")
ATT = os.path.join(HERE, "..", "..", "database", "attack")

MULTI_DIRS = [
    ("natural", os.path.join(ATT, "natural_multi24")),
    ("synthetic_byts", os.path.join(ATT, "synthetic_multi24_by_timestamp")),
    ("synthetic_shuffled", os.path.join(ATT, "synthetic_multi24_shuffled")),
]
BENIGN_FILES = [
    ("benign", os.path.join(HERE, "..", "..", "database", "benign", "CIC-IDS-2017-Benign.pcap")),
    ("benign", os.path.join(HERE, "..", "..", "database", "benign", "CIC-IoT-2023-Benign.pcap")),
]
GT_FRAC = 0.01
BENIGN_MAX = 2000000

TAU = {"entropy": 4.37, "lakhina": 5.2, "mrb": 36.07,
       "rhhh": 13727.88, "elastic": 67694.14, "heavykeeper": 67694.14}


def _gt_and_flows(path, max_pkts, kind):
    
    total = 0
    segs = {}
    for s, d, ts in pcapio.iter_pcap(path, max_pkts=max_pkts, with_flow=False):
        total += 1
        segs[(d >> 8) << 8] = segs.get((d >> 8) << 8, 0) + 1
    if total == 0:
        return None
    gt = set() if kind == "benign" else \
        set(k for k, c in segs.items() if c >= total * GT_FRAC)
    return gt, len(segs)


def _one_file(path, kind, method, tau):
    
    max_pkts = BENIGN_MAX if kind == "benign" else 10000000
    gt_segs, n_pfx = _gt_and_flows(path, max_pkts, kind)
    if gt_segs is None:
        return None
    sk, mem, structure = _build(method, 512, n_pfx)
    for pkt_i, (s, d, ts) in enumerate(
            pcapio.iter_pcap(path, max_pkts=max_pkts, with_flow=False)):
        sk.insert(s, d, pkt_i)
    scores = sk.query()
    r = eval_static(scores, gt_segs, tau)
    r["method"] = method
    r["file"] = os.path.basename(path)
    r["kind"] = kind
    r["gt"] = len(gt_segs)
    return r, scores, gt_segs


def run_real_baselines():
    files = []
    for kind, d in MULTI_DIRS:
        files += [(kind, os.path.join(d, f)) for f in sorted(os.listdir(d))
                  if pcapio.is_trace(f)]
    files += BENIGN_FILES
    rows = []
    per_method = {m: {"scores": [], "gt": []} for m in DST_METHODS}
    print("EXP_real baseline comparison: %d files × %d methods (primary convention τ = E1 final values, not re-tuned on the holdout)" %
          (len(files), len(DST_METHODS)))
    t_all = time.time()
    for kind, path in files:
        for method in DST_METHODS:
            t0 = time.time()
            out = _one_file(path, kind, method, TAU[method])
            if out is None:
                continue
            r, scores, gt = out
            r["wall_s"] = round(time.time() - t0, 1)
            rows.append(r)
            if kind != "benign":          
                per_method[method]["scores"].append(scores)
                per_method[method]["gt"].append(gt)
            print("  [%s] %-12s %-45s tp=%d fn=%d fp=%d f1=%.3f (%ss)" %
                  (kind, method, r["file"][:45], r["tp"], r["fn"], r["fp"],
                   r["f1"], r["wall_s"]))
    
    print("\nsecondary convention: best-τ over the 30 holdout files (one τ per method, same convention as E1)")
    aux = []
    for method in DST_METHODS:
        s_list = per_method[method]["scores"]
        g_list = per_method[method]["gt"]
        hi = max((max(sc.values()) for sc in s_list), default=1.0) or 1.0
        best = None
        for i in range(201):
            tau = hi * i / 200
            tp = fp = fn = 0
            for sc, gt in zip(s_list, g_list):
                r = eval_static(sc, gt, tau)
                tp += r["tp"]; fp += r["fp"]; fn += r["fn"]
            f1 = 2 * tp / (2 * tp + fn + fp) if (2 * tp + fn + fp) else 0.0
            if best is None or f1 > best["f1"]:
                best = {"method": method, "tau_holdout": round(tau, 2),
                        "tp": tp, "fp": fp, "fn": fn, "f1": round(f1, 3)}
        print("  %-12s τ_holdout=%s tp=%d fp=%d fn=%d f1=%.3f" %
              (method, best["tau_holdout"], best["tp"], best["fp"],
               best["fn"], best["f1"]))
        aux.append(best)
    os.makedirs(RES, exist_ok=True)
    cols = ["method", "kind", "file", "tau", "gt", "tp", "fp", "fn", "tn",
            "precision", "recall", "f1", "wall_s"]
    with open(os.path.join(RES, "EXP_real_baselines.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(RES, "EXP_real_baselines_holdout_tau.csv"), "w",
              newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["method", "tau_holdout", "tp",
                                           "fp", "fn", "f1"])
        w.writeheader()
        w.writerows(aux)
    print("elapsed %.0fs | output: EXP_real_baselines.csv + EXP_real_baselines_holdout_tau.csv" %
          (time.time() - t_all))


if __name__ == "__main__":
    run_real_baselines()
