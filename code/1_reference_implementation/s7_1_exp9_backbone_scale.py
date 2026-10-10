
import csv
import os

from sweepsketch.digest import Collector
from sweepsketch.pcapio import iter_pcap

from common import (ATT_DIR, DB, RES, STAGGER, attack_files, config, ip24,
                    make_sketch)

BACKBONE = ["202607011400.pcap", "202607021400.pcap", "202607031400.pcap",
            "202607041400.pcap", "202607051400.pcap"]


def _p8_one(theta0, fname, budget_kb=512):
    
    path = os.path.join(DB, "benign", fname)
    sk = make_sketch(theta0, budget_kb)
    col = Collector()
    bdur = 0.0
    for s, d, ts in iter_pcap(path, config.BENIGN_MAX, with_flow=False):
        bdur = ts
        sk.process(s, d, ts, col)
    cursor = bdur + STAGGER
    wins = []
    for f in attack_files():
        apath = os.path.join(ATT_DIR, f)
        pfx = ip24(f.split("_")[0])
        first = None
        for s, d, ts in iter_pcap(apath, config.ATTACK_MAX, with_flow=False):
            if first is None:
                first = ts
            last = ts
        if first is None:
            continue
        t0, t1 = cursor, cursor + (last - first)
        wins.append((pfx, t0, t1))
        shift = cursor - first
        for s, d, ts in iter_pcap(apath, config.ATTACK_MAX, with_flow=False):
            sk.process(s, d, ts + shift, col)
        cursor += (last - first) + STAGGER
    alerts = [a for a in col.alerts if a.level == 1]
    byp = {}
    for a in alerts:
        byp.setdefault(a.key, []).append(a.ts)
    tp = fn = 0
    lat = []
    for pfx, t0, t1 in wins:
        hits = [t for t in byp.get(pfx, []) if t0 - 4.3 <= t <= t1 + 4.3]
        if hits:
            tp += 1
            lat.append(min(hits) - t0)
        else:
            fn += 1
    atk_set = {p for p, _, _ in wins}
    fpP = set()
    fpE = 0
    for key, ts_list in byp.items():
        for t in ts_list:
            if key in atk_set and any(a <= t <= b for _, a, b in wins):
                continue
            fpE += 1
            fpP.add(key)
    f1 = 2 * tp / (2 * tp + fn + len(fpP)) if (2 * tp + fn + len(fpP)) else 0.0
    med = (sorted(lat)[len(lat) // 2] * 1000) if lat else None
    return (fname, budget_kb, tp, fn, len(fpP), fpE, round(f1, 4),
            None if med is None else round(med, 1), len(alerts))


def run_p8(theta0, budgets=(512, 1024, 2048, 4096, 8192, 10240)):
    
    from multiprocessing import Pool
    tasks = [(theta0, f, kb) for kb in budgets for f in BACKBONE]
    with Pool(min(8, len(tasks))) as p:
        rows = p.starmap(_p8_one, tasks)
    os.makedirs(RES, exist_ok=True)
    with open(os.path.join(RES, "EXP9_backbone.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["trace", "kb", "tp", "fn", "fp_prefixes", "fp_events", "f1",
                    "med_latency_ms", "n_alerts"])
        w.writerows(sorted(rows, key=lambda x: (x[1], x[0])))
    for r in sorted(rows, key=lambda x: (x[1], x[0])):
        print("P8 %s kb=%d: tp=%d fn=%d fpP=%d fpE=%d F1=%s latency=%sms" %
              (r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]))
