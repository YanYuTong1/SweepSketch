
import csv
import heapq
import os

from sweepsketch.digest import Collector
from sweepsketch.pcapio import iter_pcap, trace_name

from common import (ATT_DIR, BENIGN, DB, DUMMY, EXP4_TARGETS, RES, STAGGER,
                    attack_files, config, f1_of, feed, flush, h_flag, ip24,
                    make_sketch)

BENIGN_ALL = ["CIC-IDS-2017-Benign.pcap",
              "202607011400.pcap", "202607021400.pcap", "202607031400.pcap",
              "202607041400.pcap", "202607051400.pcap",
              "CIC-IoT-2023-Benign.pcap", "CIC-IoT-2023-Benign1.pcap",
              "CIC-IoT-2023-Benign2.pcap", "CIC-IoT-2023-Benign3.pcap"]


def run_calibrate(theta0, all_benign=False, sample_k=10):
    
    files = BENIGN_ALL if all_benign else [os.path.basename(BENIGN)]
    rows = []
    per_file = {}
    for fn in files:
        path = os.path.join(DB, "benign", fn)
        if not os.path.exists(path):
            continue
        sk = make_sketch(config.THETA0, 512)
        cur, rates = {}, []
        maxnn = {}
        n_pkt = n_used = 0
        for s, d, ts in iter_pcap(path, config.BENIGN_MAX, with_flow=False):
            n_pkt += 1
            if all_benign and n_pkt % sample_k:
                continue
            n_used += 1
            key = sk.l1.key_of(d)
            i1 = sk.l1.idx(key)
            e1o = sk.l1.buckets[i1].epoch if sk.l1.buckets[i1] is not None else -1
            sk.process(s, d, ts, DUMMY)
            b = sk.l1.buckets[i1]
            if b is None or b.key != key:
                continue
            r = cur.get(key)
            if r is None or b.epoch != e1o:
                if r is not None:
                    if r[1] >= 50:
                        rates.append(r[0] / r[1])
                    maxnn[key] = max(maxnn.get(key, 0), r[0])
                cur[key] = [b.n_new, b.pkt]
            else:
                r[0], r[1] = b.n_new, b.pkt
        for key, r in cur.items():
            if r[1] >= 50 and r[0] > 0:
                rates.append(r[0] / r[1])
            maxnn[key] = max(maxnn.get(key, 0), r[0])
        rates.sort()
        med = rates[len(rates) // 2] if rates else None
        flo = {k: sum(1 for v in maxnn.values() if v >= k)
               for k in (8, 10, 12, 14, 16, 20)}
        per_file[fn] = (med, len(rates), flo)
        rows.append((fn, None if med is None else round(med, 4), len(rates), n_used))
        print("%-28s θ₀=%s busy windows=%d sampled packets=%d prefixes≥{8,10,12,14,16,20}={%s}" %
              (fn, None if med is None else round(med, 4), len(rates), n_used,
               ",".join(str(flo[k]) for k in (8, 10, 12, 14, 16, 20))))
    if all_benign:
        meds = sorted(m for m, _, _ in per_file.values() if m)
        union_med = meds[len(meds) // 2]
        print("union θ₀ (median of per-file medians) = %.4f" % union_med)
    os.makedirs(RES, exist_ok=True)
    tag = "CAL_union_theta0.csv" if all_benign else "CAL_cic_theta0.csv"
    with open(os.path.join(RES, tag), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["file", "theta0_med", "n_busy_windows", "n_pkt_used"])
        w.writerows(rows)


def run_e1(theta0, budgets, tag="EXP1_static", dump=None, benign=None):
    
    benign_path = benign or BENIGN
    out = {}
    all_rows = []
    for kb in budgets:
        sk = make_sketch(theta0, kb)
        stats, cur = {}, {}
        gt_benign = set()
        for s, d, ts in iter_pcap(benign_path, config.BENIGN_MAX, with_flow=False):
            gt_benign.add((d >> 8) << 8)
            feed(sk, stats, cur, s, d, ts, DUMMY)
        flush(stats, cur)
        gt_attack = {ip24(f.split("_")[0]) for f in attack_files()}
        cursor = 4e9                     
        for f in attack_files():
            path = os.path.join(ATT_DIR, f)
            first = None
            for s, d, ts in iter_pcap(path, config.ATTACK_MAX, with_flow=False):
                if first is None:
                    first = ts
                last = ts
            if first is None:
                continue
            for s, d, ts in iter_pcap(path, config.ATTACK_MAX, with_flow=False):
                feed(sk, stats, cur, s, d, ts - first + cursor, DUMMY)
            cursor += (last - first) + STAGGER
        flush(stats, cur)
        rows = []
        for hb in range(4, 13):
            fl = h_flag(hb)
            flagged = {k[1]: True for k, s in stats.items()
                       if k[0] == 1 and fl(s)}      
            tp, fp, fn, f1v = f1_of(flagged, gt_attack, gt_benign)
            rows.append((kb, hb, tp, fp, fn, f1v))
            out[(kb, hb)] = (tp, fp, fn, f1v)
        
        fl = h_flag(9.2)
        flagged = {k[1]: True for k, s in stats.items() if k[0] == 1 and fl(s)}
        tp, fp, fn, f1v = f1_of(flagged, gt_attack, gt_benign)
        rows.append((kb, 9.2, tp, fp, fn, f1v))
        all_rows += rows
        if dump:
            with open(dump, "w", newline="") as fh:
                w = csv.writer(fh)
                w.writerow(["entity", "type", "flagged"])
                for f in attack_files():
                    nm = trace_name(f)
                    pfx = ip24(nm.split("_")[0])
                    w.writerow([nm, nm.split("_")[1], 1 if flagged.get(pfx) else 0])
                for p in sorted(gt_benign):
                    if flagged.get(p):
                        w.writerow([p, "benign", 1])
        os.makedirs(RES, exist_ok=True)
        if tag:                          
            with open(os.path.join(RES, tag + ".csv"), "w", newline="") as fh:
                w = csv.writer(fh)
                w.writerow(["kb", "h_bits", "tp", "fp", "fn", "f1"])
                w.writerows(rows)
        print(f"kb={kb}: best " +
              f"{max(rows, key=lambda r: r[5])[1:]} | fixed9.2 {rows[-1][2:]} | "
              f"gt_attack={len(gt_attack)} gt_benign={len(gt_benign)}")
    return out, all_rows


def run_e7(theta0, benign=None, targets=None, tag="EXP4_dynamic"):
    
    benign_path = benign or BENIGN
    tgt = targets or EXP4_TARGETS
    sk = make_sketch(theta0, 512)
    col = Collector()
    bdur = 0.0
    for s, d, ts in iter_pcap(benign_path, config.BENIGN_MAX, with_flow=False):
        bdur = ts                       
    cursor = bdur + STAGGER
    streams = [iter_pcap(benign_path, config.BENIGN_MAX, with_flow=False)]
    file_windows = []
    for fi, f in enumerate(attack_files()):
        path = os.path.join(ATT_DIR, f)
        target = tgt[fi % len(tgt)]
        first = None
        for s, d, ts in iter_pcap(path, config.ATTACK_MAX, with_flow=False):
            if first is None:
                first = ts
            last = ts
        if first is None:
            continue
        t0 = cursor
        t1 = cursor + (last - first)
        file_windows.append((f, target, t0, t1))
        def gen(path=path, first=first, target=target, shift=cursor - first):
            for s, d, ts in iter_pcap(path, config.ATTACK_MAX, with_flow=False):
                yield s, target | (d & 0xFF), ts + shift
        streams.append(gen())
        cursor += (last - first) + STAGGER
    n = 0
    for s, d, ts in heapq.merge(*streams, key=lambda x: x[2]):
        sk.process(s, d, ts, col)
        n += 1
    
    alerts = [a for a in col.alerts if a.level == 1]
    alert_by_pfx = {}
    for a in alerts:
        alert_by_pfx.setdefault(a.key, []).append((a.epoch, a.ts))
    tp = fn = 0
    latencies = []
    fp_events = 0
    fp_prefixes = set()
    target_keys = set(tgt)
    for f, target, t0, t1 in file_windows:
        hits = [t for _, t in alert_by_pfx.get(target, []) if t0 - 4.3 <= t <= t1 + 4.3]
        if hits:
            tp += 1
            latencies.append(min(hits) - t0)
        else:
            fn += 1
    win_ivals = [(t0, t1) for _, _, t0, t1 in file_windows]
    for key, evs in alert_by_pfx.items():
        for e, t in evs:
            
            if key not in target_keys:
                fp_events += 1
                fp_prefixes.add(key)
            elif not any(a <= t <= b for a, b in win_ivals):
                fp_events += 1
                fp_prefixes.add(key)
    f1v = (2 * tp / (2 * tp + fn + len(fp_prefixes))) if (2 * tp + fn + len(fp_prefixes)) else 0.0
    lat = sorted(latencies)
    med = lat[len(lat) // 2] * 1000 if lat else None
    os.makedirs(RES, exist_ok=True)
    with open(os.path.join(RES, tag + ".csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["tp", "fn", "fp_prefixes", "fp_events", "f1_prefix",
                    "med_latency_ms", "n_alerts_l1", "n_pkts"])
        w.writerow([tp, fn, len(fp_prefixes), fp_events, round(f1v, 4),
                    None if med is None else round(med, 1), len(alerts), n])
        w.writerow([])
        w.writerow(["file", "target", "t0", "t1", "first_alert_ms"])
        for f, target, t0, t1 in file_windows:
            hits = [t for _, t in alert_by_pfx.get(target, []) if t0 - 4.3 <= t <= t1 + 4.3]
            w.writerow([f, target, round(t0, 1), round(t1, 1),
                        None if not hits else round((min(hits) - t0) * 1000, 1)])
    print(f"E7: tp={tp} fn={fn} fp_prefixes={len(fp_prefixes)} fp_events={fp_events} "
          f"F1={f1v:.4f} med_latency_ms={med} alerts={len(alerts)} pkts={n}")
    return tp, fn, len(fp_prefixes), fp_events, f1v, med


def run_e2(theta0, benign=None, tag="EXP2_spoofing"):
    
    benign_path = benign or BENIGN
    sk = make_sketch(theta0, 512)
    stats, cur = {}, {}
    gt_attack = {ip24(f.split("_")[0]) for f in attack_files()}
    gt_benign = set()
    for s, d, ts in iter_pcap(benign_path, config.BENIGN_MAX, with_flow=False):
        gt_benign.add((d >> 8) << 8)
        feed(sk, stats, cur, s, d, ts, DUMMY)
    flush(stats, cur)
    cursor, n = 4e9, 0
    for f in attack_files():
        path = os.path.join(ATT_DIR, f)
        first = None
        for s, d, ts in iter_pcap(path, config.ATTACK_MAX, with_flow=False):
            if first is None:
                first = ts
            last = ts
        for s, d, ts in iter_pcap(path, config.ATTACK_MAX, with_flow=False):
            n += 1
            feed(sk, stats, cur, n & 0xFFFFFFFF, d, ts - first + cursor, DUMMY)
        cursor += (last - first) + STAGGER
    flush(stats, cur)
    fl = h_flag(9.2)
    flagged = {k[1]: True for k, s in stats.items() if k[0] == 1 and fl(s)}
    tp, fp, fn, f1v = f1_of(flagged, gt_attack, gt_benign)
    os.makedirs(RES, exist_ok=True)
    with open(os.path.join(RES, tag + ".csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["variant", "tp", "fp", "fn", "f1"])
        w.writerow(["spoofed", tp, fp, fn, round(f1v, 4)])
    print(f"E2 spoofed: tp={tp} fp={fp} fn={fn} F1={f1v:.4f}")


def run_matrix():
    
    from collections import defaultdict
    p = os.path.join(RES, "EXP5_flags.csv")
    if not os.path.exists(p):
        print("run first: run_experiments.py exp1 --dump ../../results/csv/EXP5_flags.csv")
        return
    per = defaultdict(lambda: [0, 0])
    for r in csv.DictReader(open(p)):
        if r["type"] != "benign":
            per[r["type"]][1] += 1
            per[r["type"]][0] += int(r["flagged"])
    os.makedirs(RES, exist_ok=True)
    with open(os.path.join(RES, "EXP5_types.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["type", "tp", "n", "recall"])
        for t in sorted(per):
            w.writerow([t, per[t][0], per[t][1],
                        round(per[t][0] / per[t][1], 4)])
    for t in sorted(per):
        print("exp5 %-16s tp=%d/%d recall=%.3f" % (t, per[t][0], per[t][1],
                                                     per[t][0] / per[t][1]))


def run_compare():
    
    parent = RES
    print("\n=== EXP1 static (512KB, best-τ/best-h, standard F1) ===")
    print("%-20s %7s %7s %7s %7s" % ("method", "tp", "fp", "fn", "F1"))
    for fn in ["02_baselines_detection.csv"]:
        p = os.path.join(parent, fn)
        if not os.path.exists(p):
            continue
        with open(p) as fh:
            for row in csv.DictReader(fh):
                if not row.get("method"):
                    continue
                tp, fpm, fnm = int(row["tp"]), int(row["fp"]), int(row["fn"])
                f1 = 2 * tp / (2 * tp + fnm + fpm)
                print("%-20s %7d %7d %7d %7.3f  (%s)" %
                      (row["method"][:20], tp, fpm, fnm, f1, os.path.basename(fn)))
    mine = os.path.join(RES, "EXP1_static.csv")
    if os.path.exists(mine):
        with open(mine) as fh:
            rows = [r for r in csv.DictReader(fh)]
            fixed = [r for r in rows if r["h_bits"] == "9.2"]
            best = max((r for r in rows if r["h_bits"] != "9.2"),
                       key=lambda r: float(r["f1"]))
            if fixed:
                r = fixed[-1]
                print("%-20s %7s %7s %7s %7.3f  (h=9.2 fixed parameters)" %
                      ("sweep", r["tp"], r["fp"], r["fn"], float(r["f1"])))
            print("%-20s %7s %7s %7s %7.3f  (h=%s best)" %
                  ("sweep", best["tp"], best["fp"], best["fn"],
                   float(best["f1"]), best["h_bits"]))
    print("\n=== EXP4 dynamic (tp/fn/fp prefix/fp event; standard prefix F1 = 2tp/(2tp+fn+fpP)) ===")
    print("%-20s %5s %5s %7s %7s %7s" % ("method", "tp", "fn", "fpP", "fpE", "F1"))
    
    mine = os.path.join(RES, "EXP4_dynamic.csv")
    if os.path.exists(mine):
        with open(mine) as fh:
            r = next(csv.DictReader(fh))
            tp, fn, fpp = int(r["tp"]), int(r["fn"]), int(r["fp_prefixes"])
            f1 = 2 * tp / (2 * tp + fn + fpp)
            print("%-20s %5d %5d %7d %7d %7.3f  median latency=%sms" %
                  ("sweep", tp, fn, fpp, int(r["fp_events"]), f1, r["med_latency_ms"]))
