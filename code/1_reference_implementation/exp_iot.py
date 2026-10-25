import csv
import os
from sweepsketch.pcapio import iter_pcap
from common import WORKERS, DB, DUMMY, RES, config, make_sketch
from exp_cic import run_e1, run_e2, run_e7
IOT_DATASETS = [('IoT-Benign', 'CIC-IoT-2023-Benign.pcap', 'test'), ('IoT-Benign1', 'CIC-IoT-2023-Benign1.pcap', 'calibration'), ('IoT-Benign2', 'CIC-IoT-2023-Benign2.pcap', 'calibration'), ('IoT-Benign3', 'CIC-IoT-2023-Benign3.pcap', 'test')]

def select_targets(path, n=6):
    sk = make_sketch(config.THETA0, 512)
    cur = {}
    stats = {}
    for s, d, ts in iter_pcap(path, config.BENIGN_MAX, with_flow=False):
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
                st = stats.setdefault(key, [0, 0, 0, 0])
                st[0] += 1
                st[1] += r[1]
                st[2] += r[1] * r[1]
                st[3] += r[0]
            cur[key] = [b.n_new, b.pkt]
        else:
            r[0], r[1] = (b.n_new, b.pkt)
    for key, r in cur.items():
        st = stats.setdefault(key, [0, 0, 0, 0])
        st[0] += 1
        st[1] += r[1]
        st[2] += r[1] * r[1]
        st[3] += r[0]
    cands = []
    for key, (n_ep, s_p, ss_p, s_n) in stats.items():
        if n_ep < 20:
            continue
        mean_p = s_p / n_ep
        if not 5 <= mean_p <= 200:
            continue
        var_p = max(0.0, ss_p / n_ep - mean_p * mean_p)
        if var_p ** 0.5 / mean_p > 1.5:
            continue
        if not 1 <= s_n / n_ep <= 8:
            continue
        cands.append(key)
    cands.sort()
    return cands[:n]

def _iot_one(theta0, name, fn, role):
    path = os.path.join(DB, 'benign', fn)
    tgt = select_targets(path)
    pass
    assert tgt, ' : %s' % fn
    _, rows = run_e1(theta0, [512], None, benign=path)
    fixed = [r for r in rows if r[1] == 9.2][-1]
    best = max((r for r in rows if r[1] != 9.2), key=lambda r: r[5])
    tp7, fn7, fpP7, fpE7, f17, lat7 = run_e7(theta0, benign=path, targets=tgt, tag='EXP4_iot_%s' % name)
    return (name, role, fixed[2], fixed[3], fixed[4], round(fixed[5], 4), best[2], best[3], best[4], round(best[5], 4), tp7, fn7, fpP7, fpE7, round(f17, 4), None if lat7 is None else round(lat7, 1))

def run_iot(theta0):
    from multiprocessing import Pool
    tasks = [(theta0, name, fn, role) for name, fn, role in IOT_DATASETS]
    with Pool(min(WORKERS, len(tasks))) as p:
        rows = p.starmap(_iot_one, tasks)
    rows.sort(key=lambda r: r[0])
    os.makedirs(RES, exist_ok=True)
    with open(os.path.join(RES, 'EXP1_static_iot.csv'), 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['dataset', 'role', 'tp_fixed', 'fp_fixed', 'fn_fixed', 'f1_fixed', 'tp_best', 'fp_best', 'fn_best', 'f1_best'])
        w.writerows([(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9]) for r in rows])
    with open(os.path.join(RES, 'EXP4_dynamic_iot.csv'), 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['dataset', 'role', 'tp', 'fn', 'fp_prefixes', 'fp_events', 'f1', 'med_latency_ms'])
        w.writerows([(r[0], r[1], r[10], r[11], r[12], r[13], r[14], r[15]) for r in rows])
    for r in rows:
        pass
    path = os.path.join(DB, 'benign', IOT_DATASETS[0][1])
    run_e2(theta0, benign=path, tag='EXP2_spoofing_iot')
    pass
