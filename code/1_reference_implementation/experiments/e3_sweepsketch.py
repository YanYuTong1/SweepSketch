import csv
import json
import os
import sys
import time
import numpy as np
REV = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REV, 'code', '1_reference_implementation'))
from sweepsketch import config
from sweepsketch.digest import Collector
from sweepsketch.pcapio import iter_pcap
from common import make_sketch
DB = os.path.join(REV, 'database')
OUT = os.path.join(REV, 'results', 'e3')
GT_FRAC = 0.01

def pfx_int(p):
    a, b, c = p.split('/')[0].split('.')[:3]
    return int(a) << 24 | int(b) << 16 | int(c) << 8

def pfx_str(k):
    return '%d.%d.%d.0/24' % (k >> 24 & 255, k >> 16 & 255, k >> 8 & 255)

def run_file(path, gt_prefixes):
    sk = make_sketch(config.THETA0, 512)
    col = Collector()
    t0 = time.time()
    n = 0
    first = None
    pfx_first = {}
    for s, d, ts in iter_pcap(path, max_pkts=1 << 62, with_flow=False):
        if first is None:
            first = ts
        p = d >> 8 << 8
        if p not in pfx_first:
            pfx_first[p] = ts
        sk.process(s, d, ts, col)
        n += 1
    wall = time.time() - t0
    alerts = [a for a in col.alerts if a.level == 1]
    by_key = {}
    for a in alerts:
        by_key.setdefault(a.key, []).append(a.ts)
    gt = {pfx_int(p) for p in gt_prefixes}
    hit = gt & set(by_key)
    fn = gt - hit
    fp = set(by_key) - gt
    first_hit = min((min(by_key[k]) for k in hit), default=None)
    onset = None
    for k in hit:
        if gt and k in pfx_first:
            t = min(by_key[k]) - pfx_first[k]
            onset = t if onset is None else min(onset, t)
    return {'packets': n, 'wall_s': round(wall, 2), 'pps': round(n / wall) if wall else None, 'gt_n': len(gt), 'tp': len(hit), 'fn': len(fn), 'fp_prefixes': sorted((pfx_str(k) for k in fp)), 'fp_events': sum((len(by_key[k]) for k in fp)), 'n_alerts_l1': len(alerts), 'first_alert_s': None if first_hit is None else round(first_hit - first, 3), 'first_alert_onset_s': None if onset is None else round(max(0.0, onset), 3), 'alerted_prefixes': sorted((pfx_str(k) for k in hit)), 'missed_prefixes': sorted((pfx_str(k) for k in fn))}

def main():
    os.makedirs(OUT, exist_ok=True)
    inv = json.load(open(os.path.join(OUT, 'inventory.json')))
    rows = []
    t0 = time.time()
    for r in inv['file_scan']:
        if not r['kind'].startswith('attack'):
            continue
        path = os.path.join(DB, r['path'])
        res = run_file(path, r['gt_prefixes'])
        res.update({'kind': r['kind'], 'file': r['file']})
        rows.append(res)
        print('  %-58s tp=%2d fn=%2d fp=%2d first=%s (%ss)' % (r['file'][:58], res['tp'], res['fn'], len(res['fp_prefixes']), res['first_alert_s'], res['wall_s']), flush=True)
    with open(os.path.join(OUT, 'sweepsketch_files.csv'), 'w', newline='') as f:
        cols = ['kind', 'file', 'packets', 'gt_n', 'tp', 'fn', 'fp_prefixes', 'fp_events', 'n_alerts_l1', 'first_alert_s', 'first_alert_onset_s', 'wall_s', 'pps', 'alerted_prefixes', 'missed_prefixes']
        w = csv.writer(f)
        w.writerow(cols)
        for r in rows:
            w.writerow([r.get(c) if not isinstance(r.get(c), list) else ' '.join((str(x) for x in r[c])) for c in cols])
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from e3_common import FeatureCache
    cache = FeatureCache()
    cic_fi = next((i for i, f in enumerate(cache.files) if f['file'] == 'CIC-IDS-2017-Benign.pcap'))
    bw = cache.file_windows(cic_fi)
    order = bw[np.argsort(cache.win_t[bw])]
    cut_ts = float(cache.win_t[order[int(len(order) * 0.7)]])
    print('benign test cut at ts=%.1f s' % cut_ts, flush=True)
    ben_pfx_cnt = {}
    alerts = []
    sk = make_sketch(config.THETA0, 512)
    col = Collector()
    t1 = time.time()
    n = 0
    for s, d, ts in iter_pcap(os.path.join(DB, 'benign', 'CIC-IDS-2017-Benign.pcap'), max_pkts=1 << 62, with_flow=False):
        sk.process(s, d, ts, col)
        n += 1
        if ts >= cut_ts:
            p = d >> 8 << 8
            ben_pfx_cnt[p] = ben_pfx_cnt.get(p, 0) + 1
    ben_wall = time.time() - t1
    alerts = [a for a in col.alerts if a.level == 1 and a.ts >= cut_ts]
    by_key = {}
    for a in alerts:
        by_key.setdefault(a.key, []).append(a.ts)
    fp = set(by_key) & set(ben_pfx_cnt)
    ben_row = {'packets_total': n, 'packets_test': sum(ben_pfx_cnt.values()), 'test_prefixes': len(ben_pfx_cnt), 'alerts_l1_test': len(alerts), 'fp_prefixes': len(fp), 'fp_prefix_list': sorted((pfx_str(k) for k in fp)), 'wall_s': round(ben_wall, 2), 'pps': round(n / ben_wall) if ben_wall else None, 'cut_ts': cut_ts}
    with open(os.path.join(OUT, 'sweepsketch_benign.csv'), 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['metric', 'value'])
        for k, v in ben_row.items():
            w.writerow([k, ' '.join(v) if isinstance(v, list) else v])
    main = [r for r in rows if r['kind'] == 'attack_main']
    hold = [r for r in rows if r['kind'].startswith('attack_holdout')]
    seg_tp = sum((r['tp'] for r in hold))
    seg_fn = sum((r['fn'] for r in hold))
    hold_gt = set()
    for r in hold:
        hold_gt.update(r['alerted_prefixes'])
        hold_gt.update(r['missed_prefixes'])
    uniq_tp = set()
    uniq_all = set()
    for r in hold:
        uniq_tp.update(r['alerted_prefixes'])
        uniq_all.update(r['alerted_prefixes'])
        uniq_all.update(r['missed_prefixes'])
    lats = [r['first_alert_onset_s'] for r in hold if r['first_alert_onset_s'] is not None]
    lats_file = [r['first_alert_s'] for r in hold if r['first_alert_s'] is not None]

    def pct(v, q):
        return round(float(np.percentile(v, q)), 3) if v else None
    summ = {'main_71': {'files': len(main), 'packets': sum((r['packets'] for r in main)), 'gt_prefixes_unique': len({p for r in main for p in r['alerted_prefixes'] + r['missed_prefixes']}), 'tp': sum((r['tp'] for r in main)), 'fn': sum((r['fn'] for r in main)), 'fp_prefix_instances': sum((len(r['fp_prefixes']) for r in main)), 'fp_events': sum((r['fp_events'] for r in main))}, 'holdout_30': {'files': len(hold), 'packets': sum((r['packets'] for r in hold)), 'seg_tp': seg_tp, 'seg_fn': seg_fn, 'unique_gt': len(uniq_all), 'unique_tp': len(uniq_tp), 'fp_prefix_instances': sum((len(r['fp_prefixes']) for r in hold)), 'fp_events': sum((r['fp_events'] for r in hold)), 'latency_onset_s': {'n': len(lats), 'p50': pct(lats, 50), 'p95': pct(lats, 95), 'p99': pct(lats, 99), 'max': round(max(lats), 3) if lats else None}, 'latency_file_s': {'n': len(lats_file), 'p50': pct(lats_file, 50), 'p95': pct(lats_file, 95), 'p99': pct(lats_file, 99), 'max': round(max(lats_file), 3) if lats_file else None}, 'wall_s_total': round(sum((r['wall_s'] for r in hold)), 1), 'pps_mean': round(float(np.mean([r['pps'] for r in hold])), 1)}, 'benign_test': ben_row, 'same_population_f1': {'note': 'TP/FN = 50 unique holdout prefixes; FP = benign test-segment /24 prefixes alerted by SweepSketch (same population NetRadar uses)', 'tp': len(uniq_tp), 'fn': len(uniq_all) - len(uniq_tp), 'fp': ben_row['fp_prefixes'], 'precision': round(len(uniq_tp) / (len(uniq_tp) + ben_row['fp_prefixes']), 4) if len(uniq_tp) + ben_row['fp_prefixes'] else 0.0, 'recall': round(len(uniq_tp) / len(uniq_all), 4) if uniq_all else 0.0, 'f1': round(2 * len(uniq_tp) / (2 * len(uniq_tp) + (len(uniq_all) - len(uniq_tp)) + ben_row['fp_prefixes']), 4) if uniq_tp else 0.0}, 'wall_s': round(time.time() - t0, 1), 'finished': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'host': os.uname().nodename}
    with open(os.path.join(OUT, 'sweepsketch_summary.json'), 'w') as f:
        json.dump(summ, f, indent=1)
    print(json.dumps(summ, indent=1))
    print('wrote', OUT)
if __name__ == '__main__':
    main()
