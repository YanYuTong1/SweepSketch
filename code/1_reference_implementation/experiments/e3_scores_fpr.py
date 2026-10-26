import csv
import glob
import json
import os
import sys
import time
import numpy as np
REV = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REV, 'code', '1_reference_implementation'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sweepsketch import config, pcapio
from sweepsketch.digest import Collector
from common import feed, flush, make_sketch
from baselines.step02_baselines import EntropySketch, bob_hash
from array import array
DB = os.path.join(REV, 'database')
E3 = os.path.join(REV, 'results', 'e3')
SEEDS = os.path.join(REV, 'results', 'e3_seeds')
OUT = SEEDS
EPOCH = 4294967296 / 1000000000.0
Z_ENT = 48
BEN = os.path.join(DB, 'benign', 'CIC-IDS-2017-Benign.pcap')

def pfx_str(k):
    return '%d.%d.%d.0/24' % (k >> 24 & 255, k >> 16 & 255, k >> 8 & 255)

def pfx_int(p):
    a, b, c = p.split('/')[0].split('.')[:3]
    return int(a) << 24 | int(b) << 16 | int(c) << 8

def threshold_1fpr(benign_scores):
    v = np.asarray(list(benign_scores.values()))
    return (float(np.percentile(v, 99)), v)

def fpr_at(scores, tau):
    v = np.asarray(list(scores.values()))
    return float((v > tau).mean())

def recall_at(attack_scores, tau):
    if not attack_scores:
        return (0.0, 0)
    det = sum((1 for s in attack_scores.values() if s > tau))
    return (det / len(attack_scores), len(attack_scores))

def sk_scores():
    cache_file = os.path.join(OUT, 'sk_scores.json')
    if os.path.exists(cache_file):
        return json.load(open(cache_file))
    inv = json.load(open(os.path.join(E3, 'inventory.json')))
    hold = [r for r in inv['file_scan'] if r['kind'].startswith('attack_holdout')]
    att = {}
    t0 = time.time()
    for r in hold:
        path = os.path.join(DB, r['path'])
        sk = make_sketch(config.THETA0, 512)
        stats, cur = ({}, {})
        col = Collector()
        for s, d, ts in pcapio.iter_pcap(path, max_pkts=1 << 62, with_flow=False):
            feed(sk, stats, cur, s, d, ts, col)
        flush(stats, cur)
        for (lvl, key), v in stats.items():
            if lvl != 1:
                continue
            p = pfx_str(key)
            att[p] = max(att.get(p, -1.0), float(v[0]))
    sk = make_sketch(config.THETA0, 512)
    stats, cur = ({}, {})
    col = Collector()
    for s, d, ts in pcapio.iter_pcap(BEN, max_pkts=1 << 62, with_flow=False):
        feed(sk, stats, cur, s, d, ts, col)
    flush(stats, cur)
    ben = {}
    for (lvl, key), v in stats.items():
        if lvl == 1:
            ben[pfx_str(key)] = float(v[0])
    out = {'attack': att, 'benign': ben, 'wall_s': round(time.time() - t0, 1)}
    json.dump(out, open(cache_file, 'w'))
    return out

def score_counts(cnt, z=Z_ENT):
    sk = EntropySketch(z)
    ctrs = array('I', [0]) * z
    g = sk.g
    for d, c in cnt.items():
        key = d.to_bytes(4, 'little')
        for i in range(g):
            ctrs[bob_hash(key, 49408 + i) % z] += c
    return sk._score(ctrs)

def entropy_scores_file(path):
    ep = {}
    for s, d, ts in pcapio.iter_pcap(path, max_pkts=1 << 62, with_flow=False):
        e = int(ts // EPOCH)
        p = d >> 8 << 8
        dd = ep.setdefault((e, p), {})
        dd[d] = dd.get(d, 0) + 1
    out = {}
    for (e, p), cnt in ep.items():
        s = score_counts(cnt)
        if p not in out or s > out[p]:
            out[p] = s
    return out

def entropy_scores():
    cache_file = os.path.join(OUT, 'entropy_scores.json')
    if os.path.exists(cache_file):
        return json.load(open(cache_file))
    inv = json.load(open(os.path.join(E3, 'inventory.json')))
    hold = [r for r in inv['file_scan'] if r['kind'].startswith('attack_holdout')]
    att = {}
    t0 = time.time()
    for r in hold:
        path = os.path.join(DB, r['path'])
        for p, s in entropy_scores_file(path).items():
            key = pfx_str(p)
            att[key] = max(att.get(key, -1.0), s)
        print('  entropy', r['file'][:50], flush=True)
    cache = json.load(open(os.path.join(E3, 'inventory.json')))
    cic = next((r for r in cache['file_scan'] if r['file'] == 'CIC-IDS-2017-Benign.pcap'))
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from e3_common import FeatureCache
    fc = FeatureCache()
    fi = next((i for i, f in enumerate(fc.files) if f['file'] == 'CIC-IDS-2017-Benign.pcap'))
    bw = fc.file_windows(fi)
    order = bw[np.argsort(fc.win_t[bw])]
    cut = float(fc.win_t[order[int(len(order) * 0.7)]])
    ep = {}
    for s, d, ts in pcapio.iter_pcap(BEN, max_pkts=1 << 62, with_flow=False):
        if ts < cut:
            continue
        e = int(ts // EPOCH)
        p = d >> 8 << 8
        dd = ep.setdefault((e, p), {})
        dd[d] = dd.get(d, 0) + 1
    ben = {}
    for (e, p), cnt in ep.items():
        s = score_counts(cnt)
        if p not in ben or s > ben[p]:
            ben[p] = s
    out = {'attack': att, 'benign': {pfx_str(p): s for p, s in ben.items()}, 'cut_ts': cut, 'wall_s': round(time.time() - t0, 1)}
    json.dump(out, open(cache_file, 'w'))
    return out

def netradar_runs():
    inv = json.load(open(os.path.join(E3, 'inventory.json')))
    hold = {p for r in inv['file_scan'] if r['kind'].startswith('attack_holdout') for p in r['gt_prefixes']}
    main = {p for r in inv['file_scan'] if r['kind'] == 'attack_main' for p in r['gt_prefixes']}
    absent = main - hold
    out = []
    for f in sorted(glob.glob(os.path.join(SEEDS, 'netradar_p2_s*_f*.json'))):
        d = json.load(open(f))
        fold_pfx = set(d['prefix_metrics'].get('alerted_prefixes', [])) | set(d['prefix_metrics'].get('missed_prefixes', []))
        pm = d['prefix_metrics']
        gt_hold = [p for p in set(pm.get('alerted_prefixes', [])) | set(pm.get('missed_prefixes', []))]
        scores = {}
        for k, dd in d.get('prefix_max_score', {}).items():
            for p, s in dd.items():
                scores[p] = max(scores.get(p, -1.0), s)
        out.append({'file': os.path.basename(f), 'seed': d['seed'], 'fold': d['fold'], 'scores': scores, 'benign': d.get('benign_max_score', {}), 'gt_all': gt_hold, 'gt_hold': [p for p in gt_hold if p in hold], 'absent': [p for p in gt_hold if p not in hold]})
    return (out, absent)

def main():
    os.makedirs(OUT, exist_ok=True)
    t0 = time.time()
    nr, absent = netradar_runs()
    print('netradar runs', len(nr), 'absent prefixes', sorted(absent), flush=True)
    sk = sk_scores()
    ent = entropy_scores()
    print('sk wall', sk['wall_s'], 'entropy wall', ent['wall_s'], flush=True)
    rows = []
    for r in nr:
        tau, bvals = threshold_1fpr(r['benign'])
        rec, n = recall_at({p: r['scores'][p] for p in r['gt_hold'] if p in r['scores']}, tau)
        rows.append({'method': 'netradar', 'seed': r['seed'], 'fold': r['fold'], 'tau': round(tau, 6), 'benign_n': len(bvals), 'benign_fpr': round(float((bvals > tau).mean()), 4), 'recall': round(rec, 4), 'attack_n': n, 'absent': len(r['absent'])})
    tau_sk, bv = threshold_1fpr(sk['benign'])
    hold_pfx = set((pfx_str(pfx_int(p)) for p in {p for r in nr for p in r['gt_hold']}))
    att_scores = {p: sk['attack'].get(p, -1.0) for p in hold_pfx}
    rec, n = recall_at(att_scores, tau_sk)
    rows.append({'method': 'sweepsketch', 'seed': -1, 'fold': -1, 'tau': round(tau_sk, 4), 'benign_n': len(bv), 'benign_fpr': round(float((bv > tau_sk).mean()), 4), 'recall': round(rec, 4), 'attack_n': n, 'absent': 0})
    tau_e, bv = threshold_1fpr(ent['benign'])
    att_scores = {p: ent['attack'].get(p, -1.0) for p in hold_pfx}
    rec, n = recall_at(att_scores, tau_e)
    rows.append({'method': 'entropy', 'seed': -1, 'fold': -1, 'tau': round(tau_e, 4), 'benign_n': len(bv), 'benign_fpr': round(float((bv > tau_e).mean()), 4), 'recall': round(rec, 4), 'attack_n': n, 'absent': 0})
    with open(os.path.join(OUT, 'fixed_fpr_runs.csv'), 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    nr_rows = [r for r in rows if r['method'] == 'netradar']
    summ = {'population': {'attack_prefixes': len(hold_pfx), 'absent_main_prefixes_excluded': sorted(absent), 'benign_prefixes_netradar': len(nr[0]['benign']) if nr else 0}, 'NetRadar': {'runs': len(nr_rows), 'recall_mean': round(float(np.mean([r['recall'] for r in nr_rows])), 4), 'recall_min': min((r['recall'] for r in nr_rows)), 'recall_max': max((r['recall'] for r in nr_rows)), 'tau_mean': round(float(np.mean([r['tau'] for r in nr_rows])), 6), 'benign_fpr_mean': round(float(np.mean([r['benign_fpr'] for r in nr_rows])), 4)}, 'SweepSketch': {k: rows[-2][k] for k in ('tau', 'recall', 'attack_n', 'benign_fpr')}, 'EntropySketch_4.29s': {k: rows[-1][k] for k in ('tau', 'recall', 'attack_n', 'benign_fpr')}, 'wall_s': round(time.time() - t0, 1), 'note': '1% FPR = 99th percentile of benign-prefix scores; attack population = 50 holdout-covered prefixes (5 main prefixes with no holdout data excluded)', 'finished': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
    with open(os.path.join(OUT, 'fixed_fpr_summary.json'), 'w') as f:
        json.dump(summ, f, indent=1)
    print(json.dumps(summ, indent=1))
if __name__ == '__main__':
    main()
