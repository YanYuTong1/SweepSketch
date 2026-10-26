import json
import os
import sys
import time
import numpy as np
REV = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REV, 'code', '1_reference_implementation'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sweepsketch import config
from sweepsketch.digest import Collector
from common import make_sketch
from baselines.step02_baselines import EntropySketch
import e11_gen as G
OUT = os.path.join(REV, 'results', 'e11')
EPOCH = G.EPOCH
TAU_E1 = 4.37
TOL = 0.25

def epoch_of(ts):
    return int(ts // EPOCH)

def load_benign():
    z = np.load(os.path.join(OUT, 'e11_benign_stream.npz'))
    return (z['dst'].astype(np.int64), z['ts'].astype(np.float64))

def attack_stream(cfg, meta):
    windows = meta['windows']
    dur = meta['dur']
    S = meta['S']
    rate = meta['rate']
    seed = meta['seed']
    rng = np.random.default_rng(seed * 1000003 + int(dur * 100) * 7919 + S * 104729 + rate)
    return G.attack_packets(windows, rng)

def run_sk(ben_dst, ben_ts, att):
    sk = make_sketch(config.THETA0, 512)
    col = Collector()
    n = len(ben_dst)
    all_dst = np.concatenate([ben_dst, np.asarray([a[1] for a in att], dtype=np.int64)])
    all_ts = np.concatenate([ben_ts, np.asarray([a[0] for a in att], dtype=np.float64)])
    order = np.argsort(all_ts, kind='stable')
    for i in order:
        sk.process(0, int(all_dst[i]), float(all_ts[i]), col)
    return [a for a in col.alerts if a.level == 1]

def benign_entropy_table(ben_dst, ben_ts):
    ep_data = {}
    for d, ts in zip(ben_dst, ben_ts):
        e = epoch_of(ts)
        pfx = int(d) >> 8 << 8
        dd = ep_data.setdefault(e, {}).setdefault(pfx, {})
        dd[int(d)] = dd.get(int(d), 0) + 1
    scores = {}
    zz = {}
    for e, pfxs in ep_data.items():
        n_pfx = len(pfxs)
        per_pfx = max(2 * 32, 512 * 1024 * 8 // max(n_pfx, 1))
        z = max(2, per_pfx // 32)
        zz[e] = z
        for pfx, cnt in pfxs.items():
            sk = EntropySketch(z)
            for d, c in cnt.items():
                for _ in range(c):
                    sk.insert(0, d)
            scores[e, pfx] = sk._score(sk.bm[pfx])
    vals = np.asarray(list(scores.values()))
    tau_fpr1 = float(np.percentile(vals, 99)) if len(vals) else 1.0
    return (scores, zz, tau_fpr1, vals)

def attack_entropy_score(windows, att, z):
    ep_pfx = {}
    for ts, d in att:
        e = epoch_of(ts)
        pfx = int(d) >> 8 << 8
        dd = ep_pfx.setdefault((e, pfx), {})
        dd[int(d)] = dd.get(int(d), 0) + 1
    sc = {}
    for (e, pfx), cnt in ep_pfx.items():
        sk = EntropySketch(z)
        for d, c in cnt.items():
            for _ in range(c):
                sk.insert(0, d)
        sc[e, pfx] = sk._score(sk.bm[pfx])
    out = []
    for w in windows:
        e = epoch_of(w['start'])
        out.append(sc.get((e, w['target']), 0.0))
    return out

def eval_windows(windows, alerts):
    by_key = {}
    for a in alerts:
        by_key.setdefault(a.key, []).append(a.ts)
    det_s = det_e = 0
    lat = []
    for w in windows:
        ts = by_key.get(w['target'], [])
        hit = [x for x in ts if w['start'] <= x <= w['end'] + TOL]
        if hit:
            det_s += 1
            lat.append(min(hit) - w['start'])
        e0 = epoch_of(w['start'])
        if any((epoch_of(x) == e0 for x in ts)):
            det_e += 1
    return (det_s, det_e, lat)

def pct(v, q):
    return round(float(np.percentile(v, q)), 3) if len(v) else None

def main():
    os.makedirs(OUT, exist_ok=True)
    t0 = time.time()
    ben_dst, ben_ts = load_benign()
    print('benign', len(ben_dst), 'packets', flush=True)
    benign_pfx = {int(d) >> 8 << 8 for d in ben_dst}
    print('benign prefixes', len(benign_pfx), flush=True)
    t1 = time.time()
    ben_scores, zz, tau_fpr1, vals = benign_entropy_table(ben_dst, ben_ts)
    print('benign entropy table: %d prefix-epochs, z range %s, tau_fpr1=%.3f (%.1fs)' % (len(ben_scores), (min(zz.values()), max(zz.values())), tau_fpr1, time.time() - t1), flush=True)
    fp_ev = {tau: 0 for tau in (TAU_E1, tau_fpr1)}
    fp_pfx = {tau: set() for tau in (TAU_E1, tau_fpr1)}
    for (e, pfx), s in ben_scores.items():
        for tau in fp_ev:
            if s > tau:
                fp_ev[tau] += 1
                fp_pfx[tau].add(pfx)
    cfgs = []
    for dur in G.DURATIONS:
        for S in G.SWEEPS:
            for rate in G.RATES:
                for seed in G.SEEDS:
                    cfgs.append('dur%g_S%d_r%d_s%d' % (dur, S, rate, seed))
    rows = []
    for cfg in cfgs:
        meta = json.load(open(os.path.join(OUT, 'attack_' + cfg + '.json')))
        windows = meta['windows']
        att = attack_stream(cfg, meta)
        t2 = time.time()
        alerts = run_sk(ben_dst, ben_ts, att)
        sk_s, sk_e, sk_lat = eval_windows(windows, alerts)
        sk_fp = [a for a in alerts if a.key >> 8 << 8 not in {w['target'] for w in windows}]
        sk_fp_pfx = len({a.key for a in sk_fp})
        z = int(np.median([zz[e] for e in zz]))
        esc = attack_entropy_score(windows, att, z)
        ent = {}
        for tau_name, tau in (('ent_E1tau4.37', TAU_E1), ('ent_fpr1', tau_fpr1)):
            e0 = 0
            for w, s in zip(windows, esc):
                if s > tau:
                    e0 += 1
            ent[tau_name] = e0
        rows.append({'cfg': cfg, 'dur': meta['dur'], 'S': meta['S'], 'rate': meta['rate'], 'seed': meta['seed'], 'windows': len(windows), 'sk_detect_strict': sk_s, 'sk_detect_epoch': sk_e, 'sk_recall_strict': round(sk_s / len(windows), 4), 'sk_recall_epoch': round(sk_e / len(windows), 4), 'sk_lat_p50': pct(sk_lat, 50), 'sk_lat_p95': pct(sk_lat, 95), 'sk_lat_max': round(max(sk_lat), 3) if sk_lat else None, 'sk_alerts_l1': len(alerts), 'sk_fp_prefixes': sk_fp_pfx, 'sk_fp_events': len(sk_fp), 'ent_detect_E1tau': ent['ent_E1tau4.37'], 'ent_recall_E1tau': round(ent['ent_E1tau4.37'] / len(windows), 4), 'ent_detect_fpr1': ent['ent_fpr1'], 'ent_recall_fpr1': round(ent['ent_fpr1'] / len(windows), 4), 'wall_s': round(time.time() - t2, 2)})
        print('  %-22s SK %.3f/%.3f  ENT %.3f/%.3f  (%.1fs)' % (cfg, rows[-1]['sk_recall_strict'], rows[-1]['sk_recall_epoch'], rows[-1]['ent_recall_E1tau'], rows[-1]['ent_recall_fpr1'], rows[-1]['wall_s']), flush=True)

    def agg(mask):
        sel = [r for r in rows if mask(r)]
        n = sum((r['windows'] for r in sel))
        return {'runs': len(sel), 'windows': n, 'sk_recall_strict': round(sum((r['sk_detect_strict'] for r in sel)) / n, 4), 'sk_recall_epoch': round(sum((r['sk_detect_epoch'] for r in sel)) / n, 4), 'ent_recall_E1tau': round(sum((r['ent_detect_E1tau'] for r in sel)) / n, 4), 'ent_recall_fpr1': round(sum((r['ent_detect_fpr1'] for r in sel)) / n, 4), 'fp_prefixes_sk': sum((r['sk_fp_prefixes'] for r in sel)), 'fp_events_sk': sum((r['sk_fp_events'] for r in sel))}
    summary = {'by_dur': {str(d): agg(lambda r, d=d: r['dur'] == d) for d in G.DURATIONS}, 'by_S': {str(s): agg(lambda r, s=s: r['S'] == s) for s in G.SWEEPS}, 'by_rate': {str(x): agg(lambda r, x=x: r['rate'] == x) for x in G.RATES}, 'overall': agg(lambda r: True), 'entropy_tau': {'E1_tau': TAU_E1, 'fpr1_tau': round(tau_fpr1, 4)}, 'entropy_benign_scores': {'n_prefix_epochs': len(ben_scores), 'p50': round(float(np.percentile(vals, 50)), 3), 'p90': round(float(np.percentile(vals, 90)), 3), 'p99': round(float(np.percentile(vals, 99)), 3), 'max': round(float(vals.max()), 3), 'fp_prefixes_at_E1tau': len(fp_pfx[TAU_E1]), 'fp_events_at_E1tau': fp_ev[TAU_E1], 'fp_prefixes_at_fpr1': len(fp_pfx[tau_fpr1]), 'fp_events_at_fpr1': fp_ev[tau_fpr1]}, 'sk_benign_prefixes': len(benign_pfx), 'wall_s': round(time.time() - t0, 1), 'host': os.uname().nodename, 'finished': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
    with open(os.path.join(OUT, 'e11_sk_entropy_summary.json'), 'w') as f:
        json.dump(summary, f, indent=1)
    import csv
    with open(os.path.join(OUT, 'e11_sk_entropy_runs.csv'), 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(json.dumps(summary, indent=1))
    print('done', round(time.time() - t0, 1), 's')
if __name__ == '__main__':
    main()
