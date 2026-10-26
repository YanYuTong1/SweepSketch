import json
import os
import sys
import time
from array import array
import numpy as np
import torch
REV = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REV, 'code', '1_reference_implementation'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sweepsketch import config, pcapio
from sweepsketch.digest import Collector
from common import make_sketch
from baselines.step02_baselines import EntropySketch, bob_hash
from e3_common import FeatureCache
from e3_netradar import predict_blocks_prob, N_POINTS, N_FEAT, N_POS
import e11_fpr as F
NETRADAR = os.environ.get('NETRADAR_DIR', '')
if NETRADAR:
    sys.path.insert(0, os.path.join(NETRADAR, 'detectors'))
from nn_models.loss_sort import pointnet
DB = os.path.join(REV, 'database')
E3 = os.path.join(REV, 'results', 'e3')
OUT = os.path.join(REV, 'results', 'e3_seeds')
EPOCH = 4294967296 / 1000000000.0
BEN = os.path.join(DB, 'benign', 'CIC-IDS-2017-Benign.pcap')
TARGETS = [0.1, 1.0, 5.0]
Z_ENT = 48
DUMMY = Collector()

def pfx_str(k):
    return '%d.%d.%d.0/24' % (k >> 24 & 255, k >> 16 & 255, k >> 8 & 255)

def load_inventory():
    inv = json.load(open(os.path.join(E3, 'inventory.json')))
    hold = [r for r in inv['file_scan'] if r['kind'].startswith('attack_holdout')]
    hold_pfx = {p for r in hold for p in r['gt_prefixes']}
    return (hold, hold_pfx)

def benign_cut():
    fc = FeatureCache()
    fi = next((i for i, f in enumerate(fc.files) if f['file'] == 'CIC-IDS-2017-Benign.pcap'))
    bw = fc.file_windows(fi)
    order = bw[np.argsort(fc.win_t[bw])]
    return (fc, fi, float(fc.win_t[order[int(len(order) * 0.7)]]))

def sk_events_benign():
    cache = os.path.join(OUT, 'cache_sk_benign_events.json')
    if os.path.exists(cache):
        return json.load(open(cache))
    _, _, cut = benign_cut()
    sk = make_sketch(config.THETA0, 512)
    scores = {}
    for s, d, ts in pcapio.iter_pcap(BEN, max_pkts=1 << 62, with_flow=False):
        key = d >> 8 << 8
        sk.process(0, d, ts, DUMMY)
        if ts < cut:
            continue
        i = sk.l1.idx(key)
        b = sk.l1.buckets[i]
        if b is None or b.key != key:
            continue
        gate = max(config.K_ALARM, 2 * b.n_ewma, config.K_ALARM_QUIET if b.n_ewma < config.N_EWMA_QUIET else 0)
        if b.n_new >= gate:
            k = '%d|%d' % (int(ts // EPOCH), key)
            if b.C > scores.get(k, 0):
                scores[k] = b.C
    json.dump(scores, open(cache, 'w'))
    return scores

def sk_events_holdout(hold):
    cache = os.path.join(OUT, 'cache_sk_attack_events.json')
    if os.path.exists(cache):
        return json.load(open(cache))
    out = {}
    for r in hold:
        path = os.path.join(DB, r['path'])
        sk = make_sketch(config.THETA0, 512)
        scores = {}
        for s, d, ts in pcapio.iter_pcap(path, max_pkts=1 << 62, with_flow=False):
            key = d >> 8 << 8
            sk.process(0, d, ts, DUMMY)
            i = sk.l1.idx(key)
            b = sk.l1.buckets[i]
            if b is None or b.key != key:
                continue
            gate = max(config.K_ALARM, 2 * b.n_ewma, config.K_ALARM_QUIET if b.n_ewma < config.N_EWMA_QUIET else 0)
            if b.n_new >= gate:
                k = '%d|%d' % (int(ts // EPOCH), key)
                if b.C > scores.get(k, 0):
                    scores[k] = b.C
        out[r['file']] = {'prefixes': r['gt_prefixes'], 'scores': {k: v for k, v in scores.items() if pfx_str(int(k.split('|')[1])) in set(r['gt_prefixes'])}}
    json.dump(out, open(cache, 'w'))
    return out

def entropy_events_benign():
    cache = os.path.join(OUT, 'cache_ent_benign_events.json')
    if os.path.exists(cache):
        return json.load(open(cache))
    _, _, cut = benign_cut()
    ep = {}
    for s, d, ts in pcapio.iter_pcap(BEN, max_pkts=1 << 62, with_flow=False):
        if ts < cut:
            continue
        e = int(ts // EPOCH)
        p = d >> 8 << 8
        dd = ep.setdefault((e, p), {})
        dd[d] = dd.get(d, 0) + 1
    scores = {'%d|%d' % (e, p): F.score_counts(cnt, Z_ENT) for (e, p), cnt in ep.items()}
    json.dump(scores, open(cache, 'w'))
    return scores

def entropy_events_holdout(hold):
    cache = os.path.join(OUT, 'cache_ent_attack_events.json')
    if os.path.exists(cache):
        return json.load(open(cache))
    out = {}
    for r in hold:
        path = os.path.join(DB, r['path'])
        gtset = set(r['gt_prefixes'])
        ep = {}
        for s, d, ts in pcapio.iter_pcap(path, max_pkts=1 << 62, with_flow=False):
            p = pfx_str(d >> 8 << 8)
            if p not in gtset:
                continue
            e = int(ts // EPOCH)
            dd = ep.setdefault((e, d >> 8 << 8), {})
            dd[d] = dd.get(d, 0) + 1
        out[r['file']] = {'prefixes': r['gt_prefixes'], 'scores': {'%d|%d' % (e, p): F.score_counts(cnt, Z_ENT) for (e, p), cnt in ep.items()}}
    json.dump(out, open(cache, 'w'))
    return out

def _load_models():
    dev = torch.device('mps' if torch.backends.mps.is_available() else 'cpu')
    out = {}
    for tag in ('p1_full_seed1', 'p1_full_seed2'):
        p = os.path.join(E3, 'model_' + tag + '.pt')
        m = pointnet(2, N_FEAT, N_POINTS).to(dev)
        m.load_state_dict(torch.load(p, map_location=dev))
        m.eval()
        out[tag] = m
    return out

def nr_benign_events(cache, models):
    cache_f = os.path.join(OUT, 'cache_nr_benign_events.json')
    if os.path.exists(cache_f):
        return json.load(open(cache_f))
    fi = next((i for i, f in enumerate(cache.files) if f['file'] == 'CIC-IDS-2017-Benign.pcap'))
    bw = cache.file_windows(fi)
    order = bw[np.argsort(cache.win_t[bw])]
    test = order[int(len(order) * 0.7):]
    rng = np.random.default_rng(0)
    out = {tag: {} for tag in models}
    for w in test:
        a, b = cache.window_rows(w)
        rows = np.arange(a, b)
        if len(rows) > N_POINTS:
            rows = rng.choice(rows, N_POINTS, replace=False)
        need = N_POINTS - len(rows)
        if need:
            rows = np.concatenate([rows, rng.choice(rows, need, replace=True)])
        X = cache.row_X[rows][None, :, :]
        tkey = int(round(float(cache.win_t[w]) * 100))
        for tag, m in models.items():
            _, prob = predict_blocks_prob(m, next(m.parameters()).device, X, bs=64)
            hosts = cache.row_host[rows]
            for h, p in zip(hosts, prob[0]):
                pfx = int(h >> 8 << 8)
                k = '%d|%d' % (tkey, pfx)
                if p > out[tag].get(k, -1):
                    out[tag][k] = float(p)
    json.dump(out, open(cache_f, 'w'))
    return out

def nr_attack_events(cache, models):
    cache_f = os.path.join(OUT, 'cache_nr_attack_events.json')
    if os.path.exists(cache_f):
        return json.load(open(cache_f))
    inv = json.load(open(os.path.join(E3, 'inventory.json')))
    hold = [r for r in inv['file_scan'] if r['kind'].startswith('attack_holdout')]
    out = {tag: {} for tag in models}
    for r in hold:
        fi = next((i for i, f in enumerate(cache.files) if f['file'] == r['file'] and f['kind'] == r['kind']))
        gtset = set(r['gt_prefixes'])
        rng = np.random.default_rng(0)
        blocks, meta = ([], [])
        for w in cache.file_windows(fi):
            a, b = cache.window_rows(w)
            pf = cache.row_pfx[a:b]
            rows = np.arange(a, b)
            rows = rows[[pfx_str(int(x)) in gtset for x in pf]]
            if len(rows) == 0:
                continue
            if len(rows) > 128:
                rows = rng.choice(rows, 128, replace=False)
            t = float(cache.win_t[w])
            for j in range(0, len(rows), N_POS):
                chunk = rows[j:j + N_POS]
                need = N_POINTS - len(chunk)
                Xb = cache.row_X[rng.integers(0, len(cache.row_X), need)]
                X = np.concatenate([cache.row_X[chunk], Xb])
                blocks.append(X)
                meta.append((t, chunk))
        if not blocks:
            continue
        Xall = np.stack(blocks)
        for tag, m in models.items():
            _, prob = predict_blocks_prob(m, next(m.parameters()).device, Xall, bs=128)
            for bi, (t, chunk) in enumerate(meta):
                tkey = int(round(t * 100))
                hosts = cache.row_host[chunk]
                for h, p in zip(hosts, prob[bi][:len(chunk)]):
                    pfx = int(h >> 8 << 8)
                    k = '%d|%d' % (tkey, pfx)
                    if p > out[tag].get(k, -1):
                        out[tag][k] = float(p)
    json.dump(out, open(cache_f, 'w'))
    return out

def allowed_events(budget, n_pfx, days):
    return budget * n_pfx * days

def choose_tau(vals, allowed):
    v = np.sort(np.asarray(vals))[::-1]
    allowed = int(np.floor(allowed))
    if len(v) == 0:
        return 1.0
    if allowed <= 0:
        return float(v[0]) + 1e-09
    if allowed >= len(v):
        return float(v.min()) - 1e-09
    return float(v[allowed])

def main():
    os.makedirs(OUT, exist_ok=True)
    t0 = time.time()
    hold, hold_pfx = load_inventory()
    fc, _, cut = benign_cut()
    last_ts = max(fc.win_t) if len(fc.win_t) else 0.0
    days = max(1.0, float(last_ts) - cut) / 86400.0
    ben_pfx = set()
    fi = next((i for i, f in enumerate(fc.files) if f['file'] == 'CIC-IDS-2017-Benign.pcap'))
    bw = fc.file_windows(fi)
    order = bw[np.argsort(fc.win_t[bw])]
    for w in order[int(len(order) * 0.7):]:
        a, b = fc.window_rows(w)
        ben_pfx.update((int(x) for x in np.unique(fc.row_pfx[a:b])))
    n_ben_pfx = len(ben_pfx)
    days = max(1.0, float(fc.win_t[order[-1]]) - cut) / 86400.0
    print('benign test prefixes %d, days %.4f' % (n_ben_pfx, days), flush=True)
    models = _load_models()
    sk_b = sk_events_benign()
    sk_a = sk_events_holdout(hold)
    ent_b = entropy_events_benign()
    ent_a = entropy_events_holdout(hold)
    nr_b = nr_benign_events(fc, models)
    nr_a = nr_attack_events(fc, models)
    print('scores ready %.0fs' % (time.time() - t0), flush=True)
    rows = []
    for method, ben, att in (('sweepsketch', sk_b, sk_a), ('entropy', ent_b, ent_a)):
        vals = np.asarray(list(ben.values())) if ben else np.zeros(1)
        for target in TARGETS:
            tau = choose_tau(vals, allowed_events(target, n_ben_pfx, days))
            actual = round(float((vals > tau).sum()) / n_ben_pfx / days, 3)
            uniq_det = set()
            lat = []
            for f, d in att.items():
                for p in d['prefixes']:
                    hits = [int(k.split('|')[0]) * EPOCH for k, s in d['scores'].items() if pfx_str(int(k.split('|')[1])) == p and s > tau]
                    if hits:
                        uniq_det.add(p)
                        lat.append(min(hits))
            rows.append({'method': method, 'fpr_per_pfx_day': target, 'fpr_actual': actual, 'tau': round(tau, 4), 'recall': round(len(uniq_det) / len(hold_pfx), 4), 'tp': len(uniq_det), 'attack_pop': len(hold_pfx), 'latency_p50': round(float(np.median(lat)), 3) if lat else None})
    for tag in models:
        vals = np.asarray(list(nr_b[tag].values())) if nr_b.get(tag) else np.zeros(1)
        for target in TARGETS:
            tau = choose_tau(vals, allowed_events(target, n_ben_pfx, days))
            actual = round(float((vals > tau).sum()) / n_ben_pfx / days, 3)
            uniq_det = set()
            lat = []
            for p in hold_pfx:
                hits = [int(k.split('|')[0]) / 100.0 for k, s in nr_a.get(tag, {}).items() if pfx_str(int(k.split('|')[1])) == p and s > tau]
                if hits:
                    uniq_det.add(p)
                    lat.append(min(hits))
            rows.append({'method': 'netradar_' + tag, 'fpr_per_pfx_day': target, 'fpr_actual': actual, 'tau': round(tau, 4), 'recall': round(len(uniq_det) / len(hold_pfx), 4), 'tp': len(uniq_det), 'attack_pop': len(hold_pfx), 'latency_p50': round(float(np.median(lat)), 3) if lat else None})
    import csv
    with open(os.path.join(OUT, 'e3_fpr_operational.csv'), 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    summ = {'population': {'attack_prefixes': len(hold_pfx), 'benign_test_prefixes': n_ben_pfx, 'benign_test_days': round(days, 5), 'absent_main_prefixes': sorted({p for r in json.load(open(os.path.join(E3, 'inventory.json')))['file_scan'] if r['kind'] == 'attack_main' for p in r['gt_prefixes']} - hold_pfx)}, 'fpr_definition': 'alarms per prefix per day on the benign test timeline; unit = 4.29 s epoch (SK/entropy) / 1 s window (NR)', 'rows': rows, 'wall_s': round(time.time() - t0, 1), 'finished': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
    with open(os.path.join(OUT, 'e3_fpr_operational.json'), 'w') as f:
        json.dump(summ, f, indent=1)
    print(json.dumps(rows, indent=1))
if __name__ == '__main__':
    main()
