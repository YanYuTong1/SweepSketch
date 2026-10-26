import csv
import json
import os
import sys
import time
import numpy as np
import torch
REV = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REV, 'code', '1_reference_implementation'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sweepsketch import config
from sweepsketch.digest import Collector
from common import make_sketch
from baselines.step02_baselines import EntropySketch, bob_hash
from array import array
from e3_common import FeatureCache, load_raw_file
import e11_gen as G
NETRADAR = os.environ.get('NETRADAR_DIR', '')
if NETRADAR:
    sys.path.insert(0, os.path.join(NETRADAR, 'detectors'))
from nn_models.loss_sort import pointnet
OUT = os.path.join(REV, 'results', 'e11')
EPOCH = G.EPOCH
T_SEC = 600.0
N_PFX = 878
TARGET_FPR = [0.1, 1.0, 5.0]
N_POINTS, N_FEAT = (256, 11)
POOL_HI = (50706, 50707)
DUMMY = Collector()

def pfx_str(k):
    return '%d.%d.%d.0/24' % (k >> 24 & 255, k >> 16 & 255, k >> 8 & 255)

def load_benign():
    z = np.load(os.path.join(OUT, 'e11_benign_stream.npz'))
    return (z['dst'].astype(np.int64), z['ts'].astype(np.float64))

def attack_stream(meta):
    win = meta['windows']
    rng = np.random.default_rng(meta['seed'] * 1000003 + int(meta['dur'] * 100) * 7919 + meta['S'] * 104729 + meta['rate'])
    return G.attack_packets(win, rng)

def sk_epoch_scores(dst, ts):
    sk = make_sketch(config.THETA0, 512)
    out = {}
    for d, t in zip(dst, ts):
        key = int(d) >> 8 << 8
        sk.process(0, int(d), float(t), DUMMY)
        i = sk.l1.idx(key)
        b = sk.l1.buckets[i]
        if b is None or b.key != key:
            continue
        gate = max(config.K_ALARM, 2 * b.n_ewma, config.K_ALARM_QUIET if b.n_ewma < config.N_EWMA_QUIET else 0)
        if b.n_new >= gate:
            k = (int(float(t) // EPOCH), key)
            if b.C > out.get(k, 0):
                out[k] = b.C
    return out

def score_counts(cnt, z=48):
    sk = EntropySketch(z)
    ctrs = array('I', [0]) * z
    g = sk.g
    for d, c in cnt.items():
        key = int(d).to_bytes(4, 'little')
        for i in range(g):
            ctrs[bob_hash(key, 49408 + i) % z] += c
    return sk._score(ctrs)

def entropy_epoch_scores(dst, ts):
    ep = {}
    for d, t in zip(dst, ts):
        e = int(float(t) // EPOCH)
        p = int(d) >> 8 << 8
        ep.setdefault((e, p), {})
    for d, t in zip(dst, ts):
        e = int(float(t) // EPOCH)
        p = int(d) >> 8 << 8
        ep[e, p][int(d)] = ep[e, p].get(int(d), 0) + 1
    return {k: score_counts(c) for k, c in ep.items()}

def entropy_attack_scores(meta):
    win = meta['windows']
    att = attack_stream(meta)
    ep = {}
    for ts, d in att:
        e = int(ts // EPOCH)
        p = int(d) >> 8 << 8
        ep.setdefault((e, p), {})
        ep[e, p][int(d)] = ep[e, p].get(int(d), 0) + 1
    return ({k: score_counts(c) for k, c in ep.items()}, win)
MODELS = {}

def load_models():
    for tag in ('p1_full_seed1', 'p1_full_seed2'):
        p = os.path.join(REV, 'results', 'e3', 'model_' + tag + '.pt')
        m = pointnet(2, N_FEAT, N_POINTS).to(torch.device('mps' if torch.backends.mps.is_available() else 'cpu'))
        dev = torch.device('mps' if torch.backends.mps.is_available() else 'cpu')
        m.load_state_dict(torch.load(p, map_location=dev))
        m.eval()
        MODELS[tag] = m

@torch.no_grad()
def predict_prob(model, X, bs=64):
    dev = next(model.parameters()).device
    out = []
    for i in range(0, len(X), bs):
        xb = torch.from_numpy(X[i:i + bs]).to(dev)
        pred, _ = model(xb.transpose(2, 1))
        out.append(torch.softmax(pred, dim=2)[:, :, 1].cpu().numpy())
    return np.concatenate(out, axis=0)

def nr_window_scores(cfg, cache, basename='CIC-IDS-2017-Benign.pcap', need_ben=True):
    raw = os.path.join(OUT, 'raw', cfg + '.txt')
    tw, th, tx, _ = load_raw_file(raw)
    ben_fi = next((i for i, f in enumerate(cache.files) if f['file'] == basename))
    bw = cache.file_windows(ben_fi)
    order = bw[np.argsort(cache.win_t[bw])]
    benW = order[int(len(order) * 0.7):]
    rng = np.random.default_rng(1)
    blocks, bmeta = ([], [])
    for wi in range(len(tw)):
        hosts = np.asarray(th[wi], dtype=np.int64)
        if len(hosts) == 0:
            continue
        hi16 = hosts >> 16
        is_pool = (hi16 == POOL_HI[0]) | (hi16 == POOL_HI[1])
        takes = [is_pool] if not need_ben else [~is_pool, is_pool]
        for take in takes:
            tag = 'att' if take is is_pool else 'ben'
            idx = np.arange(len(hosts))[take]
            if len(idx) == 0:
                continue
            if len(idx) > 128:
                idx = rng.choice(idx, 128, replace=False)
            for j in range(0, len(idx), 64):
                chunk = idx[j:j + 64]
                need = N_POINTS - len(chunk)
                bwv = benW[rng.integers(len(benW))]
                a, b = cache.window_rows(bwv)
                fi2 = a + rng.integers(0, b - a, need)
                X = np.concatenate([tx[wi][chunk], cache.row_X[fi2]])
                blocks.append(X)
                bmeta.append((wi, tag, chunk, float(tw[wi])))
    Xall = np.stack(blocks)
    scores = {}
    for tag, model in MODELS.items():
        prob = predict_prob(model, Xall)
        per_wi = {}
        for bi, (wi, kind, chunk, t) in enumerate(bmeta):
            hosts = np.asarray(th[wi], dtype=np.int64)[chunk]
            for h, p in zip(hosts, prob[bi]):
                pfx = int(h) >> 8 << 8
                d = per_wi.setdefault((kind, pfx), {})
                if wi not in d or p > d[wi]:
                    d[wi] = float(p)
        scores[tag] = per_wi
    return (scores, tw)

def choose_tau(scores_sorted, allowed, direction='above'):
    v = np.sort(np.asarray(scores_sorted))[::-1]
    allowed = int(np.floor(allowed))
    if allowed >= len(v):
        return float(v.min()) - 1e-09
    if allowed <= 0:
        return float(v[0]) + 1e-09
    return float(v[allowed])

def eval_recall(scores_by_window, windows, tau, time_key, tol_lo, tol_hi, tw=None):
    det = 0
    lat = []
    idx = {}
    for (wi, pfx), sc in scores_by_window.items():
        t = tw[wi] if tw is not None else wi * EPOCH
        idx.setdefault(pfx, []).append((t, sc))
    for w in windows:
        cand = [(t, sc) for t, sc in idx.get(w['target'], []) if w['start'] + tol_lo <= t <= w['end'] + tol_hi and sc > tau]
        if cand:
            det += 1
            lat.append(max(0.0, min((t for t, _ in cand)) - w['start']))
    return (det, lat)

def pct(v, q):
    return round(float(np.percentile(v, q)), 3) if len(v) else None

def main():
    os.makedirs(OUT, exist_ok=True)
    t0 = time.time()
    load_models()
    cache = FeatureCache()
    ben_dst, ben_ts = load_benign()
    print('benign', len(ben_dst), 'packets; windows', flush=True)
    sk_ben = sk_epoch_scores(ben_dst, ben_ts)
    ent_ben = entropy_epoch_scores(ben_dst, ben_ts)
    print('benign scores: SK %d epochs, entropy %d (%.0fs)' % (len(sk_ben), len(ent_ben), time.time() - t0), flush=True)
    base_cfg = 'dur0.5_S16_r40_s0'
    nr_ben_raw, nr_tw = nr_window_scores(base_cfg, cache)
    nr_ben = {}
    for tag in MODELS:
        for (kind, pfx), d in nr_ben_raw[tag].items():
            if kind != 'ben':
                continue
            for wi, p in d.items():
                k = (wi, pfx)
                cur = nr_ben.setdefault(k, {}).get(tag, -1.0)
                if p > cur:
                    nr_ben[k][tag] = p
    print('NetRadar benign window scores done (%.0fs)' % (time.time() - t0), flush=True)
    cfgs = []
    for dur in G.DURATIONS:
        for S in G.SWEEPS:
            for rate in G.RATES:
                for seed in G.SEEDS:
                    cfgs.append('dur%g_S%d_r%d_s%d' % (dur, S, rate, seed))
    sk_att, ent_att, nr_att = ({}, {}, {})
    for cfg in cfgs:
        meta = json.load(open(os.path.join(OUT, 'attack_' + cfg + '.json')))
        att = attack_stream(meta)
        dst_a = np.asarray([d for _, d in att], dtype=np.int64)
        ts_a = np.asarray([t for t, _ in att], dtype=np.float64)
        dst_m = np.concatenate([ben_dst, dst_a])
        ts_m = np.concatenate([ben_ts, ts_a])
        order = np.argsort(ts_m, kind='stable')
        sk_all = sk_epoch_scores(dst_m[order], ts_m[order])
        tgt = {w['target'] for w in meta['windows']}
        sk_att[cfg] = {k: v for k, v in sk_all.items() if k[1] in tgt}
        ent_att[cfg], _ = entropy_attack_scores(meta)
        if meta['seed'] == 0:
            nr_att[cfg] = nr_window_scores(cfg, cache, need_ben=False)
        print('  scores %-22s (%.0fs)' % (cfg, time.time() - t0), flush=True)
    rows = []
    for method, ben, att_dict in (('sweepsketch', sk_ben, sk_att), ('entropy', ent_ben, ent_att)):
        vals = np.asarray(list(ben.values()))
        for target in TARGET_FPR:
            allowed = target * N_PFX * T_SEC / 86400.0
            tau = choose_tau(vals, allowed)
            actual = round(float((vals > tau).sum()) / N_PFX / (T_SEC / 86400.0), 3)
            per_cfg = {}
            for cfg, sc in att_dict.items():
                meta = json.load(open(os.path.join(OUT, 'attack_' + cfg + '.json')))
                det = 0
                lat = []
                for w in meta['windows']:
                    e0 = int(w['start'] // EPOCH)
                    e1 = int((w['end'] - 1e-09) // EPOCH)
                    best = max(sc.get((e0, w['target']), 0.0), sc.get((e1, w['target']), 0.0))
                    if best > tau:
                        det += 1
                        lat.append(max(0.0, (e1 + 1) * EPOCH - w['start']))
                per_cfg[cfg] = (det, len(meta['windows']), lat)
            for cfg, (det, n, lat) in per_cfg.items():
                p = cfg.split('_')
                rows.append({'method': method, 'fpr_per_pfx_day': target, 'fpr_actual': actual, 'rate': int(p[2][1:]), 'S': int(p[1][1:]), 'dur': float(p[0][3:]), 'recall': round(det / n, 4), 'latency_p50': pct(lat, 50), 'latency_p95': pct(lat, 95), 'windows': n})
        print(method, 'tau per target:', flush=True)
    for tag in MODELS:
        ben_events = []
        for (wi, pfx), d in nr_ben.items():
            if tag in d:
                ben_events.append(d[tag])
        vals = np.asarray(ben_events)
        for target in TARGET_FPR:
            allowed = target * N_PFX * T_SEC / 86400.0
            tau = choose_tau(vals, allowed)
            actual = round(float((vals > tau).sum()) / N_PFX / (T_SEC / 86400.0), 3)
            cfgs_nr = [c for c in cfgs if c in nr_att]
            recall_by_cfg = {}
            for cfg in cfgs_nr:
                meta = json.load(open(os.path.join(OUT, 'attack_' + cfg + '.json')))
                per = nr_att[cfg][0][tag]
                tw = nr_att[cfg][1]
                sc = {}
                for (kind, pfx), d in per.items():
                    if kind != 'att':
                        continue
                    for wi, p in d.items():
                        sc[wi, pfx] = p
                det, lat = eval_recall(sc, meta['windows'], tau, 'wi', -0.5, 1.0, tw=tw)
                recall_by_cfg[cfg] = (det, len(meta['windows']), lat)
            for cfg, (det, n, lat) in recall_by_cfg.items():
                p = cfg.split('_')
                rows.append({'method': 'netradar_' + tag, 'fpr_per_pfx_day': target, 'fpr_actual': actual, 'rate': int(p[2][1:]), 'S': int(p[1][1:]), 'dur': float(p[0][3:]), 'recall': round(det / n, 4), 'latency_p50': pct(lat, 50), 'latency_p95': pct(lat, 95), 'windows': n})
    with open(os.path.join(OUT, 'e11_fpr_curve.csv'), 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    summ = {}
    for r in rows:
        m = r['method']
        k = '%s|fpr%.1f' % (m, r['fpr_per_pfx_day'])
        d = summ.setdefault(k, {'method': m, 'fpr': r['fpr_per_pfx_day'], 'fpr_actual': r['fpr_actual'], 'rec': [], 'lat': []})
        d['rec'].append(r['recall'])
        if r['latency_p50'] is not None:
            d['lat'].append(r['latency_p50'])
    for k, d in summ.items():
        d['recall_mean'] = round(float(np.mean(d.pop('rec'))), 4)
        d['latency_p50_mean'] = round(float(np.mean(d.pop('lat'))), 3) if d['fpr'] is not None else None
    out = {'design': {'benign_timeline_s': T_SEC, 'benign_prefixes': N_PFX, 'fpr_targets_per_pfx_day': TARGET_FPR, 'fpr_definition': 'events = # (prefix,unit) with score>tau on the benign timeline; rate = events / n_prefixes / (T/86400)', 'units': {'sweepsketch': '4.29 s epoch', 'entropy': '4.29 s epoch', 'netradar': '1 s feature window'}, 'netradar_models': list(MODELS), 'netradar_seed': 0, 'sk_version': 'v1'}, 'by_method': summ, 'wall_s': round(time.time() - t0, 1), 'host': os.uname().nodename, 'finished': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
    with open(os.path.join(OUT, 'e11_fpr_summary.json'), 'w') as f:
        json.dump(out, f, indent=1)
    print(json.dumps(summ, indent=1))
    print('wrote', os.path.join(OUT, 'e11_fpr_curve.csv'))
if __name__ == '__main__':
    main()
