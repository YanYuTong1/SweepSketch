import collections
import csv
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
from sweepsketch import config
from sweepsketch.digest import Collector
from common import make_sketch
from baselines.step02_baselines import EntropySketch, bob_hash
from e3_common import FeatureCache, load_raw_file
import e11_gen as G
import e11_fpr as F
NETRADAR = os.environ.get('NETRADAR_DIR', '')
if NETRADAR:
    sys.path.insert(0, os.path.join(NETRADAR, 'detectors'))
from nn_models.loss_sort import pointnet
OUT = os.path.join(REV, 'results', 'e11')
EPOCH = G.EPOCH
T_SEC = 600.0
N_PFX = 878
TARGETS = [0.1, 1.0, 5.0]
N_POINTS, N_FEAT, N_POS = (256, 11, 32)
POOL_HI = (50706, 50707)
DUMMY = Collector()
MODELS = {}
DEV = torch.device('mps' if torch.backends.mps.is_available() else 'cpu')

def pfx_str(k):
    return '%d.%d.%d.0/24' % (k >> 24 & 255, k >> 16 & 255, k >> 8 & 255)

def load_benign():
    z = np.load(os.path.join(OUT, 'e11_benign_stream.npz'))
    return (z['dst'].astype(np.int64), z['ts'].astype(np.float64))

def attack_stream(meta):
    win = meta['windows']
    rng = np.random.default_rng(meta['seed'] * 1000003 + int(meta['dur'] * 100) * 7919 + meta['S'] * 104729 + meta['rate'])
    return G.attack_packets(win, rng)

def sk_track(dst, ts, only_keys=None, traj=False):
    sk = make_sketch(config.THETA0, 512)
    out = {}
    for d, t in zip(dst, ts):
        key = int(d) >> 8 << 8
        if only_keys is not None and key not in only_keys:
            pass
        sk.process(0, int(d), float(t), DUMMY)
        i = sk.l1.idx(key)
        b = sk.l1.buckets[i]
        if b is None or b.key != key:
            continue
        gate = max(config.K_ALARM, 2 * b.n_ewma, config.K_ALARM_QUIET if b.n_ewma < config.N_EWMA_QUIET else 0)
        if b.n_new >= gate:
            if only_keys is not None and key not in only_keys:
                continue
            k = (int(float(t) // EPOCH), key)
            if traj:
                out.setdefault(k, []).append((b.C, float(t)))
            elif b.C > out.get(k, 0):
                out[k] = b.C
    return out

def entropy_scores(dst, ts, extra_n_pfx=None):
    ep = {}
    for d, t in zip(dst, ts):
        e = int(float(t) // EPOCH)
        p = int(d) >> 8 << 8
        ep.setdefault(e, {}).setdefault(p, {})
    for d, t in zip(dst, ts):
        e = int(float(t) // EPOCH)
        p = int(d) >> 8 << 8
        ep[e][p][int(d)] = ep[e][p].get(int(d), 0) + 1
    out = {}
    for e, pfxs in ep.items():
        n_act = len(pfxs) + (extra_n_pfx.get(e, 0) if extra_n_pfx else 0)
        z = max(2, 512 * 1024 * 8 // max(n_act, 1) // 32)
        out[e, 'z'] = z
        for p, cnt in pfxs.items():
            sk = EntropySketch(z)
            ctrs = array('I', [0]) * z
            g = sk.g
            for d, c in cnt.items():
                key = d.to_bytes(4, 'little')
                for i in range(g):
                    ctrs[bob_hash(key, 49408 + i) % z] += c
            out[e, p] = sk._score(ctrs)
    return out

def load_models():
    for tag in ('p1_full_seed1', 'p1_full_seed2'):
        p = os.path.join(REV, 'results', 'e3', 'model_' + tag + '.pt')
        m = pointnet(2, N_FEAT, N_POINTS).to(DEV)
        m.load_state_dict(torch.load(p, map_location=DEV))
        m.eval()
        MODELS[tag] = m

@torch.no_grad()
def predict_prob(model, X, bs=128):
    out = []
    for i in range(0, len(X), bs):
        xb = torch.from_numpy(X[i:i + bs]).to(DEV)
        pred, _ = model(xb.transpose(2, 1))
        out.append(torch.softmax(pred, dim=2)[:, :, 1].cpu().numpy())
    return np.concatenate(out, axis=0)

def nr_scores(cfg, cache, need_ben=True):
    raw = os.path.join(OUT, 'raw', cfg + '.txt')
    tw, th, tx, _ = load_raw_file(raw)
    fi = next((i for i, f in enumerate(cache.files) if f['file'] == 'CIC-IDS-2017-Benign.pcap'))
    bw = cache.file_windows(fi)
    order = bw[np.argsort(cache.win_t[bw])]
    benW = order[int(len(order) * 0.7):]
    rng = np.random.default_rng(3)
    ben_blocks, ben_meta, att_blocks, att_meta = ([], [], [], [])
    for wi in range(len(tw)):
        hosts = np.asarray(th[wi], dtype=np.int64)
        if len(hosts) == 0:
            continue
        hi16 = hosts >> 16
        is_pool = (hi16 == POOL_HI[0]) | (hi16 == POOL_HI[1])
        t = float(tw[wi])
        for take, kind in ((np.arange(len(hosts))[~is_pool], 'ben'), (np.arange(len(hosts))[is_pool], 'att')):
            if kind == 'ben' and (not need_ben):
                continue
            if len(take) == 0:
                continue
            if len(take) > 128:
                take = rng.choice(take, 128, replace=False)
            for j in range(0, len(take), N_POS):
                chunk = take[j:j + N_POS]
                need = N_POINTS - len(chunk)
                b = benW[rng.integers(len(benW))]
                a2, b2 = cache.window_rows(b)
                fill = a2 + rng.integers(0, b2 - a2, need)
                X = np.concatenate([tx[wi][chunk], cache.row_X[fill]])
                if kind == 'ben':
                    ben_blocks.append(X)
                    ben_meta.append((t, chunk, wi))
                else:
                    att_blocks.append(X)
                    att_meta.append((t, chunk, wi))
    ben = {tag: {} for tag in MODELS}
    for tag, m in MODELS.items():
        if ben_blocks:
            prob = predict_prob(m, np.stack(ben_blocks))
            for bi, (t, chunk, wi) in enumerate(ben_meta):
                hw = np.asarray(th[wi], dtype=np.int64)[chunk]
                for h, p in zip(hw, prob[bi][:len(chunk)]):
                    k = (round(t, 3), int(h >> 8 << 8))
                    if p > ben[tag].get(k, -1):
                        ben[tag][k] = float(p)
    att = {tag: {} for tag in MODELS}
    if att_blocks:
        Xall = np.stack(att_blocks)
        for tag, m in MODELS.items():
            prob = predict_prob(m, Xall)
            for bi, (t, chunk, wi) in enumerate(att_meta):
                hw = np.asarray(th[wi], dtype=np.int64)[chunk]
                for h, p in zip(hw, prob[bi][:len(chunk)]):
                    k = (round(t, 3), int(h >> 8 << 8))
                    if p > att[tag].get(k, -1):
                        att[tag][k] = float(p)
    return (ben, att)

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

def damage(win, alarm_t):
    hosts = win['hosts']
    n = win['packets']
    S_eff = win['S_eff']
    if alarm_t >= win['end']:
        return (1.0, 1.0)
    elapsed = max(0.0, alarm_t - win['start'])
    frac_t = min(1.0, elapsed / 0.5)
    k = int(np.floor(frac_t * n))
    pk = k / n if n else 1.0
    vic = min(S_eff, k) / S_eff if S_eff else 1.0
    return (vic, pk)

def main():
    os.makedirs(OUT, exist_ok=True)
    t0 = time.time()
    load_models()
    cache = FeatureCache()
    ben_dst, ben_ts = load_benign()
    print('benign', len(ben_dst), flush=True)
    sk_ben = sk_track(ben_dst, ben_ts)
    ent_ben = entropy_scores(ben_dst, ben_ts)
    n_pfx = len({pfx_str(int(p)) for p in cache.row_pfx if float(0) == 0}) if False else 0
    ben_pfx = {int(d) >> 8 << 8 for d in ben_dst}
    NPFX = len(ben_pfx)
    ben_n_pfx_by_epoch = {}
    for d, t in zip(ben_dst, ben_ts):
        e = int(t // EPOCH)
        ben_n_pfx_by_epoch.setdefault(e, set()).add(int(d) >> 8 << 8)
    ben_n_pfx_by_epoch = {e: len(v) for e, v in ben_n_pfx_by_epoch.items()}
    main_nr_ben, _ = nr_scores('dur0.5_S16_r40_s0', cache, need_ben=True)
    print('benign scores ready %.0fs (prefixes %d)' % (time.time() - t0, NPFX), flush=True)
    ent_bvals = np.asarray([v for k, v in ent_ben.items() if k[1] != 'z'])
    sk_bvals = np.asarray(list(sk_ben.values()))
    nr_bvals = {tag: np.asarray(list(main_nr_ben[tag].values())) for tag in MODELS}
    cfgs = []
    for dur in G.DURATIONS:
        for S in G.SWEEPS:
            for rate in G.RATES:
                for seed in G.SEEDS:
                    cfgs.append('dur%g_S%d_r%d_s%d' % (dur, S, rate, seed))
    recs = []
    for cfg in cfgs:
        meta = json.load(open(os.path.join(OUT, 'attack_' + cfg + '.json')))
        att = attack_stream(meta)
        dst_a = np.asarray([d for _, d in att], dtype=np.int64)
        ts_a = np.asarray([t for t, _ in att], dtype=np.float64)
        tgt = {w['target'] for w in meta['windows']}
        dst_m = np.concatenate([ben_dst, dst_a])
        ts_m = np.concatenate([ben_ts, ts_a])
        order = np.argsort(ts_m, kind='stable')
        tr = sk_track(dst_m[order], ts_m[order], only_keys=tgt, traj=True)
        ep_scores = entropy_scores(dst_a, ts_a, extra_n_pfx=ben_n_pfx_by_epoch)
        nr_att = None
        if meta['seed'] == 0:
            _, nr_att = nr_scores(cfg, cache, need_ben=False)
        recs.append({'cfg': cfg, 'meta': meta, 'att': att, 'sk_tr': tr, 'ent': ep_scores, 'nr': nr_att})
        print('  cfg %-22s (%.0fs)' % (cfg, time.time() - t0), flush=True)

    def sk_first_alarm(tr, pfx, tau):
        best = None
        for (e, p), traj in tr.items():
            if p != pfx:
                continue
            for c, t in traj:
                if c > tau and (best is None or t < best):
                    best = t
        return best
    rows = []
    for target_budget in TARGETS:
        allowed = target_budget * NPFX * T_SEC / 86400.0
        tau = choose_tau(sk_bvals, allowed)
        fpr_actual = round(float((sk_bvals > tau).sum()) / NPFX / (T_SEC / 86400.0), 3)
        for rec in recs:
            meta = rec['meta']
            det = dead = grace = 0
            lat = []
            dmg_v = []
            dmg_p = []
            for w in meta['windows']:
                ta = sk_first_alarm(rec['sk_tr'], w['target'], tau)
                if ta is None:
                    dmg_v.append(1.0)
                    dmg_p.append(1.0)
                    continue
                det += 1
                lat.append(ta - w['start'])
                dead += int(ta <= w['end'])
                grace += int(ta <= w['end'] + EPOCH)
                dv, dp = damage(w, ta)
                dmg_v.append(dv)
                dmg_p.append(dp)
            rows.append({'_lat': lat, '_method': 'sweepsketch', '_budget': target_budget, 'method': 'sweepsketch', 'fpr_per_pfx_day': target_budget, 'fpr_actual': fpr_actual, 'cfg': rec['cfg'], 'recall': round(det / len(meta['windows']), 4), 'recall_strict': round(dead / len(meta['windows']), 4), 'recall_eventual': round(grace / len(meta['windows']), 4), 'lat_p50': round(float(np.median(lat)), 3) if lat else None, 'lat_p95': round(float(np.percentile(lat, 95)), 3) if lat else None, 'damage_victim_mean': round(float(np.mean(dmg_v)), 4), 'damage_victim_worst': round(float(np.max(dmg_v)), 4), 'damage_pkt_mean': round(float(np.mean(dmg_p)), 4)})
    for method in ('entropy',) + tuple(('netradar_' + t for t in MODELS)):
        if method == 'entropy':
            bvals = ent_bvals
        else:
            bvals = nr_bvals[method.split('netradar_')[1]]
        for target_budget in TARGETS:
            allowed = target_budget * NPFX * T_SEC / 86400.0
            tau = choose_tau(bvals, allowed)
            fpr_actual = round(float((bvals > tau).sum()) / NPFX / (T_SEC / 86400.0), 3)
            for rec in recs:
                meta = rec['meta']
                if method != 'entropy' and rec['nr'] is None:
                    continue
                det = dead = grace = 0
                lat = []
                dmg_v = []
                dmg_p = []
                for w in meta['windows']:
                    e0 = int(w['start'] // EPOCH)
                    e1 = int((w['end'] - 1e-09) // EPOCH)
                    if method == 'entropy':
                        hits = [(e + 1) * EPOCH for e in {e0, e1} if rec['ent'].get((e, w['target']), 0) > tau]
                        ta = min(hits) if hits else None
                    else:
                        tag = method.split('netradar_')[1]
                        scores = rec['nr'].get(tag, {})
                        hits = [t for (t, p), pscore in scores.items() if p == w['target'] and w['start'] - 0.5 <= t <= w['end'] + 1.0 and (pscore > tau)]
                        ta = min(hits) if hits else None
                    if ta is None:
                        dmg_v.append(1.0)
                        dmg_p.append(1.0)
                        continue
                    det += 1
                    lat.append(max(0.0, ta - w['start']))
                    dead += int(ta <= w['end'])
                    grace += int(ta <= w['start'] + EPOCH)
                    dv, dp = damage(w, ta)
                    dmg_v.append(dv)
                    dmg_p.append(dp)
                rows.append({'_lat': lat, '_method': method, '_budget': target_budget, 'method': method, 'fpr_per_pfx_day': target_budget, 'fpr_actual': fpr_actual, 'cfg': rec['cfg'], 'recall': round(det / len(meta['windows']), 4), 'recall_strict': round(dead / len(meta['windows']), 4), 'recall_eventual': round(grace / len(meta['windows']), 4), 'lat_p50': round(float(np.median(lat)), 3) if lat else None, 'lat_p95': round(float(np.percentile(lat, 95)), 3) if lat else None, 'damage_victim_mean': round(float(np.mean(dmg_v)), 4), 'damage_victim_worst': round(float(np.max(dmg_v)), 4), 'damage_pkt_mean': round(float(np.mean(dmg_p)), 4)})
    lat_by = collections.defaultdict(list)
    for r in rows:
        lat_by[r['method'], r['fpr_per_pfx_day']].extend(r.get('_lat', []))
        r.pop('_lat', None)
        r.pop('_method', None)
        r.pop('_budget', None)
    with open(os.path.join(OUT, 'e11_deadline.csv'), 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    curve = []
    for r in rows:
        p = r['cfg'].split('_')
        curve.append({'method': r['method'], 'fpr_per_pfx_day': r['fpr_per_pfx_day'], 'fpr_actual': r['fpr_actual'], 'rate': int(p[2][1:]), 'S': int(p[1][1:]), 'dur': float(p[0][3:]), 'strict_recall': r['recall_strict'], 'eventual_recall': r['recall_eventual'], 'latency_p50': r['lat_p50'], 'latency_p95': r['lat_p95'], 'damage_victim_mean': r['damage_victim_mean']})
    with open(os.path.join(OUT, 'e11_fpr_curve.csv'), 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(curve[0].keys()))
        w.writeheader()
        w.writerows(curve)
    agg = collections.defaultdict(list)
    for r in rows:
        p = r['cfg'].split('_')
        key = (r['method'], r['fpr_per_pfx_day'], int(p[2][1:]), int(p[1][1:]), float(p[0][3:]))
        agg[key].append(r)
    summ = {}
    for key, sel in agg.items():
        m, b, rate, S, dur = key
        k = '%s|fpr%.1f|r%d|S%d|dur%g' % (m, b, rate, S, dur)
        summ[k] = {'recall': round(float(np.mean([r['recall'] for r in sel])), 4), 'recall_strict': round(float(np.mean([r['recall_strict'] for r in sel])), 4), 'recall_eventual': round(float(np.mean([r['recall_eventual'] for r in sel])), 4), 'lat_p50': round(float(np.mean([r['lat_p50'] for r in sel if r['lat_p50'] is not None])), 3) if any((r['lat_p50'] is not None for r in sel)) else None, 'damage_victim_mean': round(float(np.mean([r['damage_victim_mean'] for r in sel])), 4), 'damage_pkt_mean': round(float(np.mean([r['damage_pkt_mean'] for r in sel])), 4), 'fpr_actual': sel[0]['fpr_actual']}
    meth = {}
    for key, sel in agg.items():
        m = key[0]
        d = meth.setdefault(m, {'recall': [], 'deadline': [], 'grace': [], 'lat': [], 'dmg': [], 'cfg_n': 0})
        d['recall'].append(np.mean([r['recall'] for r in sel]))
        d['deadline'].append(np.mean([r['recall_strict'] for r in sel]))
        d['grace'].append(np.mean([r['recall_eventual'] for r in sel]))
        lats = [r['lat_p50'] for r in sel if r['lat_p50'] is not None]
        if lats:
            d['lat'].append(np.mean(lats))
        d['dmg'].append(np.mean([r['damage_victim_mean'] for r in sel]))
        d['cfg_n'] += 1
    for m, d in meth.items():
        summ['METHOD_' + m] = {'configs': d['cfg_n'], 'recall_mean': round(float(np.mean(d['recall'])), 4), 'recall_strict_mean': round(float(np.mean(d['deadline'])), 4), 'recall_eventual_mean': round(float(np.mean(d['grace'])), 4), 'lat_p50_mean': round(float(np.mean(d['lat'])), 3) if d['lat'] else None, 'damage_victim_mean': round(float(np.mean(d['dmg'])), 4)}
    for (m, b), lats in lat_by.items():
        key = 'METHOD_%s|fpr%.1f' % (m, b)
        sel = [r for r in rows if r['method'] == m and r['fpr_per_pfx_day'] == b]
        summ[key] = {'windows': sum((int(r['cfg'].count('_')) + 1 for r in sel)) and sum((200 for _ in sel)), 'recall_mean': round(float(np.mean([r['recall'] for r in sel])), 4), 'recall_strict_mean': round(float(np.mean([r['recall_strict'] for r in sel])), 4), 'recall_eventual_mean': round(float(np.mean([r['recall_eventual'] for r in sel])), 4), 'lat_p50': round(float(np.percentile(lats, 50)), 3) if lats else None, 'lat_p95': round(float(np.percentile(lats, 95)), 3) if lats else None, 'lat_n': len(lats), 'damage_victim_mean': round(float(np.mean([r['damage_victim_mean'] for r in sel])), 4), 'damage_pkt_mean': round(float(np.mean([r['damage_pkt_mean'] for r in sel])), 4)}
    out = {'design': {'benign_prefixes': NPFX, 'timeline_s': T_SEC, 'fpr_targets': TARGETS, 'entropy_memory': '512 KB per epoch (z allocated from active prefixes)', 'sk_memory': '512 KB fixed', 'netradar_models': list(MODELS), 'deadline_definition': 'first alarm ts <= attack window end', 'grace_definition': 'first alarm ts <= attack end + 4.294967296 s', 'damage_definition': 'fraction of victim hosts already hit at first alarm; undetected windows count as 1.0'}, 'by_config': summ, 'wall_s': round(time.time() - t0, 1), 'finished': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
    with open(os.path.join(OUT, 'e11_deadline_summary.json'), 'w') as f:
        json.dump(out, f, indent=1)
    print(json.dumps({k: v for k, v in summ.items() if k.startswith('METHOD_')}, indent=1))
if __name__ == '__main__':
    main()
