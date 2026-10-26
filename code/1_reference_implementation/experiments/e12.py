import csv
import json
import os
import sys
import time
from array import array
import numpy as np
REV = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REV, 'code', '1_reference_implementation'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sweepsketch import config, pcapio
from baselines.step02_baselines import EntropySketch, bob_hash
DB = os.path.join(REV, 'database')
E1 = os.path.join(REV, 'results', 'e1')
V2 = os.path.join(REV, 'results', 'v2')
E3 = os.path.join(REV, 'results', 'e3')
OUT = os.path.join(REV, 'results', 'e12')
EPOCH = config.EPOCH_NS / 1000000000.0
Z_ENT = 48
TAUS = {'E1_tau4.37': 4.37, 'op0.1': 3.1297, 'op1': 2.683, 'op5': 2.1966}

def pfx_str(k):
    return '%d.%d.%d.0/24' % (k >> 24 & 255, k >> 16 & 255, k >> 8 & 255)

def load_csv(p):
    with open(p) as f:
        return list(csv.DictReader(f))

def entropy_first_alarm(path, gt_prefix):
    first_ts = None
    ep = {}
    for s, d, ts in pcapio.iter_pcap(path, max_pkts=1 << 62, with_flow=False):
        if first_ts is None:
            first_ts = ts
        p = d >> 8 << 8
        e = int((ts - first_ts) // EPOCH)
        dd = ep.setdefault((e, p), {})
        dd[d] = dd.get(d, 0) + 1
    gt = gt_prefix >> 0
    out = {k: (None, None) for k in TAUS}
    for (e, p), cnt in sorted(ep.items()):
        if p != gt:
            continue
        sk = EntropySketch(Z_ENT)
        ctrs = array('I', [0]) * Z_ENT
        for d, c in cnt.items():
            key = int(d).to_bytes(4, 'little')
            for i in range(sk.g):
                ctrs[bob_hash(key, 49408 + i) % Z_ENT] += c
        score = sk._score(ctrs)
        for lab, tau in TAUS.items():
            if out[lab][0] is None and score > tau:
                out[lab] = ((e + 1) * EPOCH, score)
    return (out, first_ts or 0.0, len(ep))

def netradar_holdout_damage():
    import torch
    from e3_common import FeatureCache
    from e3_netradar import predict_blocks_prob, N_POINTS, N_FEAT, N_POS
    NET = os.environ.get('NETRADAR_DIR', '')
    if NET:
        sys.path.insert(0, os.path.join(NET, 'detectors'))
    from nn_models.loss_sort import pointnet
    TAU = {'p1_full_seed1': 0.1831, 'p1_full_seed2': 0.0861}
    dev = torch.device('mps' if torch.backends.mps.is_available() else 'cpu')
    models = {}
    for tag in ('p1_full_seed1', 'p1_full_seed2'):
        m = pointnet(2, N_FEAT, N_POINTS).to(dev)
        m.load_state_dict(torch.load(os.path.join(E3, 'model_' + tag + '.pt'), map_location=dev))
        m.eval()
        models[tag] = m
    cache = FeatureCache()
    inv = json.load(open(os.path.join(E3, 'inventory.json')))
    rows = []
    rng = np.random.default_rng(0)
    for fi, f in enumerate(cache.files):
        if not f['kind'].startswith('attack_holdout'):
            continue
        gtset = set(f['gt_prefixes'])
        onset, last = ({}, {})
        blocks, metas = ([], [])
        for w in cache.file_windows(fi):
            a, b = cache.window_rows(w)
            pf = np.asarray(cache.row_pfx[a:b])
            t = float(cache.win_t[w])
            for p in set((int(x) for x in pf)):
                k = pfx_str(p)
                if k not in gtset:
                    continue
                onset[k] = min(onset.get(k, t), t)
                last[k] = max(last.get(k, t), t)
                idx = np.arange(a, b)[pf == p]
                if len(idx) > 64:
                    idx = rng.choice(idx, 64, replace=False)
                for j in range(0, len(idx), N_POS):
                    chunk = idx[j:j + N_POS]
                    need = N_POINTS - len(chunk)
                    fill = cache.row_X[rng.integers(0, len(cache.row_X), need)]
                    blocks.append(np.concatenate([cache.row_X[chunk], fill]))
                    metas.append((t, chunk, p))
        if not blocks:
            continue
        Xall = np.stack(blocks)
        for tag, m in models.items():
            prob = predict_blocks_prob(m, dev, Xall, bs=128)[1]
            per = {}
            for bi, (t, chunk, p) in enumerate(metas):
                k = (pfx_str(p), round(t, 3))
                mx = float(np.max(prob[bi][:len(chunk)]))
                if mx > per.get(k, -1):
                    per[k] = mx
            for pfx in gtset:
                o, l = (onset.get(pfx), last.get(pfx))
                if o is None or l is None or l <= o:
                    continue
                cand = sorted([(t, v) for (pp, t), v in per.items() if pp == pfx])
                for tau_name, tau in (('op0.1', TAU[tag]), ('argmax0.5', 0.5)):
                    hit = next(((t, v) for t, v in cand if v > tau), None)
                    rows.append({'model': tag, 'threshold': tau_name, 'tau': tau, 'file': f['file'], 'prefix': pfx, 'onset': round(o, 3), 'last': round(l, 3), 'alert': round(hit[0], 3) if hit else None, 'damage_frac': round(min(1.0, max(0.0, (hit[0] - o) / (l - o))), 4) if hit else 1.0, 'strict': int(hit[0] <= l) if hit else 0, 'detected': int(hit is not None)})
    return rows

def summarize(vals, strict, det, label):
    v = np.asarray(vals, dtype=float)
    return {'label': label, 'n': int(len(v)), 'damage_median': round(float(np.median(v)), 4) if len(v) else None, 'damage_p95': round(float(np.percentile(v, 95)), 4) if len(v) else None, 'damage_max': round(float(np.max(v)), 4) if len(v) else None, 'strict_rate': round(float(np.mean(strict)), 4) if len(v) else None, 'detected_rate': round(float(np.mean(det)), 4) if len(v) else None}

def main():
    os.makedirs(OUT, exist_ok=True)
    t0 = time.time()
    win = load_csv(os.path.join(E1, 'e1_windows.csv'))
    v2_path = os.path.join(V2, 'e1_v2_latency.csv')
    v2 = {(r['seed'], r['round'], r['file']): r for r in load_csv(v2_path)} if os.path.exists(v2_path) else {}
    inv = json.load(open(os.path.join(E3, 'inventory.json')))
    file_meta = {r['file']: r for r in inv['file_scan']}
    ent = {}
    for i, r in enumerate({r['file']: r for r in win}.values()):
        f = r['file']
        meta = file_meta.get(f)
        if not meta:
            continue
        path = os.path.join(DB, meta['path'])
        gt = int(meta['gt_prefixes'][0].split('/')[0].split('.')[0]) << 24
        a = int(meta['gt_prefixes'][0].split('/')[0].split('.')[1]) << 16
        b = int(meta['gt_prefixes'][0].split('/')[0].split('.')[2]) << 8
        gt |= a | b
        ent[f], _, ne = entropy_first_alarm(path, gt)
        if i % 10 == 0:
            print('entropy', i, f, 'epochs', ne, '(%.0fs)' % (time.time() - t0), flush=True)
    print('entropy done %.0fs' % (time.time() - t0), flush=True)
    nr = netradar_holdout_damage()
    print('netradar holdout rows', len(nr), '(%.0fs)' % (time.time() - t0), flush=True)
    out_rows = []
    for r in win:
        key = (r['seed'], r['round'], r['file'])
        dur = float(r['orig_dur_s'])
        first_v1 = r['first_alert_s']
        v1 = None if first_v1 in ('', 'None') else float(first_v1)
        v2r = v2.get(key, {})
        fv2 = v2r.get('first_episode_s')
        v2s = None if fv2 in ('', 'None', None) else float(fv2)
        row = {'seed': r['seed'], 'round': r['round'], 'file': r['file'], 'gt_prefix': r['gt_prefix'], 'orig_dur_s': dur, 'packets': r['packets'], 'short': int(dur < 60.0), 'sk_v1_first_s': v1, 'sk_v1_damage': None if v1 is None else round(min(1.0, v1 / dur), 4), 'sk_v1_detected': int(v1 is not None), 'sk_v2_first_s': v2s, 'sk_v2_damage': None if v2s is None else round(min(1.0, v2s / dur), 4), 'sk_v2_detected': int(v2s is not None)}
        e = ent.get(r['file'], {})
        for lab in TAUS:
            al, sc = e.get(lab, (None, None))
            row['ent_%s_first_s' % lab] = None if al is None else round(al, 3)
            row['ent_%s_damage' % lab] = None if al is None else round(min(1.0, al / dur), 4)
            row['ent_%s_score' % lab] = None if sc is None else round(sc, 3)
        out_rows.append(row)
    summ = {'generated': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'n_windows': len(out_rows), 'n_files': len({r['file'] for r in out_rows}), 'n_short': sum((r['short'] for r in out_rows)), 'strict_def': 'first_alert_s <= orig_dur_s', 'damage_def': 'first_alert_s / orig_dur_s (uniform-scan approximation)', 'entropy': {'epoch_s': EPOCH, 'z': Z_ENT, 'taus': TAUS}, 'by_group': {}}
    for group, sel in (('all', out_rows), ('short_lt60s', [r for r in out_rows if r['short']]), ('long_ge60s', [r for r in out_rows if not r['short']])):
        g = {}
        for m in ('sk_v1', 'sk_v2'):
            vals = [r[m + '_damage'] if r[m + '_damage'] is not None else 1.0 for r in sel]
            strict = [r[m + '_damage'] is not None and float(r[m + '_first_s']) <= float(r['orig_dur_s']) for r in sel]
            det = [r[m + '_detected'] for r in sel]
            g[m] = summarize(vals, strict, det, m)
        for lab in TAUS:
            vals = [r['ent_%s_damage' % lab] if r['ent_%s_damage' % lab] is not None else 1.0 for r in sel]
            strict = [r['ent_%s_damage' % lab] is not None and float(r['ent_%s_first_s' % lab]) <= float(r['orig_dur_s']) for r in sel]
            det = [r['ent_%s_first_s' % lab] is not None for r in sel]
            g['entropy_' + lab] = summarize(vals, strict, det, 'entropy_' + lab)
        summ['by_group'][group] = g
    nr_summ = {}
    for tag in sorted({(r['model'], r['threshold']) for r in nr}):
        sel = [r for r in nr if (r['model'], r['threshold']) == tag]
        vals = [r['damage_frac'] for r in sel]
        nr_summ[tag[0] + '|' + tag[1]] = {'n': len(vals), 'damage_median': round(float(np.median(vals)), 4) if vals else None, 'damage_p95': round(float(np.percentile(vals, 95)), 4) if vals else None, 'damage_max': round(float(np.max(vals)), 4) if vals else None, 'strict_rate': round(float(np.mean([r['strict'] for r in sel])), 4) if sel else None, 'note': 'onset-relative on 30 holdout files (p1 model not trained on them); holdout by_timestamp spans are concatenated, file-relative duration unreliable'}
    summ['netradar_holdout'] = nr_summ
    cols = list(out_rows[0].keys())
    with open(os.path.join(OUT, 'e12_windows_damage.csv'), 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(out_rows)
    with open(os.path.join(OUT, 'e12_netradar_holdout.csv'), 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(nr[0].keys()) if nr else ['model'])
        w.writeheader()
        w.writerows(nr)
    short = {}
    for r in out_rows:
        if not r['short']:
            continue
        d = short.setdefault(r['file'], {'file': r['file'], 'orig_dur_s': r['orig_dur_s'], 'gt_prefix': r['gt_prefix'], 'sk_v1': [], 'sk_v2': [], 'ent': {k: [] for k in TAUS}})
        d['sk_v1'].append(r['sk_v1_damage'])
        d['sk_v2'].append(r['sk_v2_damage'])
        for lab in TAUS:
            d['ent'][lab].append(r['ent_%s_damage' % lab])
    short_rows = []
    for f, d in short.items():
        row = {'file': f, 'orig_dur_s': d['orig_dur_s'], 'gt_prefix': d['gt_prefix'], 'sk_v1_damage_median': round(float(np.median([x for x in d['sk_v1'] if x is not None] or [1.0])), 4), 'sk_v2_damage_median': round(float(np.median([x for x in d['sk_v2'] if x is not None] or [1.0])), 4)}
        for lab in TAUS:
            row['ent_%s_damage' % lab] = round(float(np.median([x for x in d['ent'][lab] if x is not None] or [1.0])), 4)
        short_rows.append(row)
    with open(os.path.join(OUT, 'e12_short_windows.csv'), 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(short_rows[0].keys()))
        w.writeheader()
        w.writerows(short_rows)
    with open(os.path.join(OUT, 'e12_summary.json'), 'w') as f:
        json.dump(summ, f, indent=1)
    print(json.dumps(summ, indent=1))
    print('wall %.0fs' % (time.time() - t0))
if __name__ == '__main__':
    main()
