import csv
import json
import os
import subprocess
import sys
import numpy as np
import torch
REV = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REV, 'code', '1_reference_implementation'))
from e3_common import FeatureCache, pfx_str
from e3_netradar import predict_blocks_prob, N_POINTS, N_FEAT, N_POS, pfx_int
from sweepsketch import config
NETRADAR = os.environ.get('NETRADAR_DIR', '')
if NETRADAR:
    sys.path.insert(0, os.path.join(NETRADAR, 'detectors'))
from nn_models.loss_sort import pointnet
E3 = os.path.join(REV, 'results', 'e3')
OUT = os.path.join(REV, 'results', 'e3_seeds')
DEV = torch.device('mps' if torch.backends.mps.is_available() else 'cpu')
TARGETS = [0.1, 1.0, 5.0]
MODEL = os.path.join(OUT, 'model_p2_fold0_seed0.pt')
JSON = os.path.join(OUT, 'netradar_p2_fold0_seed0.json')

def ensure_model():
    if os.path.exists(MODEL):
        return
    cmd = [sys.executable, '-u', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'e3_netradar.py'), '--protocol', 'p2', '--fold', '0', '--seed', '0', '--epochs', '2', '--full-epoch', '--outdir', OUT, '--tag', 'p2_fold0_seed0']
    print('training fold0 with model save ...', flush=True)
    subprocess.run(cmd, check=True)

def load_model():
    m = pointnet(2, N_FEAT, N_POINTS).to(DEV)
    m.load_state_dict(torch.load(MODEL, map_location=DEV))
    m.eval()
    return m

def main():
    os.makedirs(OUT, exist_ok=True)
    ensure_model()
    model = load_model()
    cache = FeatureCache()
    inv = json.load(open(os.path.join(E3, 'inventory.json')))
    main_pfx = sorted({p for r in inv['file_scan'] if r['kind'] == 'attack_main' for p in r['gt_prefixes']})
    hold = {p for r in inv['file_scan'] if r['kind'].startswith('attack_holdout') for p in r['gt_prefixes']}
    fold_pfx = [p for p in main_pfx[0::5] if p in hold]
    rng = np.random.default_rng(0)
    fi = next((i for i, f in enumerate(cache.files) if f['file'] == 'CIC-IDS-2017-Benign.pcap'))
    bw = cache.file_windows(fi)
    order = bw[np.argsort(cache.win_t[bw])]
    test = order[int(len(order) * 0.7):]
    ben_events = []
    days = (float(cache.win_t[test[-1]]) - float(cache.win_t[test[0]])) / 86400.0
    ben_pfx = set()
    Xs = []
    metas = []
    for w in test:
        a, b = cache.window_rows(w)
        rows = np.arange(a, b)
        if len(rows) > N_POINTS:
            rows = rng.choice(rows, N_POINTS, replace=False)
        need = N_POINTS - len(rows)
        if need:
            rows = np.concatenate([rows, rng.choice(rows, need, replace=True)])
        Xs.append(cache.row_X[rows])
        metas.append(rows)
    prob = predict_blocks_prob(model, DEV, np.stack(Xs), bs=64)[1]
    for w, rows, pr in zip(test, metas, prob):
        hosts = cache.row_host[rows]
        per = {}
        for h, p in zip(hosts, pr):
            k = pfx_str(int(h >> 8 << 8))
            if p > per.get(k, -1):
                per[k] = float(p)
        for k, p in per.items():
            ben_events.append(p)
            ben_pfx.add(k)
    print('benign events', len(ben_events), 'prefixes', len(ben_pfx), 'days', round(days, 5), flush=True)
    att_scores = {}
    for r in inv['file_scan']:
        if not r['kind'].startswith('attack_holdout'):
            continue
        gtset = set(r['gt_prefixes']) & set(fold_pfx)
        if not gtset:
            continue
        fsel = [i for i, f in enumerate(cache.files) if f['file'] == r['file'] and f['kind'] == r['kind']]
        if not fsel:
            continue
        fi2 = fsel[0]
        blocks, metas = ([], [])
        for w in cache.file_windows(fi2):
            a, b = cache.window_rows(w)
            pf = cache.row_pfx[a:b]
            rows = np.arange(a, b)
            keep = rows[[pfx_str(int(x)) in gtset for x in pf]]
            if len(keep) == 0:
                continue
            for j in range(0, len(keep), N_POS):
                chunk = keep[j:j + N_POS]
                need = N_POINTS - len(chunk)
                fill = cache.row_X[rng.integers(0, len(cache.row_X), need)]
                blocks.append(np.concatenate([cache.row_X[chunk], fill]))
                metas.append(chunk)
        if not blocks:
            continue
        pr = predict_blocks_prob(model, DEV, np.stack(blocks), bs=128)[1]
        for bi, chunk in enumerate(metas):
            hosts = cache.row_host[chunk]
            for h, p in zip(hosts, pr[bi][:len(chunk)]):
                k = pfx_str(int(h >> 8 << 8))
                att_scores[k] = max(att_scores.get(k, -1), float(p))
    rows_out = []
    vals = np.asarray(ben_events)
    for target in TARGETS:
        allowed = target * len(ben_pfx) * days
        v = np.sort(vals)[::-1]
        allowed_i = int(np.floor(allowed))
        tau = float(v[0]) + 1e-09 if allowed_i <= 0 else float(v[allowed_i]) if allowed_i < len(v) else float(v.min()) - 1e-09
        actual = round(float((vals > tau).sum()) / len(ben_pfx) / days, 3)
        det = sum((1 for p in fold_pfx if att_scores.get(p, -1) > tau))
        rows_out.append({'method': 'netradar_p2fold0', 'fpr_per_pfx_day': target, 'fpr_actual': actual, 'tau': round(tau, 5), 'recall': round(det / len(fold_pfx), 4), 'tp': det, 'attack_pop': len(fold_pfx), 'benign_prefixes': len(ben_pfx), 'days': round(days, 5)})
        print(rows_out[-1], flush=True)
    ref = []
    fp = os.path.join(OUT, 'e3_fpr_operational.json')
    if os.path.exists(fp):
        ref = json.load(open(fp))['rows']
    with open(os.path.join(OUT, 'e3_fold0_fpr.json'), 'w') as f:
        json.dump({'fold_pfx': fold_pfx, 'rows': rows_out, 'sk_ref': [r for r in ref if r.get('method') == 'sweepsketch'], 'entropy_ref': [r for r in ref if r.get('method') == 'entropy']}, f, indent=1)
    print('wrote', os.path.join(OUT, 'e3_fold0_fpr.json'))
if __name__ == '__main__':
    main()
