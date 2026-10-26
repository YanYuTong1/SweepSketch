import csv
import json
import os
import subprocess
import sys
import time
import numpy as np
import torch
HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, HERE)
from e3_common import FeatureCache, load_raw_file, pfx_str
import e11_gen as G
NETRADAR = os.environ.get('NETRADAR_DIR', '')
if NETRADAR:
    sys.path.insert(0, os.path.join(NETRADAR, 'detectors'))
from nn_models.loss_sort import pointnet
OUT = os.path.join(REV, 'results', 'e11')
RAW = os.path.join(OUT, 'raw')
BIN = os.path.join(NETRADAR, 'cpp_datacooking', 'build', 'extract_raw_feature')
MAPS = os.path.join(OUT, 'tmp')
N_POINTS, N_FEAT, N_POS = (256, 11, 32)
N_EVAL_MAX = 128
DEV = torch.device('mps' if torch.backends.mps.is_available() else 'cpu')

def prepare_maps():
    os.makedirs(MAPS, exist_ok=True)
    with open(os.path.join(MAPS, 'empty_list.json'), 'w') as f:
        f.write('[]')
    src = os.path.join(REV, 'results', 'e3', 'http_maps', 'benign__CIC-IDS-2017-Benign.pcap.json')
    d = json.load(open(src))
    with open(os.path.join(MAPS, 'cic_url.json'), 'w') as f:
        json.dump(d['url_map'], f)
    with open(os.path.join(MAPS, 'cic_size.json'), 'w') as f:
        json.dump(d['flow_size'], f)
    with open(os.path.join(MAPS, 'cic_pkt.json'), 'w') as f:
        json.dump(d['flow_pkt_size'], f)

def extract_features(cfg):
    os.makedirs(RAW, exist_ok=True)
    out = os.path.join(RAW, cfg + '.txt')
    if os.path.exists(out) and os.path.getsize(out) > 0:
        return out
    cmd = [BIN, os.path.join(OUT, 'pcap', cfg + '.pcap'), os.path.join(MAPS, 'cic_url.json'), os.path.join(MAPS, 'cic_size.json'), os.path.join(MAPS, 'cic_pkt.json'), os.path.join(MAPS, 'empty_list.json'), out, '--features', 'statistic_t2_1000']
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    return out

def load_model(path):
    m = pointnet(2, N_FEAT, N_POINTS).to(DEV)
    m.load_state_dict(torch.load(path, map_location=DEV))
    m.eval()
    return m

@torch.no_grad()
def predict(model, X, bs=64):
    outs, probs = ([], [])
    for i in range(0, len(X), bs):
        xb = torch.from_numpy(X[i:i + bs]).to(DEV)
        pred, _ = model(xb.transpose(2, 1))
        p1 = torch.softmax(pred, dim=2)[:, :, 1]
        outs.append(pred.argmax(2).cpu().numpy())
        probs.append(p1.cpu().numpy())
    return (np.concatenate(outs, axis=0), np.concatenate(probs, axis=0))

def benign_pool(cache, n=200000):
    fi = next((i for i, f in enumerate(cache.files) if f['file'] == 'CIC-IDS-2017-Benign.pcap'))
    bw = cache.file_windows(fi)
    order = bw[np.argsort(cache.win_t[bw])]
    test = order[int(len(order) * 0.7):]
    rows = []
    for w in test:
        a, b = cache.window_rows(w)
        rows.append(np.arange(a, b))
    rows = np.concatenate(rows)
    if len(rows) > n:
        sel = np.random.default_rng(0).choice(len(rows), n, replace=False)
        rows = rows[sel]
    return cache.row_X[rows]

def main():
    os.makedirs(OUT, exist_ok=True)
    prepare_maps()
    cache = FeatureCache()
    benX = benign_pool(cache)
    rng = np.random.default_rng(0)
    models = {}
    for tag in ('p1_full_seed1', 'p1_full_seed2'):
        p = os.path.join(REV, 'results', 'e3', 'model_' + tag + '.pt')
        if os.path.exists(p):
            models[tag] = load_model(p)
    print('models', list(models), 'benign pool', benX.shape, flush=True)
    cfgs = []
    for dur in G.DURATIONS:
        for S in G.SWEEPS:
            for rate in G.RATES:
                cfgs.append('dur%g_S%d_r%d_s0' % (dur, S, rate))
    rows = []
    t0 = time.time()
    for cfg in cfgs:
        meta = json.load(open(os.path.join(OUT, 'attack_' + cfg + '.json')))
        windows = meta['windows']
        t1 = time.time()
        raw = extract_features(cfg)
        tw, th, tx, totals = load_raw_file(raw)
        nw = len(tw)
        win_by_pfx = {}
        for w in windows:
            win_by_pfx.setdefault(w['target'], []).append(w)
        blocks, bmeta = ([], [])
        for wi in range(nw):
            hosts = np.asarray(th[wi], dtype=np.int64)
            if not len(hosts):
                continue
            hi16 = hosts >> 16
            sel = (hi16 == 198 << 8 | 18) | (hi16 == 198 << 8 | 19)
            if not sel.any():
                continue
            rows_i = np.arange(len(hosts))[sel]
            if len(rows_i) > N_EVAL_MAX:
                rows_i = rng.choice(rows_i, N_EVAL_MAX, replace=False)
            Xh = tx[wi][rows_i]
            for j in range(0, len(rows_i), N_POS):
                chunk = rows_i[j:j + N_POS]
                need = N_POINTS - len(chunk)
                bi = rng.integers(0, len(benX), need)
                X = np.concatenate([Xh[j:j + len(chunk)], benX[bi]])
                blocks.append((wi, chunk, X))
        if not blocks:
            print('  %-22s no attack-pool rows' % cfg, flush=True)
            continue
        Xall = np.stack([b[2] for b in blocks])
        for tag, model in models.items():
            pred, prob = predict(model, Xall)
            flagged = {}
            flag_cnt = {}
            ben_hit = ben_n = 0
            for bi, (wi, chunk, X) in enumerate(blocks):
                ts = float(tw[wi])
                hw = np.asarray(th[wi], dtype=np.int64)[chunk]
                hits = prob[bi][:len(chunk)] >= 0.5
                for h, hit in zip(hw, hits):
                    pfx = int(h) >> 8 << 8
                    if hit:
                        flagged.setdefault(pfx, []).append(ts)
                        kk = (pfx, wi)
                        flag_cnt[kk] = flag_cnt.get(kk, 0) + 1
                ben_hit += int((prob[bi][len(chunk):] >= 0.5).sum())
                ben_n += N_POINTS - len(chunk)
            det = {'strict': 0, 'overlap': 0, 'lenient': 0, 'ge4': 0, 'ge8': 0, 'ge16': 0}
            lat = []
            for w in windows:
                ts = flagged.get(w['target'], [])
                hs = [x for x in ts if w['start'] <= x <= w['end'] + 0.5]
                ho = [x for x in ts if w['start'] - 0.5 <= x <= w['end'] + 1.0]
                hl = [x for x in ts if w['start'] - 1.5 <= x <= w['end'] + 2.0]
                if hs:
                    det['strict'] += 1
                if ho:
                    det['overlap'] += 1
                    lat.append(max(0.0, min(ho) - w['start']))
                if hl:
                    det['lenient'] += 1
                cnts = [c for (p2, wi2), c in flag_cnt.items() if p2 == w['target']]
                best = max(cnts) if cnts else 0
                if best >= 4:
                    det['ge4'] += 1
                if best >= 8:
                    det['ge8'] += 1
                if best >= 16:
                    det['ge16'] += 1
            n = len(windows)
            ben_pfx = {pfx for pfx in flagged if pfx >> 16 != 198 << 8 | 18 and pfx >> 16 != 198 << 8 | 19}
            rows.append({'cfg': cfg, 'model': tag, 'dur': meta['dur'], 'S': meta['S'], 'rate': meta['rate'], 'windows': n, 'det_strict': det['strict'], 'det_overlap': det['overlap'], 'det_lenient': det['lenient'], 'det_ge4': det['ge4'], 'det_ge8': det['ge8'], 'det_ge16': det['ge16'], 'recall_strict': round(det['strict'] / n, 4), 'recall_overlap': round(det['overlap'] / n, 4), 'recall_lenient': round(det['lenient'] / n, 4), 'recall_ge8': round(det['ge8'] / n, 4), 'recall_ge16': round(det['ge16'] / n, 4), 'lat_p50': round(float(np.percentile(lat, 50)), 3) if lat else None, 'lat_p95': round(float(np.percentile(lat, 95)), 3) if lat else None, 'benign_host_fp': round(ben_hit / max(ben_n, 1), 5), 'benign_pfx_fp': len(ben_pfx), 'feature_windows': nw, 'blocks': len(blocks), 'wall_s': round(time.time() - t1, 1)})
            print('  %-22s %-14s recall %.3f/%.3f/%.3f  fps %.4f (%.1fs)' % (cfg, tag, rows[-1]['recall_strict'], rows[-1]['recall_overlap'], rows[-1]['recall_lenient'], rows[-1]['benign_host_fp'], rows[-1]['wall_s']), flush=True)

    def agg(mask, model=None):
        sel = [r for r in rows if mask(r) and (model is None or r['model'] == model)]
        n = sum((r['windows'] for r in sel)) or 1
        return {'runs': len(sel), 'recall_strict': round(sum((r['det_strict'] for r in sel)) / n, 4), 'recall_overlap': round(sum((r['det_overlap'] for r in sel)) / n, 4), 'recall_lenient': round(sum((r['det_lenient'] for r in sel)) / n, 4), 'recall_ge8': round(sum((r['det_ge8'] for r in sel)) / n, 4), 'recall_ge16': round(sum((r['det_ge16'] for r in sel)) / n, 4)}
    summary = {'by_dur': {str(d): agg(lambda r, d=d: r['dur'] == d) for d in G.DURATIONS}, 'by_S': {str(s): agg(lambda r, s=s: r['S'] == s) for s in G.SWEEPS}, 'by_rate': {str(x): agg(lambda r, x=x: r['rate'] == x) for x in G.RATES}, 'overall': agg(lambda r: True), 'per_model': {m: agg(lambda r: True, m) for m in models}, 'benign_host_fp_mean': round(float(np.mean([r['benign_host_fp'] for r in rows])), 5) if rows else None, 'note': 'detection = some victim host of the target /24 flagged in a 1 s feature window within [start-0.5, end+1.0]; benign fillers are sampled CIC hosts used only for context/FP', 'wall_s': round(time.time() - t0, 1), 'host': os.uname().nodename, 'finished': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
    with open(os.path.join(OUT, 'e11_netradar_summary.json'), 'w') as f:
        json.dump(summary, f, indent=1)
    if rows:
        with open(os.path.join(OUT, 'e11_netradar_runs.csv'), 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
    print(json.dumps(summary, indent=1))
if __name__ == '__main__':
    main()
