import argparse
import csv
import json
import os
import resource
import sys
import time
import numpy as np
import torch
HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, HERE)
from e3_common import FeatureCache, OUT, pfx_str
NETRADAR = os.environ.get('NETRADAR_DIR', '')
if NETRADAR:
    sys.path.insert(0, os.path.join(NETRADAR, 'detectors'))
from nn_models.loss_sort import pointnet, pointnetloss
N_POINTS = 256
N_FEAT = 11
N_POS = 32
N_EVAL_MAX = 128
BATCH = 32
DROP_MASK = np.array([1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0], dtype=np.float32)

def log(*a):
    print(*a, flush=True)

def pfx_int(p):
    a, b, c = p.split('/')[0].split('.')[:3]
    return int(a) << 24 | int(b) << 16 | int(c) << 8
ATTACK_TYPES = ['DNS-Reflection', 'HTTPS-Reflection', 'HTTP-Reflection', 'TCP-Reflection', 'ACK', 'ICMP', 'SYN', 'UDP', 'WEB', 'HTTP']

def attack_type(name):
    for t in ATTACK_TYPES:
        if t in name:
            return t
    raise ValueError('unknown attack type: ' + name)

class Data:

    def __init__(self, cache, protocol, fold=None, seed=0, hold_type=None):
        self.c = cache
        self.protocol = protocol
        self.seed = seed
        self.rng = np.random.default_rng(seed)
        self.main_files = [i for i, f in enumerate(cache.files) if f['kind'] == 'attack_main']
        self.hold_files = [i for i, f in enumerate(cache.files) if f['kind'].startswith('attack_holdout')]
        self.cic_fi = next((i for i, f in enumerate(cache.files) if f['file'] == 'CIC-IDS-2017-Benign.pcap'))
        main_pfx = set()
        for fi in self.main_files:
            main_pfx.update(cache.files[fi]['gt_prefixes'])
        self.all_main_pfx = sorted(main_pfx)
        assert len(self.all_main_pfx) == 55, len(self.all_main_pfx)
        if protocol == 'p2':
            assert fold is not None
            self.fold_pfx = set(self.all_main_pfx[fold::5])
            self.train_pfx = set(self.all_main_pfx) - self.fold_pfx
            self.train_files = [fi for fi in self.main_files if all((p in self.train_pfx for p in cache.files[fi]['gt_prefixes']))]
        elif protocol == 'loto':
            assert hold_type in ATTACK_TYPES, hold_type
            self.hold_type = hold_type
            self.fold_pfx = None
            self.train_pfx = set(self.all_main_pfx)
            self.train_files = [fi for fi in self.main_files if attack_type(cache.files[fi]['file']) != hold_type]
        else:
            self.fold_pfx = None
            self.train_pfx = set(self.all_main_pfx)
            self.train_files = list(self.main_files)
        self.train_attack_w = np.concatenate([cache.file_windows(fi) for fi in self.train_files])
        if protocol == 'loto':
            self.test_files = [fi for fi in self.main_files if attack_type(cache.files[fi]['file']) == hold_type]
            self.test_prefixes = {p for fi in self.test_files for p in cache.files[fi]['gt_prefixes']}
        else:
            self.test_files = [fi for fi in self.hold_files if cache.files[fi]['gt_n'] > 0]
            self.test_prefixes = set(self.fold_pfx) if protocol == 'p2' else {p for fi in self.test_files for p in cache.files[fi]['gt_prefixes']}
        self.test_prefix_int = np.asarray(sorted((pfx_int(p) for p in self.test_prefixes)), dtype=np.int64)
        bw = cache.file_windows(self.cic_fi)
        order = bw[np.argsort(cache.win_t[bw])]
        cut = int(len(order) * 0.7)
        self.ben_train_w = order[:cut]
        self.ben_test_w = order[cut:]
        log('data: %s fold=%s train_files=%d train_windows=%d ben_train=%d ben_test=%d test_files=%d test_prefixes=%d' % (protocol, fold, len(self.train_files), len(self.train_attack_w), len(self.ben_train_w), len(self.ben_test_w), len(self.test_files), len(self.test_prefixes)))

    def benign_block(self, test=False):
        c = self.c
        pool = self.ben_test_w if test else self.ben_train_w
        w = int(pool[self.rng.integers(len(pool))])
        a, b = c.window_rows(w)
        idx = a + self.rng.integers(0, b - a, N_POINTS)
        return (c.row_X[idx], np.zeros(N_POINTS, dtype=np.int64))

    def attack_block_train(self, w):
        c = self.c
        a, b = c.window_rows(w)
        n = b - a
        if n <= N_POS:
            idx = np.concatenate([np.arange(a, b), a + self.rng.choice(n, N_POS - n, replace=True)])
        else:
            idx = a + self.rng.choice(n, N_POS, replace=False)
        need = N_POINTS - len(idx)
        X = c.row_X[idx].copy()
        y = c.row_lab[idx].astype(np.int64)
        if need:
            Xb, yb = self.benign_block()
            X = np.concatenate([X, Xb[:need]])
            y = np.concatenate([y, yb[:need]])
        return (X, y)

def train(data, dev, epochs, steps, seed, lr=0.001):
    torch.manual_seed(seed)
    model = pointnet(2, N_FEAT, N_POINTS).to(dev)
    crit = pointnetloss().to(dev)
    opt = torch.optim.Adam(model.parameters(), lr=lr, betas=(0.9, 0.999), eps=1e-08, weight_decay=0.0001)
    nw = len(data.train_attack_w)
    hist = []
    t0 = time.time()
    for ep in range(epochs):
        lr_ep = max(lr * 0.5 ** (ep // 20), 1e-06)
        for g in opt.param_groups:
            g['lr'] = lr_ep
        model.train()
        losses, accs, pos = ([], [], [])
        for _ in range(steps):
            Xs, ys = ([], [])
            for _b in range(BATCH):
                if data.rng.random() < 0.6:
                    w = int(data.train_attack_w[data.rng.integers(nw)])
                    X, y = data.attack_block_train(w)
                else:
                    X, y = data.benign_block()
                p = data.rng.choice([0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
                flag = data.rng.random(N_POINTS) < p
                mask = np.where(flag[:, None], DROP_MASK[None, :], np.ones((1, N_FEAT), dtype=np.float32))
                Xs.append(X * mask)
                ys.append(y)
                pos.append(float(y.mean()))
            xb = torch.from_numpy(np.stack(Xs)).to(dev)
            yb = torch.from_numpy(np.stack(ys)).to(dev)
            opt.zero_grad()
            pred, tf = model(xb.transpose(2, 1))
            pred = pred.contiguous().view(-1, 2)
            target = yb.view(-1, 1)[:, 0]
            loss = crit(pred, target, tf)
            loss.backward()
            opt.step()
            with torch.no_grad():
                acc = (pred.argmax(1) == target).float().mean().item()
            losses.append(float(loss.detach().cpu()))
            accs.append(acc)
        hist.append({'epoch': ep, 'loss': round(float(np.mean(losses)), 5), 'train_acc': round(float(np.mean(accs)), 5), 'pos_frac': round(float(np.mean(pos)), 4), 'lr': lr_ep, 'wall_s': round(time.time() - t0, 1)})
        log('  epoch %d loss %.4f acc %.4f pos %.3f (%.0fs)' % (ep, np.mean(losses), np.mean(accs), np.mean(pos), time.time() - t0))
    return (model, hist)

@torch.no_grad()
def predict_blocks(model, dev, X, bs=64):
    out = []
    model.eval()
    for i in range(0, len(X), bs):
        xb = torch.from_numpy(X[i:i + bs]).to(dev)
        pred, _ = model(xb.transpose(2, 1))
        out.append(pred.argmax(2).cpu().numpy())
    return np.concatenate(out, axis=0)

@torch.no_grad()
def predict_blocks_prob(model, dev, X, bs=64):
    outs, probs = ([], [])
    model.eval()
    for i in range(0, len(X), bs):
        xb = torch.from_numpy(X[i:i + bs]).to(dev)
        pred, _ = model(xb.transpose(2, 1))
        p1 = torch.softmax(pred, dim=2)[:, :, 1]
        outs.append(pred.argmax(2).cpu().numpy())
        probs.append(p1.cpu().numpy())
    return (np.concatenate(outs, axis=0), np.concatenate(probs, axis=0))

def eval_attack(data, model, dev):
    c = data.c
    prefix_alerts = {}
    first_seen = {}
    rule_counts = {}
    score_max = {}
    host_total = 0
    infer_ms = []
    model.eval()
    pending_X, pending_meta = ([], [])

    def flush():
        if not pending_X:
            return
        t1 = time.time()
        pr, prob = predict_blocks_prob(model, dev, np.stack(pending_X), bs=32)
        dt = (time.time() - t1) * 1000.0 / len(pr)
        infer_ms.extend([dt] * len(pr))
        for bi, (fi, w, chunk) in enumerate(pending_meta):
            sm = score_max.setdefault(fi, {})
            for h, sc in zip(chunk, prob[bi][:len(chunk)]):
                p = int(c.row_pfx[h])
                sc = float(sc)
                if p not in sm or sc > sm[p]:
                    sm[p] = sc
            hit = chunk[pr[bi][:len(chunk)] == 1]
            if len(hit):
                ts = float(c.win_t[w])
                ep = int(ts // EPOCH)
                pa = prefix_alerts.setdefault(fi, {})
                rc = rule_counts.setdefault(fi, {})
                for h in hit:
                    p = int(c.row_pfx[h])
                    if p not in pa or ts < pa[p]:
                        pa[p] = ts
                    pp = rc.setdefault(p, {})
                    pp[ep] = pp.get(ep, 0) + 1
        pending_X.clear()
        pending_meta.clear()
    for fi in data.test_files:
        for w in c.file_windows(fi):
            a, b = c.window_rows(w)
            if data.protocol == 'p2':
                keep = np.isin(c.row_pfx[a:b], data.test_prefix_int)
                rows = np.arange(a, b)[keep]
            else:
                rows = np.arange(a, b)
            if len(rows) == 0:
                continue
            host_total += len(rows)
            ts_w = float(c.win_t[w])
            fs = first_seen.setdefault(fi, {})
            for p in np.unique(c.row_pfx[rows]):
                p = int(p)
                if p not in fs or ts_w < fs[p]:
                    fs[p] = ts_w
            if len(rows) > N_EVAL_MAX:
                keep_rows = data.rng.choice(rows, N_EVAL_MAX, replace=False)
            else:
                keep_rows = rows
            for j in range(0, len(keep_rows), N_POS):
                chunk = keep_rows[j:j + N_POS]
                if len(chunk) < N_POS:
                    chunk = np.concatenate([chunk, data.rng.choice(rows, N_POS - len(chunk), replace=True)])
                need = N_POINTS - N_POS
                Xb, _ = data.benign_block(test=True)
                X = np.concatenate([c.row_X[chunk], Xb[:need]])
                pending_X.append(X)
                pending_meta.append((fi, w, chunk))
                if len(pending_X) >= 32:
                    flush()
        if len(pending_X) >= 16:
            flush()
    flush()
    return (prefix_alerts, first_seen, {'attack_host_rows': int(host_total)}, rule_counts, score_max, infer_ms)

def eval_benign(data, model, dev):
    c = data.c
    blocks, meta = ([], [])
    for w in data.ben_test_w:
        a, b = c.window_rows(w)
        rows = np.arange(a, b)
        if len(rows) == 0:
            continue
        idx = rows if len(rows) <= N_POINTS else data.rng.choice(rows, N_POINTS, replace=False)
        need = N_POINTS - len(idx)
        if need:
            idx = np.concatenate([idx, data.rng.choice(idx, need, replace=True)])
        blocks.append(c.row_X[idx])
        meta.append((w, idx))
    infer_ms = []
    alerts = {}
    ben_rule = {}
    ben_score = {}
    for i in range(0, len(blocks), 64):
        t1 = time.time()
        pr, prob = predict_blocks_prob(model, dev, np.stack(blocks[i:i + 64]), bs=64)
        infer_ms += [(time.time() - t1) * 1000.0 / len(pr)] * len(pr)
        for bi in range(len(pr)):
            w, idx = meta[i + bi]
            for h, sc in zip(idx, prob[bi]):
                p = int(c.row_pfx[h])
                sc = float(sc)
                if p not in ben_score or sc > ben_score[p]:
                    ben_score[p] = sc
            hit = idx[pr[bi] == 1]
            if len(hit) == 0:
                continue
            ts = float(c.win_t[w])
            ep = int(ts // EPOCH)
            for h in hit:
                p = int(c.row_pfx[h])
                if p not in alerts or ts < alerts[p]:
                    alerts[p] = ts
                pp = ben_rule.setdefault(p, {})
                pp[ep] = pp.get(ep, 0) + 1
    return (alerts, ben_rule, ben_score, infer_ms)
EPOCH = 4294967296 / 1000000000.0

def rule_metrics(prefix_alerts, rule_counts, ben_rule, data):
    c = data.c
    if data.protocol == 'p2':
        gt = {pfx_int(p) for p in data.fold_pfx}
    else:
        gt = {pfx_int(p) for fi in data.test_files for p in c.files[fi]['gt_prefixes']}
    ben_pfx = set()
    for w in data.ben_test_w:
        a, b = c.window_rows(w)
        ben_pfx.update((int(x) for x in np.unique(c.row_pfx[a:b])))
    out = {}
    for name, k in [('any_host_ever', 1), ('ge4_hosts_per_epoch', 4), ('ge8_hosts_per_epoch', 8), ('ge16_hosts_per_epoch', 16)]:
        det = set()
        for fi, rc in rule_counts.items():
            for p, epc in rc.items():
                if p in {pfx_int(x) for x in c.files[fi]['gt_prefixes']} and any((v >= k for v in epc.values())):
                    det.add(p)
        fp = {p for p in ben_rule if any((v >= k for v in ben_rule[p].values()))}
        fp &= ben_pfx
        tp, fn, fpp = (len(det & gt), len(gt - det), len(fp))
        out[name] = {'k': k, 'tp': tp, 'fn': fn, 'fp': fpp, 'precision': round(tp / (tp + fpp), 4) if tp + fpp else 0.0, 'recall': round(tp / (tp + fn), 4) if tp + fn else 0.0, 'f1': round(2 * tp / (2 * tp + fn + fpp), 4) if tp else 0.0}
    return out

def prefix_metrics(data, prefix_alerts, ben_alerts, first_seen):
    c = data.c
    gt_int = {pfx_int(p): p for p in data.test_prefixes}
    first_t = {}
    for fi, pa in prefix_alerts.items():
        for p, t in pa.items():
            if p not in first_t or t < first_t[p]:
                first_t[p] = t
    tp_set = set(gt_int) & set(first_t)
    fn_set = set(gt_int) - set(first_t)
    seg_tp = seg_fn = 0
    for fi in data.test_files:
        pa = prefix_alerts.get(fi, {})
        for p in c.files[fi]['gt_prefixes']:
            if pfx_int(p) in pa:
                seg_tp += 1
            else:
                seg_fn += 1
    ben_pfx = set()
    for w in data.ben_test_w:
        a, b = c.window_rows(w)
        ben_pfx.update((int(x) for x in np.unique(c.row_pfx[a:b])))
    fp = set(ben_alerts) & ben_pfx
    tp, fn, fpp = (len(tp_set), len(fn_set), len(fp))
    return {'gt_prefixes': len(gt_int), 'tp_prefixes': tp, 'fn_prefixes': fn, 'precision': round(tp / (tp + fpp), 4) if tp + fpp else 0.0, 'recall': round(tp / (tp + fn), 4) if tp + fn else 0.0, 'f1': round(2 * tp / (2 * tp + fn + fpp), 4) if tp else 0.0, 'seg_tp': seg_tp, 'seg_fn': seg_fn, 'benign_test_prefixes': len(ben_pfx), 'benign_fp_prefixes': fpp, 'alerted_prefixes': sorted((gt_int[p] for p in tp_set)), 'missed_prefixes': sorted((gt_int[p] for p in fn_set)), 'benign_fp_list': sorted((pfx_str(p) for p in fp))[:200], 'first_alert_t_s': {gt_int[p]: round(first_t[p], 3) for p in sorted(tp_set)}}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--protocol', choices=['p1', 'p2', 'loto'], default='p1')
    ap.add_argument('--fold', type=int, default=0)
    ap.add_argument('--hold-type', default=None)
    ap.add_argument('--seed', type=int, default=0)
    ap.add_argument('--epochs', type=int, default=6)
    ap.add_argument('--steps', type=int, default=300)
    ap.add_argument('--full-epoch', action='store_true', help='steps/epoch = ceil(train_windows/BATCH), i.e. every training window is visited once per epoch')
    ap.add_argument('--dev', default=None)
    ap.add_argument('--tag', default='')
    ap.add_argument('--outdir', default=OUT, help='output directory (default results/e3)')
    ap.add_argument('--no-save', action='store_true', help='do not write the 141 MB model checkpoint')
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    cache = FeatureCache()
    dev = args.dev or ('mps' if torch.backends.mps.is_available() else 'cpu')
    torch.set_num_threads(2)
    data = Data(cache, args.protocol, args.fold, args.seed, args.hold_type)
    steps = args.steps
    if args.full_epoch:
        steps = int(np.ceil(len(data.train_attack_w) / BATCH))
        log('full-epoch: %d steps/epoch (windows=%d)' % (steps, len(data.train_attack_w)))
    t0 = time.time()
    model, hist = train(data, dev, args.epochs, steps, args.seed)
    train_wall = time.time() - t0
    log('train done in %.0fs' % train_wall)
    nparam = sum((p.numel() for p in model.parameters()))
    t1 = time.time()
    prefix_alerts, first_seen, host_stat, rule_counts, score_max, infer_ms = eval_attack(data, model, dev)
    eval_attack_wall = time.time() - t1
    t2 = time.time()
    ben_alerts, ben_rule, ben_score, ben_ms = eval_benign(data, model, dev)
    eval_ben_wall = time.time() - t2
    pm = prefix_metrics(data, prefix_alerts, ben_alerts, first_seen)
    pm['alert_rule_sensitivity'] = rule_metrics(prefix_alerts, rule_counts, ben_rule, data)
    pm.update(host_stat)
    all_ms = infer_ms + ben_ms

    def pct(v, q):
        return round(float(np.percentile(v, q)), 3) if v else None
    ts_file, ts_onset = ([], [])
    for fi, pa in prefix_alerts.items():
        gts = {pfx_int(x) for x in cache.files[fi]['gt_prefixes']}
        for p, t in pa.items():
            if p not in gts:
                continue
            ts_file.append(t)
            onset = first_seen.get(fi, {}).get(p)
            if onset is not None:
                ts_onset.append(t - onset)
    ts_file.sort()
    ts_onset.sort()
    lat_stats = {'n': len(ts_file), 'file_relative': {'p50': pct(ts_file, 50), 'p95': pct(ts_file, 95), 'p99': pct(ts_file, 99), 'max': round(max(ts_file), 3) if ts_file else None, 'mean': round(float(np.mean(ts_file)), 3) if ts_file else None, 'note': "first-flagged window time since file first packet. WARNING: by_timestamp holdout files concatenate captures across dates (span up to 1.6e7 s), so a prefix that first appears late in the file has a huge 'latency' that is not detection delay."}, 'onset_relative': {'p50': pct(ts_onset, 50), 'p95': pct(ts_onset, 95), 'p99': pct(ts_onset, 99), 'max': round(max(ts_onset), 3) if ts_onset else None, 'mean': round(float(np.mean(ts_onset)), 3) if ts_onset else None, 'note': 'PRIMARY detection delay: first-flagged window time minus the first window in which that prefix appears; includes the 1 s feature-window dwell, excludes wall-clock compute.'}}
    test_pkts = sum((cache.files[fi]['packets'] for fi in data.test_files))
    perf = {'train_wall_s': round(train_wall, 1), 'eval_attack_wall_s': round(eval_attack_wall, 1), 'eval_benign_wall_s': round(eval_ben_wall, 1), 'session_wall_s': round(time.time() - t0, 1), 'test_attack_packets': test_pkts, 'inference_ms_per_block_p50': pct(all_ms, 50), 'inference_ms_per_block_p95': pct(all_ms, 95), 'inference_ms_per_block_p99': pct(all_ms, 99), 'inference_ms_per_block_max': round(max(all_ms), 3) if all_ms else None, 'inference_blocks': len(all_ms), 'param_M': round(nparam / 1000000.0, 2), 'model_bytes': int(nparam * 4), 'peak_rss_MB': round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1000000.0 if sys.platform == 'darwin' else 1000.0), 1)}
    out = {'protocol': args.protocol, 'fold': args.fold, 'seed': args.seed, 'device': dev, 'epochs': args.epochs, 'steps_per_epoch': steps, 'full_epoch': bool(args.full_epoch), 'batch': BATCH, 'n_points': N_POINTS, 'n_pos': N_POS, 'n_eval_max': N_EVAL_MAX, 'train_files': [cache.files[fi]['file'] for fi in data.train_files], 'test_files': [cache.files[fi]['file'] for fi in data.test_files], 'train_windows': int(len(data.train_attack_w)), 'benign_train_windows': int(len(data.ben_train_w)), 'benign_test_windows': int(len(data.ben_test_w)), 'train_log': hist, 'prefix_metrics': pm, 'latency_event_s': lat_stats, 'perf': perf, 'notes': ['official pointnet/pointnetloss/training semantics from NETRADAR_DIR checkout; feature extractor = official C++ T2', "URL-derived host features are 0 (no HTTP payload pipeline), so this is a lower bound of NetRadar's paper configuration on HTTP attacks", 'test attack windows are padded with benign test-segment hosts to 256 points, mirroring the official 256-server inference input'], 'host': os.uname().nodename, 'finished': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
    tag = args.tag or '%s_fold%d_seed%d' % (args.protocol, args.fold, args.seed)
    if not args.no_save:
        model_path = os.path.join(args.outdir, 'model_' + tag + '.pt')
        torch.save(model.state_dict(), model_path)
        out['model_path'] = model_path
    out['prefix_max_score'] = {cache.files[fi]['kind'] + '|' + cache.files[fi]['file']: {pfx_str(p): round(s, 6) for p, s in sorted(sm.items())} for fi, sm in score_max.items()}
    out['benign_max_score'] = {pfx_str(p): round(s, 6) for p, s in sorted(ben_score.items())}
    path = os.path.join(args.outdir, 'netradar_' + tag + '.json')
    with open(path, 'w') as f:
        json.dump(out, f, indent=1)
    with open(os.path.join(args.outdir, 'netradar_scores_' + tag + '.csv'), 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['kind', 'file', 'prefix', 'max_score'])
        for fi, sm in score_max.items():
            for p, s in sorted(sm.items()):
                w.writerow([cache.files[fi]['kind'], cache.files[fi]['file'], pfx_str(p), round(s, 6)])
        for p, s in sorted(ben_score.items()):
            w.writerow(['benign_test', 'CIC-IDS-2017-Benign.pcap', pfx_str(p), round(s, 6)])
    with open(os.path.join(args.outdir, 'netradar_prefix_alerts_' + tag + '.csv'), 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['kind', 'file', 'prefix', 'first_alert_t_s'])
        for fi, pa in prefix_alerts.items():
            for p, t in sorted(pa.items()):
                w.writerow([cache.files[fi]['kind'], cache.files[fi]['file'], pfx_str(p), round(t, 3)])
    log(json.dumps({'tag': tag, 'f1': pm['f1'], 'p': pm['precision'], 'r': pm['recall'], 'fp': pm['benign_fp_prefixes'], 'seg': [pm['seg_tp'], pm['seg_fn']], 'lat': lat_stats}, indent=1))
    log('wrote', path)
if __name__ == '__main__':
    main()
