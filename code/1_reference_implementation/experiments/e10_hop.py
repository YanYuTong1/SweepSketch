import argparse
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
BEN = os.path.join(DB, 'benign', 'CIC-IDS-2017-Benign.pcap')
OUT = os.path.join(REV, 'results', 'e10')
EPOCH = 4294967296 / 1000000000.0
ATTACK_POOL_BASE = 198 << 24
ATTACK_POOL_N = 512
RATES = [40, 100, 400]
DWELLS = [1, 2]
SEEDS = [0, 1, 2, 3, 4]
N_ATTACK_EPOCHS = 120
START_EPOCH = 10
MAX_WORKERS = int(os.environ.get('SWEEPSKETCH_WORKERS', '2'))

def load_benign(t_start, t_end):
    out = []
    t0 = None
    for s, d, ts in iter_pcap(BEN, max_pkts=1 << 62, with_flow=False):
        if t0 is None:
            t0 = ts
        rel = ts - t0
        if rel < t_start:
            continue
        if rel >= t_end:
            break
        out.append((s, d, rel - t_start))
    return out

def load_sweep_dist():
    d = json.load(open(os.path.join(OUT, 'sweep_dist.json')))
    seg = d['benign_segment']
    s = np.asarray(d['sweep_width']['samples'], dtype=np.int32)
    return (s, seg)

def add_benign_prefixes(benign, seg, target_total=5000):
    st = json.load(open(os.path.join(OUT, 'benign_pfx_epoch.json')))
    have = {d >> 8 << 8 for _, d, _ in benign}
    need = target_total - len(have)
    if need <= 0:
        return (benign, len(have), 0)
    hist = np.asarray([(int(k), v) for k, v in st['hist'].items() if 1 <= int(k) <= 9], dtype=np.int64)
    s_vals = hist[:, 0]
    probs = hist[:, 1] / hist[:, 1].sum()
    cand = []
    for b in range(64, 128):
        for c in range(256):
            cand.append(100 << 24 | b << 16 | c << 8)
            if len(cand) >= need:
                break
        if len(cand) >= need:
            break
    rng = np.random.default_rng(20261021)
    n_ep = int(seg['segment_s'] / EPOCH)
    extra = []
    n_extra_pkts = 0
    for pf in cand[:need]:
        acts = [int(rng.integers(0, n_ep))]
        if rng.random() < st['p_active'] * n_ep:
            acts.append(int(rng.integers(0, n_ep)))
        for e in acts:
            S = int(rng.choice(s_vals, p=probs))
            S = max(1, min(S, 9))
            hosts = pf & ~255 | rng.choice(256, S, replace=False)
            for h in hosts:
                ts = e * EPOCH + rng.random() * EPOCH
                extra.append((10 << 24, int(pf & ~255 | h), ts))
                n_extra_pkts += 1
    print('synthetic benign prefixes', need, 'packets', n_extra_pkts, flush=True)
    return (benign + extra, len(have) + need, n_extra_pkts)

def gen_attack(rng, rate, dwell_windows, n_epochs, s_pool, pool, start_epoch):
    pkts = []
    events = []
    prev_target = None
    e = start_epoch
    targets = list(pool)
    while e < start_epoch + n_epochs:
        d = dwell_windows if e + dwell_windows <= start_epoch + n_epochs else start_epoch + n_epochs - e
        t = rng.choice(targets)
        while t == prev_target and len(targets) > 1:
            t = rng.choice(targets)
        prev_target = t
        ev_start = e * EPOCH
        ev_end = (e + d) * EPOCH
        events.append({'target': int(t), 'start': ev_start, 'end': ev_end, 'epochs': int(d), 's_list': []})
        for w in range(d):
            ws = (e + w) * EPOCH
            npkt = int(round(rate * EPOCH))
            S = int(s_pool[rng.integers(len(s_pool))])
            S = max(1, min(S, 256, npkt))
            events[-1]['s_list'].append((S, npkt))
            dsts = t & ~255 | np.asarray(rng.choice(256, S, replace=False), dtype=np.uint32)
            for k in range(npkt):
                ts = ws + (k + rng.random()) / npkt * EPOCH
                dj = dsts[k % S]
                sid = 10 << 24 | int(rng.integers(1, 1 << 24))
                pkts.append((sid, int(dj), ts))
        e += d
    return (pkts, events)

def run_once(rng, benign, rate, dwell, seed, s_pool, pool, control=False):
    if control:
        att_pkts, events = ([], [])
    else:
        att_pkts, events = gen_attack(rng, rate, dwell, N_ATTACK_EPOCHS, s_pool, pool, START_EPOCH)
    all_pkts = benign + att_pkts
    all_pkts.sort(key=lambda x: x[2])
    sk = make_sketch(config.THETA0, 512)
    col = Collector()
    for s, d, ts in all_pkts:
        sk.process(s, d, ts, col)
    alerts = [a for a in col.alerts if a.level == 1]
    by_key = {}
    for a in alerts:
        by_key.setdefault(a.key, []).append(a.ts)
    attack_keys = set(pool)
    ev_rows = []
    for ev in events:
        ts_list = by_key.get(ev['target'], [])
        first = min((x for x in ts_list if ev['start'] <= x <= ev['end']), default=None)
        late = min((x for x in ts_list if x > ev['end']), default=None)
        ev_rows.append({'seed': seed, 'rate': rate, 'dwell': dwell, 'target': '%d.%d.%d.0/24' % (ev['target'] >> 24 & 255, ev['target'] >> 16 & 255, ev['target'] >> 8 & 255), 'start_s': round(ev['start'], 3), 'end_s': round(ev['end'], 3), 's_median': float(np.median([x[0] for x in ev['s_list']])) if ev['s_list'] else None, 'detected': int(first is not None), 'first_alert_s': None if first is None else round(first - ev['start'], 3), 'post_window_alert_s': None if late is None else round(late - ev['end'], 3)})
    win_rows = []
    for ev in events:
        for w in range(ev['epochs']):
            ws = ev['start'] + w * EPOCH
            we = ws + EPOCH
            first = min((x for x in by_key.get(ev['target'], []) if ws <= x <= we), default=None)
            S, npkt = ev['s_list'][w] if w < len(ev['s_list']) else (None, None)
            win_rows.append({'seed': seed, 'rate': rate, 'dwell': dwell, 'target': ev['target'], 'window': w, 'S': S, 'packets': npkt, 'detected': int(first is not None), 'lat_s': None if first is None else round(first - ws, 3)})
    fp_keys = {k: v for k, v in by_key.items() if k not in attack_keys}
    fp_events = sum((len(v) for v in fp_keys.values()))
    return (ev_rows, win_rows, {'rate': rate, 'dwell': dwell, 'seed': seed, 'events': len(events), 'events_detected': sum((r['detected'] for r in ev_rows)), 'windows': len(win_rows), 'windows_detected': sum((r['detected'] for r in win_rows)), 'fp_prefixes': len(fp_keys), 'fp_events': fp_events, 'fp_prefix_list': ' '.join(('%d.%d.%d.0/24' % (k >> 24 & 255, k >> 16 & 255, k >> 8 & 255) for k in sorted(fp_keys))), 'fp_per_hour': round(fp_events / (N_ATTACK_EPOCHS * EPOCH) * 3600, 2), 'total_alerts': len(alerts), 'attack_packets': sum((1 for _ in [])), 'wall_s': None})

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--seeds', type=int, nargs='+', default=SEEDS)
    ap.add_argument('--rates', type=int, nargs='+', default=RATES)
    ap.add_argument('--dwells', type=int, nargs='+', default=DWELLS)
    ap.add_argument('--smoke', action='store_true')
    ap.add_argument('--control', action='store_true', help='no attack traffic; measures baseline FP only')
    ap.add_argument('--tag', default='')
    args = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    s_pool, seg = load_sweep_dist()
    t_start, t_end = (seg['t_start'], seg['t_end'])
    print('benign segment %.1f-%.1f s, %d distinct /24' % (t_start, t_end, seg['distinct_24']), flush=True)
    benign = load_benign(t_start, t_end)
    benign, n_ben_pfx, n_ben_extra = add_benign_prefixes(benign, seg, 5000)
    print('benign packets', len(benign), 'prefixes', n_ben_pfx, flush=True)
    benign_keys = {d >> 8 << 8 for _, d, _ in benign}
    pool = [ATTACK_POOL_BASE + (i << 8) for i in range(ATTACK_POOL_N)]
    pool = [p for p in pool if p not in benign_keys]
    print('attack target pool', len(pool), flush=True)
    if args.smoke:
        args.seeds = [0]
        args.rates = [100]
        args.dwells = [1]
    if args.control:
        args.seeds = [0]
        args.rates = [0]
        args.dwells = [1]
    rows, ev_all, win_all = ([], [], [])
    t0 = time.time()
    for rate in args.rates:
        for dwell in args.dwells:
            for seed in args.seeds:
                rng = np.random.default_rng(1000 * seed + 7 * rate + 13 * dwell)
                t1 = time.time()
                evr, wr, r = run_once(rng, benign, rate, dwell, seed, s_pool, pool, control=args.control)
                r['wall_s'] = round(time.time() - t1, 2)
                r['attack_packets'] = rate * EPOCH * N_ATTACK_EPOCHS
                rows.append(r)
                ev_all += evr
                win_all += wr
                print('  rate=%3d dwell=%d seed=%d events %d/%d windows %d/%d fp_pfx=%d fp_ev=%d %.1fs' % (rate, dwell, seed, r['events_detected'], r['events'], r['windows_detected'], r['windows'], r['fp_prefixes'], r['fp_events'], r['wall_s']), flush=True)
    with open(os.path.join(OUT, (args.tag or '') + 'e10_runs.csv'), 'w', newline='') as f:
        cols = list(rows[0].keys())
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(OUT, (args.tag or '') + 'e10_events.csv'), 'w', newline='') as f:
        if not ev_all:
            f.write('no_events\n')
            ev_all = []
        cols = list(ev_all[0].keys()) if ev_all else []
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(ev_all)
    with open(os.path.join(OUT, (args.tag or '') + 'e10_windows.csv'), 'w', newline='') as f:
        cols = list(win_all[0].keys()) if win_all else []
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(win_all)
    summ = {}
    for r in rows:
        k = 'rate%d_dwell%d' % (r['rate'], r['dwell'])
        s = summ.setdefault(k, {'rate': r['rate'], 'dwell': r['dwell'], 'event_det': 0, 'event_n': 0, 'win_det': 0, 'win_n': 0, 'fp_pfx': [], 'fp_ev': [], 'lat': []})
        s['event_det'] += r['events_detected']
        s['event_n'] += r['events']
        s['win_det'] += r['windows_detected']
        s['win_n'] += r['windows']
        s['fp_pfx'].append(r['fp_prefixes'])
        s['fp_ev'].append(r['fp_events'])
    for r in ev_all:
        if r['detected']:
            k = 'rate%d_dwell%d' % (r['rate'], r['dwell'])
            summ[k]['lat'].append(r['first_alert_s'])
    for k, s in summ.items():
        lat = sorted(s.pop('lat'))
        s['event_detection_rate'] = round(s['event_det'] / s['event_n'], 4) if s['event_n'] else None
        s['window_detection_rate'] = round(s['win_det'] / s['win_n'], 4) if s['win_n'] else None
        s['fp_prefixes_mean'] = round(float(np.mean(s['fp_pfx'])), 2)
        s['fp_prefixes_max'] = int(np.max(s['fp_pfx']))
        s['fp_events_mean'] = round(float(np.mean(s['fp_ev'])), 2)
        s['latency_p50_s'] = round(float(np.percentile(lat, 50)), 3) if lat else None
        s['latency_p95_s'] = round(float(np.percentile(lat, 95)), 3) if lat else None
        s['latency_max_s'] = round(max(lat), 3) if lat else None
        s['latency_n'] = len(lat)
    out = {'design': {'epoch_s': EPOCH, 'rates_pps': args.rates, 'dwell_windows': args.dwells, 'seeds': args.seeds, 'attack_epochs': N_ATTACK_EPOCHS, 'start_epoch': START_EPOCH, 'sweep_width_source': 'empirical per-(/24,epoch) distinct dst hosts from the 71 project attack pcaps', 'sweep_width_median': float(np.median(s_pool)), 'benign_segment_s': seg['segment_s'], 'benign_segment_t': [t_start, t_end], 'benign_distinct_24': n_ben_pfx, 'benign_distinct_24_real_segment': seg['distinct_24'], 'benign_synthetic_prefix_packets': n_ben_extra, 'benign_packets': len(benign), 'target_pool': len(pool), 'target_pool_range': '198.18.0.0/15 (RFC2544)', 'detector': 'SweepSketch 512KB: L1 7943 / L2 3972 buckets, theta0=%.4f, h=%.1f bits' % (config.THETA0, config.H_BITS), 'alert': 'L1 (/24) only; event detected if any L1 alert for the target prefix inside the dwell window'}, 'by_config': summ, 'runs': rows, 'started': time.strftime('%Y-%m-%dT%H:%M:%S%z', time.localtime(t0)), 'finished': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'wall_s': round(time.time() - t0, 1), 'host': os.uname().nodename, 'workers': MAX_WORKERS, 'python': sys.version.split()[0]}
    with open(os.path.join(OUT, (args.tag or '') + 'e10_summary.json'), 'w') as f:
        json.dump(out, f, indent=1)
    print(json.dumps(summ, indent=1))
    print('wrote', OUT)
if __name__ == '__main__':
    main()
