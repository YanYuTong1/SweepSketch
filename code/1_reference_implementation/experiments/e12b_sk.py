import csv
import json
import os
import sys
import time
REV = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
IMPL_V2 = os.path.join(REV, 'code', '1_reference_implementation')
sys.path.insert(0, IMPL_V2)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sweepsketch import config
from sweepsketch.digest import Collector
from sweepsketch.pcapio import iter_pcap
from sweepsketch.v2run import finalize
from common import make_sketch
DB = os.path.join(REV, 'database')
E3 = os.path.join(REV, 'results', 'e3')
OUT = os.path.join(REV, 'results', 'e12b')
HORIZONS = [0.5, 1.0, 2.0]
NEED_S = 2.05
DIAG_FILE = '119.188.238.0_UDP-Carpet-Bombing_20250508.pcap'

def pfx_int(p):
    a, b, c = p.split('/')[0].split('.')[:3]
    return int(a) << 24 | int(b) << 16 | int(c) << 8

def run_v2(path, gt_int, horizon=NEED_S):
    col = Collector(keep_reason=True)
    sk = make_sketch(config.THETA0, 512)
    first = None
    n = 0
    for s, d, ts in iter_pcap(path, max_pkts=1 << 62, with_flow=False):
        if first is None:
            first = ts
        if ts - first > horizon + 1e-09:
            break
        sk.process(s, d, ts, col)
        n += 1
    eps, stats = finalize(col.alerts)
    l1 = [e for e in eps if e.level == 1 and e.key == gt_int]
    first_ep = min((e.ts - first for e in l1), default=None)
    raw = [a for a in col.alerts if a.level == 1 and a.key == gt_int]
    raw_d1 = min((a.ts - first for a in raw if a.reason == 'D1'), default=None)
    raw_d2 = min((a.ts - first for a in raw if a.reason == 'D2'), default=None)
    raw_n12 = min((a.ts - first for a in raw if a.reason == 'N12'), default=None)
    return {'first_episode_s': first_ep, 'raw_D1_s': raw_d1, 'raw_D2_s': raw_d2, 'raw_N12_s': raw_n12, 'episodes': len(l1), 'raw': len(raw), 'packets_fed': n, 'stats': stats}

def main():
    os.makedirs(OUT, exist_ok=True)
    t0 = time.time()
    inv = json.load(open(os.path.join(E3, 'inventory.json')))
    main = [r for r in inv['file_scan'] if r['kind'] == 'attack_main']
    rows = []
    for i, r in enumerate(main):
        gt = pfx_int(r['gt_prefixes'][0])
        res = run_v2(os.path.join(DB, r['path']), gt)
        row = {'file': r['file'], 'gt_prefix': r['gt_prefixes'][0], 'packets': r['packets'], 'span_s': r['span_s'], 'first_episode_s': res['first_episode_s'], 'raw_D1_s': res['raw_D1_s'], 'raw_D2_s': res['raw_D2_s'], 'raw_N12_s': res['raw_N12_s']}
        for h in HORIZONS:
            row['detected_h%s' % h] = int(res['first_episode_s'] is not None and res['first_episode_s'] <= h)
        rows.append(row)
        if i % 10 == 0:
            print('sk_v2', i, r['file'][:50], round(time.time() - t0), flush=True)
    with open(os.path.join(OUT, 'sk_v2_onset.csv'), 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    d = next((r for r in main if r['file'] == DIAG_FILE))
    gt = pfx_int(d['gt_prefixes'][0])
    col = Collector(keep_reason=True)
    sk = make_sketch(config.THETA0, 512)
    first = None
    for s, pkt_d, ts in iter_pcap(os.path.join(DB, d['path']), max_pkts=1 << 62, with_flow=False):
        if first is None:
            first = ts
        sk.process(s, pkt_d, ts, col)
    eps, stats = finalize(col.alerts)
    raw = sorted([a for a in col.alerts if a.level == 1 and a.key == gt], key=lambda a: a.ts)
    l1 = sorted([e for e in eps if e.level == 1 and e.key == gt], key=lambda e: e.ts)
    diag = {'file': DIAG_FILE, 'span_s': d['span_s'], 'gt_prefix': d['gt_prefixes'][0], 'first_packets': None, 'raw_alerts': [{'t_s': round(a.ts - first, 4), 'epoch_rel': round((a.ts - first) / config.EPOCH_S, 3), 'reason': a.reason, 'k': a.k, 'C': a.C, 'pkt': a.pkt} for a in raw[:40]], 'episodes': [{'t_s': round(e.ts - first, 4), 'epoch_rel': round((e.ts - first) / config.EPOCH_S, 3), 'reason': e.reason, 'k': e.k} for e in l1[:40]], 'stats': stats, 'first_episode_s': round(l1[0].ts - first, 4) if l1 else None, 'note': 'v2 full-file; compare with v1 e1_mixed (first_alert_s=0.177*22=3.89 s) and v2 e1_v2_latency (0.406*22=8.93 s)'}
    with open(os.path.join(OUT, 'e12b_22s_v2_diag.json'), 'w') as f:
        json.dump(diag, f, indent=1)
    print(json.dumps({'rows': len(rows), 'wall_s': round(time.time() - t0, 1), 'diag_first_episode_s': diag['first_episode_s']}))
if __name__ == '__main__':
    main()
