import json
import os
import sys
import time
import numpy as np
REV = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REV, 'code', '1_reference_implementation'))
from sweepsketch import pcapio
DB = os.path.join(REV, 'database')
ATT = os.path.join(DB, 'attack', 'normal_single24')
BEN = os.path.join(DB, 'benign', 'CIC-IDS-2017-Benign.pcap')
OUT = os.path.join(REV, 'results', 'e10')
EPOCH = 4294967296 / 1000000000.0
SEG = 600.0

def sweep_widths():
    files = sorted((f for f in os.listdir(ATT) if f.lower().endswith(('.csv', '.csv.gz', '.pcap', '.pcapng'))))
    all_s = []
    rows = []
    for f in files:
        p = os.path.join(ATT, f)
        t0 = None
        ep = {}
        for s, d, ts in pcapio.iter_pcap(p, max_pkts=1 << 62, with_flow=False):
            if t0 is None:
                t0 = ts
            e = int((ts - t0) // EPOCH)
            pf = d >> 8 << 8
            ep.setdefault((e, pf), set()).add(d)
        pfx_counts = {}
        for (e, pf), hosts in ep.items():
            pfx_counts.setdefault(pf, []).append(len(hosts))
            all_s.append(len(hosts))
        main_pfx = max(pfx_counts, key=lambda k: sum(pfx_counts[k]))
        rows.append({'file': f, 'gt_prefix': '%d.%d.%d.0/24' % (main_pfx >> 24 & 255, main_pfx >> 16 & 255, main_pfx >> 8 & 255), 'epochs': len(pfx_counts.get(main_pfx, [])), 's_median': float(np.median(pfx_counts[main_pfx])) if pfx_counts.get(main_pfx) else 0, 's_max': max(pfx_counts[main_pfx]) if pfx_counts.get(main_pfx) else 0})
    s = np.asarray(all_s)
    return {'n_prefix_epochs': int(len(s)), 'mean': round(float(s.mean()), 2), 'median': float(np.median(s)), 'p10': float(np.percentile(s, 10)), 'p25': float(np.percentile(s, 25)), 'p75': float(np.percentile(s, 75)), 'p90': float(np.percentile(s, 90)), 'p95': float(np.percentile(s, 95)), 'p99': float(np.percentile(s, 99)), 'max': int(s.max()), 'hist': {str(k): int(v) for k, v in zip(*np.unique(np.clip(s, 0, 256), return_counts=True))}, 'samples': [int(x) for x in s[:20000]], 'per_file': rows}

def pick_benign_segment():
    bins = {}
    n = 0
    t_first = None
    for s, d, ts in pcapio.iter_pcap(BEN, max_pkts=1 << 62, with_flow=False):
        if t_first is None:
            t_first = ts
        b = int((ts - t_first) // SEG)
        bins.setdefault(b, set()).add(d >> 8 << 8)
        n += 1
        if n % 2000000 == 0:
            print('  benign scanned', n, flush=True)
    best = max(bins, key=lambda k: len(bins[k]))
    npkt = {}
    for s, d, ts in pcapio.iter_pcap(BEN, max_pkts=1 << 62, with_flow=False):
        b = int((ts - t_first) // SEG)
        npkt[b] = npkt.get(b, 0) + 1
    return {'segment_s': SEG, 'best_bin': int(best), 't_start': round(best * SEG, 3), 't_end': round((best + 1) * SEG, 3), 'distinct_24': len(bins[best]), 'packets': npkt.get(best, 0), 'distinct_24_all_file': len(set().union(*bins.values())), 'bins': len(bins), 'per_bin_distinct': {str(k): len(v) for k, v in sorted(bins.items(), key=lambda x: -len(x[1]))[:20]}}

def main():
    os.makedirs(OUT, exist_ok=True)
    t0 = time.time()
    print('sweep widths ...', flush=True)
    sw = sweep_widths()
    print('  n', sw['n_prefix_epochs'], 'median', sw['median'], 'p90', sw['p90'], 'p99', sw['p99'], flush=True)
    print('benign segment ...', flush=True)
    seg = pick_benign_segment()
    print('  best', seg['best_bin'], 'prefixes', seg['distinct_24'], 'packets', seg['packets'], flush=True)
    out = {'script': os.path.abspath(__file__), 'epoch_s': EPOCH, 'sweep_width_source': '71 project attack pcaps (normal_single24), per (target /24, epoch) distinct dst hosts', 'sweep_width': sw, 'benign_segment': seg, 'wall_s': round(time.time() - t0, 1), 'finished': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'host': os.uname().nodename}
    with open(os.path.join(OUT, 'sweep_dist.json'), 'w') as f:
        json.dump(out, f)
    print('wrote', os.path.join(OUT, 'sweep_dist.json'))
if __name__ == '__main__':
    main()
