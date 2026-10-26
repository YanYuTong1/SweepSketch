import csv
import json
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor
REV = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REV, 'code', '1_reference_implementation'))
from sweepsketch import pcapio
DB = os.path.join(REV, 'database')
ATT = os.path.join(DB, 'attack')
BEN = os.path.join(DB, 'benign')
OUT = os.path.join(REV, 'results', 'e3')
GT_FRAC = 0.01
WORKERS = int(os.environ.get('SWEEPSKETCH_WORKERS', '2'))

def pfx(k):
    return '%d.%d.%d.0/24' % (k >> 24 & 255, k >> 16 & 255, k >> 8 & 255)

def scan_one(job):
    kind, path = job
    t0 = time.time()
    total = 0
    first = last = None
    segs = {}
    for s, d, ts in pcapio.iter_pcap(path, max_pkts=1 << 62, with_flow=False):
        total += 1
        if first is None:
            first = ts
        last = ts
        k = d >> 8 << 8
        segs[k] = segs.get(k, 0) + 1
    gt = [] if kind.startswith('benign') else sorted((k for k, c in segs.items() if c >= total * GT_FRAC))
    r = {'kind': kind, 'file': os.path.basename(path), 'path': os.path.relpath(path, DB), 'packets': total, 'first_ts': first, 'last_ts': last, 'span_s': round(last - first, 3) if total else 0.0, 'n_dst_24': len(segs), 'gt_prefixes': [pfx(k) for k in gt], 'gt_n': len(gt), 'gt_pkt_share': round(sum((segs[k] for k in gt)) / total, 6) if total else 0.0, 'scan_wall_s': round(time.time() - t0, 2), 'seg_pkt_counts': {pfx(k): c for k, c in sorted(segs.items(), key=lambda x: -x[1])[:200]}}
    print('  %-52s %9d pkts  %7.1fs  gt=%d  (%.1fs)' % (r['path'], total, r['span_s'], len(gt), r['scan_wall_s']), flush=True)
    return r

def main():
    jobs = []
    for d, kind in [('normal_single24', 'attack_main'), ('natural_multi24', 'attack_holdout_natural'), ('synthetic_multi24_by_timestamp', 'attack_holdout_byts'), ('synthetic_multi24_shuffled', 'attack_holdout_shuffled')]:
        dd = os.path.join(ATT, d)
        for f in sorted(os.listdir(dd)):
            if f.endswith('.pcap'):
                jobs.append((kind, os.path.join(dd, f)))
    for f in ['CIC-IDS-2017-Benign.pcap', 'CIC-IoT-2023-Benign.pcap', 'CIC-IoT-2023-Benign1.pcap', 'CIC-IoT-2023-Benign2.pcap', 'CIC-IoT-2023-Benign3.pcap']:
        p = os.path.join(BEN, f)
        if os.path.exists(p):
            jobs.append(('benign', p))
    os.makedirs(OUT, exist_ok=True)
    t0 = time.time()
    rows = []
    with ProcessPoolExecutor(max_workers=WORKERS) as ex:
        for r in ex.map(scan_one, jobs):
            rows.append(r)
    by = {}
    for r in rows:
        by.setdefault(r['kind'], {'files': 0, 'packets': 0})
        by[r['kind']]['files'] += 1
        by[r['kind']]['packets'] += r['packets']
    meta = {'script': os.path.abspath(__file__), 'argv': sys.argv, 'started': time.strftime('%Y-%m-%dT%H:%M:%S%z', time.localtime(t0)), 'finished': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'wall_s': round(time.time() - t0, 1), 'workers': WORKERS, 'gt_frac': GT_FRAC, 'gt_convention': 'per-file dst /24 share >= 1% of IPv4 packets (exp_real.py convention)', 'host': os.uname().nodename, 'python': sys.version.split()[0], 'totals_by_kind': by, 'file_scan': rows}
    with open(os.path.join(OUT, 'inventory.json'), 'w') as f:
        json.dump(meta, f, indent=1)
    with open(os.path.join(OUT, 'inventory.csv'), 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['kind', 'file', 'packets', 'span_s', 'n_dst_24', 'gt_n', 'gt_prefixes', 'gt_pkt_share', 'scan_wall_s'])
        for r in rows:
            w.writerow([r['kind'], r['file'], r['packets'], r['span_s'], r['n_dst_24'], r['gt_n'], ' '.join(r['gt_prefixes']), r['gt_pkt_share'], r['scan_wall_s']])
    print(json.dumps(by, indent=1))
    print('wrote', os.path.join(OUT, 'inventory.json'))
if __name__ == '__main__':
    main()
