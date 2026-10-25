import csv
import os
import sys
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sweepsketch import config, pcapio
from sweepsketch.sketch import SweepSketch
from sweepsketch.digest import Collector
from common import DB, RES
HERE = os.path.dirname(os.path.abspath(__file__))
ATT = os.path.join(DB, 'attack')
MULTI_DIRS = [('natural', os.path.join(ATT, 'natural_multi24')), ('synthetic_byts', os.path.join(ATT, 'synthetic_multi24_by_timestamp')), ('synthetic_shuffled', os.path.join(ATT, 'synthetic_multi24_shuffled'))]
BENIGN_FILES = [('benign', os.path.join(DB, 'benign', 'CIC-IDS-2017-Benign.pcap')), ('benign', os.path.join(DB, 'benign', 'CIC-IoT-2023-Benign.pcap'))]
GT_FRAC = 0.01
MAX_PKTS_ATT = 10000000
MAX_PKTS_BENIGN = config.BENIGN_MAX

def _pfx(k):
    return '%d.%d.%d.0/24' % (k >> 24 & 255, k >> 16 & 255, k >> 8 & 255)

def _one_file(path, theta0, kind):
    t0 = time.time()
    total = 0
    segs = {}
    first_ts = last_ts = None
    max_pkts = MAX_PKTS_BENIGN if kind == 'benign' else MAX_PKTS_ATT
    for s, d, ts in pcapio.iter_pcap(path, max_pkts=max_pkts, with_flow=False):
        total += 1
        if first_ts is None:
            first_ts = ts
        last_ts = ts
        segs[d >> 8 << 8] = segs.get(d >> 8 << 8, 0) + 1
    if total == 0:
        return None
    gt = [] if kind == 'benign' else sorted((k for k, c in segs.items() if c >= total * GT_FRAC))
    sk = SweepSketch(theta0)
    col = Collector()
    for s, d, ts in pcapio.iter_pcap(path, max_pkts=max_pkts, with_flow=False):
        sk.process(s, d, ts, col)
    alerts = [a for a in col.alerts if a.level == 1]
    by_key = {}
    for a in alerts:
        by_key.setdefault(a.key, []).append((a.epoch, a.ts))
    gt_set = set(gt)
    tp = [k for k in gt if k in by_key]
    fn = [k for k in gt if k not in by_key]
    fp_keys = sorted((k for k in by_key if k not in gt_set))
    fp_events = sum((len(v) for k, v in by_key.items() if k not in gt_set))
    first_hit = min((a.ts for a in alerts if a.key in gt_set), default=None)
    lat = round(first_hit - first_ts, 1) if first_hit is not None else ''
    return {'folder': os.path.basename(os.path.dirname(path)), 'file': os.path.basename(path), 'kind': kind, 'packets': total, 'span_s': round(last_ts - first_ts, 1), 'gt_segs': ' '.join((_pfx(k) for k in gt)), 'tp': len(tp), 'fn': len(fn), 'fp_segs': len(fp_keys), 'fp_events': fp_events, 'first_alert_s': lat, 'alerted_gt': ' '.join((_pfx(k) for k in tp)), 'alerted_fp': ' '.join((_pfx(k) for k in fp_keys)), 'wall_s': round(time.time() - t0, 1)}

def run_real(theta0, dump=None):
    files = []
    for kind, d in MULTI_DIRS:
        files += [(kind, os.path.join(d, f)) for f in sorted(os.listdir(d)) if f.lower().endswith(('.pcap', '.pcapng', '.csv', '.csv.gz'))]
    files += BENIGN_FILES
    rows = []
    pass
    for kind, path in files:
        r = _one_file(path, theta0, kind)
        if r is None:
            pass
            continue
        rows.append(r)
        pass
        if r['fn']:
            pass
        if r['alerted_fp']:
            pass
    os.makedirs(RES, exist_ok=True)
    cols = ['folder', 'file', 'kind', 'packets', 'span_s', 'gt_segs', 'tp', 'fn', 'fp_segs', 'fp_events', 'first_alert_s', 'alerted_gt', 'alerted_fp', 'wall_s']
    with open(os.path.join(RES, 'EXP_real.csv'), 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    tot = {'tp': sum((r['tp'] for r in rows)), 'fn': sum((r['fn'] for r in rows)), 'fp_segs': sum((r['fp_segs'] for r in rows))}
    pass
    return (rows, tot)
if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--theta0', type=float, default=config.THETA0)
    ap.add_argument('--one', default=None, help=' ( )')
    args = ap.parse_args()
    if args.one:
        r = _one_file(args.one, args.theta0, 'debug')
        for k, v in (r or {}).items():
            print('%-14s %s' % (k, v))
    else:
        run_real(args.theta0)
