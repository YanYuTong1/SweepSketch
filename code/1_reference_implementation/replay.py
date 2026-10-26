#!/usr/bin/env python3
from __future__ import annotations
import argparse
import csv
import os
import struct
import sys
import time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from sweepsketch import config
from sweepsketch.digest import Collector
from sweepsketch.pcapio import iter_pcap
from sweepsketch.runner import finalize
from common import make_sketch

def iter_bin(path, limit=1 << 60):
    with open(path, 'rb') as f:
        n = 0
        while n < limit:
            b = f.read(12)
            if len(b) < 12:
                break
            ts_ns, dst = struct.unpack('<QI', b)
            n += 1
            yield (0, dst, ts_ns / 1000000000.0)

def iter_input(args):
    if args.pcap:
        return iter_pcap(args.pcap, args.limit, with_flow=False)
    return iter_bin(args.bin, args.limit)

def pfx24(k):
    return '%d.%d.%d.0/24' % (k >> 24 & 255, k >> 16 & 255, k >> 8 & 255)

def pfx16(k):
    return '%d.%d.0.0/16' % (k >> 24 & 255, k >> 16 & 255)

def write_csv(path, alerts, n_pkts, wall, args, stats, raw=False):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['ts_ns', 'epoch_full', 'level', 'key_int', 'key_str', 'reason', 'n_new', 'C', 'pkt'])
        for a in alerts:
            ts_ns = int(round(a.ts * 1000000000.0)) if a.ts is not None else ''
            ks = pfx16(a.key) if a.level >= 3 else pfx24(a.key)
            w.writerow([ts_ns, a.epoch, a.level, a.key, ks, a.reason, a.k, a.C, a.pkt])
    meta = os.path.splitext(path)[0] + '.meta.json'
    import json
    payload = {'tool': 'replay.py', 'argv': sys.argv, 'input': args.pcap or args.bin, 'limit': args.limit, 'budget_kb': args.budget_kb, 'raw': raw, 'n_packets': n_pkts, 'n_alerts': len(alerts), 'wall_s': round(wall, 2), 'pps': round(n_pkts / wall, 1) if wall > 0 else None, 'config': {'AGE_ENABLE': config.AGE_ENABLE, 'AGE_WIN': config.AGE_WIN, 'ALARM_CONFIRM': config.ALARM_CONFIRM, 'D2_CONFIRM_WINDOWS': config.D2_CONFIRM_WINDOWS, 'D2_CONFIRM_COUNT': config.D2_CONFIRM_COUNT, 'COOLDOWN_WIN': config.COOLDOWN_WIN, 'QUARANTINE': config.QUARANTINE, 'Q_MAX_K': config.Q_MAX_K, 'Q_GROWTH_MULT': config.Q_GROWTH_MULT, 'Q_REQUIRE_NO_D1': config.Q_REQUIRE_NO_D1, 'CROSS16': config.CROSS16, 'CROSS_W': config.CROSS_W, 'CROSS_K': config.CROSS_K, 'CROSS_NNEW_FLOOR': config.CROSS_NNEW_FLOOR}, 'stats': stats}
    with open(meta, 'w', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=True)

def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--pcap')
    g.add_argument('--bin')
    ap.add_argument('--budget-kb', type=int, default=512)
    ap.add_argument('--limit', type=int, default=1 << 60)
    ap.add_argument('--out', required=True)
    ap.add_argument('--raw', action='store_true')
    ap.add_argument('--age', choices=['on', 'off'], default='on')
    ap.add_argument('--alarm', choices=['on', 'off'], default='on')
    ap.add_argument('--cross16', choices=['on', 'off'], default='on')
    args = ap.parse_args()
    config.AGE_ENABLE = args.age == 'on'
    config.ALARM_CONFIRM = args.alarm == 'on'
    config.CROSS16 = args.cross16 == 'on'
    sk = make_sketch(config.THETA0, args.budget_kb)
    raw = Collector(keep_reason=True)
    t0 = time.time()
    n = 0
    for s, d, ts in iter_input(args):
        sk.process(s, d, ts, raw)
        n += 1
    wall = time.time() - t0
    eps, stats = finalize(raw.alerts)
    alerts = raw.alerts if args.raw else eps
    if args.raw:
        alerts = sorted(alerts, key=lambda a: (a.ts, a.level, a.key, a.reason))
    write_csv(args.out, alerts, n, wall, args, stats, raw=args.raw)
    pass
if __name__ == '__main__':
    main()
