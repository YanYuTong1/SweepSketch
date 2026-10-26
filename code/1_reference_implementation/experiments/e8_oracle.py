from __future__ import annotations
import argparse
import csv
import heapq
import json
import os
import platform
import resource
import subprocess
import sys
import time
from datetime import datetime
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import rev_common as rc
rc.add_impl_path()
from sweepsketch import config
from sweepsketch.epoch import epoch_of
from sweepsketch.llr import make_llr_table
from sweepsketch.pcapio import iter_pcap
from common import ATT_DIR, BENIGN, DUMMY, STAGGER, attack_files, f1_of, feed, flush, h_flag, ip24, make_sketch
OUT = os.path.join(rc.RESULTS, 'e8')
PARTS = os.path.join(OUT, 'parts')
LOG = os.path.join(rc.LOGS, 'e8')
HW_BITMAP_KB_PER_PREFIX = (1 << 24) // 8 // 1024
VARIANTS = {'exact_serial': dict(kind='exact', stream='serial'), 'exact_concurrent': dict(kind='exact', stream='concurrent'), 'exact_cal_serial': dict(kind='exact', stream='serial', recal=True), 'sweep512_serial': dict(kind='sweep', stream='serial', kb=512), 'sweep1024_serial': dict(kind='sweep', stream='serial', kb=1024), 'sweep512_concurrent': dict(kind='sweep', stream='concurrent', kb=512)}

class ExactBucket:
    __slots__ = ('key', 'epoch', 'win', 'n_new', 'n_ewma', 'C', 'pkt', 'pkt_ewma', 'seen', 'd2_held', 'peak')

    def __init__(self, key, epoch=0):
        self.key, self.epoch = (key, epoch)
        self.win = 1
        self.n_new = self.n_ewma = self.C = 0
        self.pkt = self.pkt_ewma = 0
        self.d2_held = False
        self.seen = set()
        self.peak = 0

    def process(self, d, global_epoch, llr_tbl):
        delta = 0
        if self.epoch != global_epoch:
            self.d2_held = self.pkt >= max(config.P_MIN, config.D2_MULT * self.pkt_ewma) and self.n_new >= max(config.K_FLOOD, 2 * self.n_ewma if config.USE_GATE else 0)
            self.n_ewma += self.n_new - self.n_ewma >> config.EWMA_SHIFT
            self.pkt_ewma += self.pkt - self.pkt_ewma >> config.EWMA_SHIFT
            delta -= len(self.seen)
            self.seen.clear()
            self.n_new = self.pkt = self.C = 0
            self.win = self.win + 1 & config.WIN_MASK
        if d in self.seen:
            event = 0
        else:
            self.seen.add(d)
            event = 1
            delta += 1
        self.C = min(config.C_MAX, max(0, self.C + llr_tbl['new' if event else 'rep']))
        self.n_new = len(self.seen)
        self.pkt = min(config.PKT_MAX, self.pkt + 1)
        self.epoch = global_epoch
        if self.n_new > self.peak:
            self.peak = self.n_new
        gate = max(config.K_ALARM, 2 * self.n_ewma if config.USE_GATE else 0, config.K_ALARM_QUIET if config.USE_GATE and self.n_ewma < config.N_EWMA_QUIET else 0)
        alarm1 = config.USE_D1 and self.C >= config.H_FP and (self.n_new >= gate)
        alarm2 = config.USE_D2 and self.pkt >= config.P_MIN and (self.pkt >= config.D2_MULT * self.pkt_ewma) and (self.n_new >= max(config.K_FLOOD, 2 * self.n_ewma if config.USE_GATE else 0)) and self.d2_held
        return (alarm1, alarm2, delta)

class ExactSketch:

    def __init__(self, theta0):
        self.theta0 = theta0
        self.llr = make_llr_table(theta0)
        self.buckets = {}
        self.entries = 0
        self.peak_entries = 0
        self.alerts_l1 = 0
        self.flagged = set()
        self.n_pkts = 0

    def process(self, _s, d, ts):
        g = epoch_of(ts)
        key = d >> 8 << 8
        b = self.buckets.get(key)
        if b is None:
            b = self.buckets[key] = ExactBucket(key, g)
        a1, a2, delta = b.process(d, g, self.llr)
        self.entries += delta
        if self.entries > self.peak_entries:
            self.peak_entries = self.entries
        self.n_pkts += 1
        if a1 or a2:
            self.alerts_l1 += 1
            self.flagged.add(key)

def attack_plan():
    plan = []
    for f in attack_files():
        path = os.path.join(ATT_DIR, f)
        first = last = None
        n = 0
        for _s, _d, ts in iter_pcap(path, config.ATTACK_MAX, with_flow=False):
            n += 1
            if first is None:
                first = ts
            last = ts
        plan.append(dict(file=f, path=path, first=first, last=last, n=n, pfx=ip24(f.split('_')[0])))
    return plan

def stream_serial(plan):
    gt_benign = set()
    for s, d, ts in iter_pcap(BENIGN, config.BENIGN_MAX, with_flow=False):
        gt_benign.add(d >> 8 << 8)
        yield (s, d, ts)
    cursor = 4000000000.0
    for item in plan:
        for s, d, ts in iter_pcap(item['path'], config.ATTACK_MAX, with_flow=False):
            yield (s, d, ts - item['first'] + cursor)
        cursor += item['last'] - item['first'] + STAGGER

def stream_concurrent(plan):
    bfirst = blast = None
    for _s, _d, ts in iter_pcap(BENIGN, config.BENIGN_MAX, with_flow=False):
        if bfirst is None:
            bfirst = ts
        blast = ts
    D = max(1e-09, blast - bfirst)

    def benign():
        for s, d, ts in iter_pcap(BENIGN, config.BENIGN_MAX, with_flow=False):
            yield (s, d, ts)

    def atk(item, t_start):
        shift = t_start - item['first']
        for s, d, ts in iter_pcap(item['path'], config.ATTACK_MAX, with_flow=False):
            yield (s, d, ts + shift)
    streams = [benign()]
    for i, item in enumerate(plan):
        streams.append(atk(item, bfirst + (i + 1) * D / (len(plan) + 1)))
    yield from heapq.merge(*streams, key=lambda x: x[2])

def _rss_kb():
    v = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return v / 1024.0 if platform.system() == 'Darwin' else float(v)

def run_exact(stream, theta0, gt_attack):
    base = _rss_kb()
    sk = ExactSketch(theta0)
    t0 = time.time()
    for s, d, ts in stream:
        sk.process(s, d, ts)
    wall = time.time() - t0
    peak = _rss_kb()
    peaks = sorted((b.peak for b in sk.buckets.values()))
    pct = lambda q: peaks[min(len(peaks) - 1, int(q * len(peaks)))] if peaks else 0
    tp, fp, fn, f1v = f1_of({k: True for k in sk.flagged}, gt_attack, set(sk.buckets) - gt_attack)
    return dict(variant='', kind='exact', theta0=theta0, n_prefixes=len(sk.buckets), n_pkts=sk.n_pkts, memory_measured_kb=round(peak - base, 0), memory_state_kb=round(sk.peak_entries * (28 + 8) / 1024.0, 0), peak_entries=sk.peak_entries, bytes_per_entry=round((peak - base) * 1024 / max(1, sk.peak_entries), 1), prefix_peak_distinct_p50=pct(0.5), prefix_peak_distinct_p95=pct(0.95), prefix_peak_distinct_max=peaks[-1] if peaks else 0, hw_bitmap_kb_total=HW_BITMAP_KB_PER_PREFIX * len(sk.buckets), tp=tp, fp=fp, fn=fn, f1=round(f1v, 4), n_alerts=sk.alerts_l1, wall_s=round(wall, 1), pps=round(sk.n_pkts / wall, 0))

def run_sweep(stream, kb, theta0, gt_attack):
    base = _rss_kb()
    sk = make_sketch(theta0, kb)
    stats, cur = ({}, {})
    t0 = time.time()
    n = 0
    for s, d, ts in stream:
        feed(sk, stats, cur, s, d, ts, DUMMY)
        n += 1
    flush(stats, cur)
    wall = time.time() - t0
    peak = _rss_kb()
    gt_benign = {k[1] for k in stats if k[0] == 1} - gt_attack
    fl = h_flag(9.2)
    flagged = {k[1]: True for k, s2 in stats.items() if k[0] == 1 and fl(s2)}
    tp, fp, fn, f1v = f1_of(flagged, gt_attack, gt_benign)
    return dict(variant='', kind='sweep', kb=kb, theta0=theta0, n_prefixes=len(gt_benign), n_pkts=n, memory_measured_kb=round(peak - base, 0), memory_state_kb=round((sk.l1.nb + sk.l2.nb) * 44 / 1024.0, 0), peak_entries='', bytes_per_entry='', prefix_peak_distinct_p50='', prefix_peak_distinct_p95='', prefix_peak_distinct_max='', hw_bitmap_kb_total='', tp=tp, fp=fp, fn=fn, f1=round(f1v, 4), n_alerts=len(flagged), wall_s=round(wall, 1), pps=round(n / wall, 0))

def calibrate_exact(plan):
    llr = None
    sk = ExactSketch(config.THETA0)
    cur = {}
    rates = []
    for s, d, ts in stream_serial(plan):
        key = d >> 8 << 8
        g = epoch_of(ts)
        b = sk.buckets.get(key)
        if b is None:
            b = sk.buckets[key] = ExactBucket(key, g)
        prev_epoch = b.epoch
        b.process(d, g, sk.llr)
        if b.epoch != prev_epoch:
            r = cur.get(key)
            if r is not None and r[1] >= 50:
                rates.append(r[0] / r[1])
        cur[key] = (b.n_new, b.pkt)
    for key, (nn, pkt) in cur.items():
        if pkt >= 50 and nn > 0:
            rates.append(nn / pkt)
    rates.sort()
    theta = rates[len(rates) // 2] if rates else config.THETA0
    return (round(theta, 6), len(rates))

def run_variant(name):
    cfg = VARIANTS[name]
    os.makedirs(PARTS, exist_ok=True)
    plan = attack_plan()
    gt_attack = {ip24(f.split('_')[0]) for f in attack_files()}
    gen = stream_serial(plan) if cfg['stream'] == 'serial' else stream_concurrent(plan)
    theta0 = config.THETA0
    extra = {}
    if cfg.get('recal'):
        theta0, n_busy = calibrate_exact(plan)
        extra['theta0_exact'] = theta0
        extra['n_busy_windows_exact'] = n_busy
        print('exact recalibration: theta0_exact=%.4f over %d busy windows' % (theta0, n_busy), flush=True)
        gen = stream_serial(plan)
    t0 = time.time()
    if cfg['kind'] == 'exact':
        r = run_exact(gen, theta0, gt_attack)
    else:
        r = run_sweep(gen, cfg['kb'], theta0, gt_attack)
    r['variant'] = name
    r['stream'] = cfg['stream']
    r.update(extra)
    r['wall_total_s'] = round(time.time() - t0, 1)
    r['host_platform'] = platform.platform()
    with open(os.path.join(PARTS, name + '.json'), 'w', encoding='utf-8') as fh:
        json.dump(r, fh, ensure_ascii=False, indent=2, sort_keys=True)
    print('E8 %-20s %s' % (name, json.dumps({k: v for k, v in r.items() if k in ('theta0', 'memory_measured_kb', 'memory_state_kb', 'tp', 'fp', 'fn', 'f1', 'wall_s', 'pps', 'peak_entries')}, ensure_ascii=False)), flush=True)
    return r

def _run_child(name):
    run_variant(name)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--variant', default=None, help='subprocess interface: run a single variant')
    ap.add_argument('--variants', default=','.join(VARIANTS))
    args = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    os.makedirs(LOG, exist_ok=True)
    if args.variant:
        run_variant(args.variant)
        return
    names = [v for v in args.variants.split(',') if v in VARIANTS]
    t_all = time.time()
    start = datetime.now().astimezone().isoformat(timespec='seconds')
    log = os.path.join(LOG, 'e8_oracle.log')
    for n in names:
        with open(log, 'a', encoding='utf-8') as fh:
            fh.write('### %s %s\n' % (datetime.now().isoformat(timespec='seconds'), n))
        rc_ = subprocess.run([sys.executable, '-u', os.path.abspath(__file__), '--variant', n], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        with open(log, 'a', encoding='utf-8') as fh:
            fh.write(rc_.stdout or '')
        print(rc_.stdout, end='', flush=True)
        if rc_.returncode != 0:
            print('[e8] variant %s failed (see %s)' % (n, rc.rel(log)), flush=True)
            sys.exit(2)
    rows = []
    for n in names:
        p = os.path.join(PARTS, n + '.json')
        if os.path.exists(p):
            rows.append(json.load(open(p, encoding='utf-8')))
    cols = ['variant', 'kind', 'stream', 'kb', 'theta0', 'theta0_exact', 'n_prefixes', 'n_pkts', 'memory_measured_kb', 'memory_state_kb', 'peak_entries', 'bytes_per_entry', 'prefix_peak_distinct_p50', 'prefix_peak_distinct_p95', 'prefix_peak_distinct_max', 'hw_bitmap_kb_total', 'tp', 'fp', 'fn', 'f1', 'n_alerts', 'wall_s', 'pps', 'wall_total_s']
    out = os.path.join(OUT, 'e8_oracle.csv')
    with open(out, 'w', newline='', encoding='utf-8') as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction='ignore')
        w.writeheader()
        w.writerows(rows)
    exact = [r for r in rows if r['kind'] == 'exact']
    sweep512 = [r for r in rows if r['kind'] == 'sweep' and r.get('kb') == 512]
    ratio = ''
    if exact and sweep512:
        ratio = round(float(exact[0]['memory_measured_kb']) / 512.0, 1)
    rc.write_meta(out, experiment='e8_oracle', command='python3 -u e8_oracle.py --variants %s' % args.variants, full_scale=True, sampling='none', workers=1, theta0=config.THETA0, note_theta0='the main row uses the theta0 calibrated for T-HLL; the exact_cal_serial row recalibrates theta0 for the exact event stream on CIC benign traffic with the same calibration procedure', memory_method='each variant runs in its own subprocess; resource.ru_maxrss peak minus baseline (bytes converted to KB on macOS)', hw_bitmap_kb_per_prefix=HW_BITMAP_KB_PER_PREFIX, memory_ratio_exact_over_512kb=ratio, variants=names, design=dict(exact='per-/24 dict/set: exact count of distinct destination IPs in the window; gate/CUSUM/EWMA/d2_held mirror bucket.py line by line (only T-HLL event generation is replaced)', serial='R0/EXP1 protocol (full benign stream, then the 71 attacks appended, cursor=4e9)', concurrent='the 71 attacks are inserted concurrently into the benign timeline by their real timestamps (same as E5)', gt='destination-side /24; tp/fp/fn under entity-level F1 (h=9.2 / H_FP=74)'), start=start, end=datetime.now().astimezone().isoformat(timespec='seconds'), wall_s=round(time.time() - t_all, 1), log=rc.rel(log), notes=['the exact event stream has no T-HLL rho-recording events, so theta0 is not fully comparable; a recalibration row is included', 'same-memory comparison: measured exact-oracle memory / 512KB = %sx' % ratio])
    print('\nwrote %s (%d rows)' % (rc.rel(out), len(rows)), flush=True)
if __name__ == '__main__':
    main()
