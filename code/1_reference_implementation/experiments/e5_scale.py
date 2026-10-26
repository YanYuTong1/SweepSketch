from __future__ import annotations
import argparse
import csv
import heapq
import os
import sys
import time
from collections import defaultdict
from datetime import datetime
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import rev_common as rc
rc.add_impl_path()
from sweepsketch import config
from sweepsketch.bucket import Bucket
from sweepsketch.digest import Alert
from sweepsketch.hash import pfx_hash
from sweepsketch.pcapio import iter_pcap
from sweepsketch.sketch import Level, SweepSketch
from common import BENIGN, DUMMY, attack_files, f1_of, feed, flush, h_flag, ip24
OUT = os.path.join(rc.RESULTS, 'e5')
LOG = os.path.join(rc.LOGS, 'e5')
BENIGN_BASE = 167772160
ATTACK_BASE = 184549376
SEED = 0

class InstrumentedSketch(SweepSketch):

    def __init__(self, theta0, ctr):
        super().__init__(theta0)
        self.ctr = ctr
        self.seen = defaultdict(int)
        self.hit = defaultdict(int)
        self.owned = set()
        self.evicted = set()
        self.attack_keys = set()
        self.attack_seen = defaultdict(int)
        self.attack_hit = defaultdict(int)
        self.attack_evicted = set()

    def _up(self, level, key, r, rho, lvl, g, gf, ts, collector):
        i = level.idx(key)
        b = level.buckets[i]
        new_own = False
        if b is None:
            b = level.buckets[i] = Bucket(key, g)
            new_own = True
        elif b.key != key:
            if not (b.pkt < config.P_MIN and b.C < config.H_FP):
                if lvl == 1:
                    self.ctr['drop_l1'] += 1
                    self.seen[key] += 1
                    if key in self.attack_keys:
                        self.attack_seen[key] += 1
                return
            if lvl == 1:
                self.ctr['replace_l1'] += 1
                self.evicted.add(b.key)
                if b.key in self.attack_keys:
                    self.attack_evicted.add(b.key)
            b = level.buckets[i] = Bucket(key, g)
            new_own = True
        if lvl == 1:
            self.seen[key] += 1
            self.hit[key] += 1
            if new_own:
                self.owned.add(key)
            if key in self.attack_keys:
                self.attack_seen[key] += 1
                self.attack_hit[key] += 1
        a1, a2, _ = b.process(r, rho, g, self.llr)
        if a1:
            collector.add(Alert(lvl, key, b.n_new, b.C, b.pkt, gf, 'D1', ts))
        if a2:
            collector.add(Alert(lvl, key, b.n_new, b.C, b.pkt, gf, 'D2', ts))

def benign_pass(path):
    s, n = (set(), 0)
    first = last = None
    for _s, d, ts in iter_pcap(path, config.BENIGN_MAX, with_flow=False):
        n += 1
        s.add(d >> 8 << 8)
        if first is None:
            first = ts
        last = ts
    return (sorted(s), n, first, last)

def build_mapping(real_pfx, n_level):
    order = sorted(real_pfx, key=lambda p: pfx_hash(p, SEED))
    P = len(order)
    idx = {p: i for i, p in enumerate(order)}
    blocks = []
    for i in range(P):
        base = i * n_level // P
        end = (i + 1) * n_level // P
        blocks.append((base, max(1, end - base)))
    return (idx, blocks, order)

def benign_gen(path, idx, blocks, base=BENIGN_BASE):
    seq = [0] * len(idx)
    for _s, d, ts in iter_pcap(path, config.BENIGN_MAX, with_flow=False):
        i = idx[d >> 8 << 8]
        b, k = blocks[i]
        synth = b + seq[i] % k
        seq[i] += 1
        yield (_s, base | synth << 8 | d & 255, ts)

def attack_plan(files):
    keys = sorted({ip24(f.split('_')[0]) for f in files})
    kmap = {k: ATTACK_BASE | j << 16 for j, k in enumerate(keys)}
    plan = []
    for f in files:
        path = os.path.join(rc.ATTACK_DIR, f)
        first = last = None
        n = 0
        for _s, d, ts in iter_pcap(path, config.ATTACK_MAX, with_flow=False):
            n += 1
            if first is None:
                first = ts
            last = ts
        pfx = ip24(f.split('_')[0])
        plan.append(dict(file=f, path=path, first=first, last=last, n=n, key=kmap[pfx], pfx=pfx))
    return (plan, kmap)

def attack_gen(item, t_start):
    shift = t_start - item['first']
    for _s, d, ts in iter_pcap(item['path'], config.ATTACK_MAX, with_flow=False):
        yield (_s, item['key'] | d & 255, ts + shift)

def run_one(n_level, kb, idx, blocks, plan, kmap, bfirst, blast):
    ctr = {'replace_l1': 0, 'drop_l1': 0}
    sk = InstrumentedSketch(config.THETA0, ctr)
    total = kb * 1024 // 44
    n1 = total * 2 // 3
    sk.l1 = Level(n1, lambda d: d >> 8 << 8, 17)
    sk.l2 = Level(total - n1, lambda d: d >> 16 << 16, 34)
    sk.attack_keys = set(kmap.values())
    stats, cur = ({}, {})
    D = max(1e-09, blast - bfirst)
    streams = [benign_gen(BENIGN, idx, blocks)]
    for i, item in enumerate(plan):
        t_start = bfirst + (i + 1) * D / (len(plan) + 1)
        streams.append(attack_gen(item, t_start))
    t0 = time.time()
    npkt = 0
    for _s, d, ts in heapq.merge(*streams, key=lambda x: x[2]):
        feed(sk, stats, cur, _s, d, ts, DUMMY)
        npkt += 1
    flush(stats, cur)
    wall = time.time() - t0
    fl = h_flag(9.2)
    flagged = {k[1]: True for k, s in stats.items() if k[0] == 1 and fl(s)}
    gt_attack = set(kmap.values())
    gt_benign = {BENIGN_BASE | s << 8 for s in range(n_level)}
    tp, fp, fn, f1v = f1_of(flagged, gt_attack, gt_benign)
    seen_ben = {k: v for k, v in sk.seen.items() if k not in sk.attack_keys}
    hit_ben = sk.hit
    ratios = sorted((hit_ben.get(k, 0) / v for k, v in seen_ben.items() if v))
    mean_ratio = sum(ratios) / len(ratios) if ratios else 0.0
    overall = sum((hit_ben.get(k, 0) for k in seen_ben)) / max(1, sum(seen_ben.values()))
    pct = lambda q: ratios[min(len(ratios) - 1, int(q * len(ratios)))] if ratios else 0.0
    active = sk.owned - sk.attack_keys
    evicted_ben = sk.evicted - sk.attack_keys
    atk_seen = sum(sk.attack_seen.values())
    atk_hit = sum(sk.attack_hit.values())
    return dict(kb=kb, l1_buckets=sk.l1.nb, level=n_level, avg_prefixes_per_bucket=round(n_level / sk.l1.nb, 3), active_prefixes=len(sk.owned), active_benign_prefixes=len(active), n_pkts=npkt, n_benign_pkts=sum(seen_ben.values()), n_attack_pkts=atk_seen, n_replace_l1=ctr['replace_l1'], n_drop_l1=ctr['drop_l1'], replace_per_1k_pkts=round(1000.0 * ctr['replace_l1'] / max(1, npkt), 2), pct_active_evicted=round(100.0 * len(evicted_ben) / max(1, len(active)), 2), mean_hit_ratio=round(mean_ratio, 4), overall_hit_ratio=round(overall, 4), hit_p05=round(pct(0.05), 4), hit_p50=round(pct(0.5), 4), hit_p95=round(pct(0.95), 4), pct_prefixes_hit_lt_1=round(100.0 * sum((1 for r in ratios if r < 1.0)) / max(1, len(ratios)), 2), n_attack_prefixes=len(gt_attack), n_attack_evicted=len(sk.attack_evicted), attack_hit_ratio=round(atk_hit / max(1, atk_seen), 4), tp=tp, fp=fp, fn=fn, f1=round(f1v, 4), n_flagged=len(flagged), wall_s=round(wall, 1), pps=round(npkt / wall, 0))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--levels', default='1000,2000,5000,10000,20000')
    ap.add_argument('--budgets', default='512,1024')
    ap.add_argument('--tag', default='e5_scale')
    args = ap.parse_args()
    levels = [int(x) for x in args.levels.split(',')]
    budgets = [int(x) for x in args.budgets.split(',')]
    os.makedirs(OUT, exist_ok=True)
    os.makedirs(LOG, exist_ok=True)
    t_all = time.time()
    start = datetime.now().astimezone().isoformat(timespec='seconds')
    real_pfx, n_benign, bfirst, blast = benign_pass(BENIGN)
    files = attack_files()
    plan, kmap = attack_plan(files)
    print('E5 full: benign %d packets / %d distinct /24s / span %.0fs; attack %d files / %d packets / %d distinct /24s' % (n_benign, len(real_pfx), blast - bfirst, len(files), sum((p['n'] for p in plan)), len(kmap)), flush=True)
    rows = []
    for kb in budgets:
        for n_level in levels:
            idx, blocks, _order = build_mapping(real_pfx, n_level)
            r = run_one(n_level, kb, idx, blocks, plan, kmap, bfirst, blast)
            rows.append(r)
            print('E5 kb=%-4d N=%-5d buckets=%d (%.2f prefixes/bucket): replace=%d drop=%d active-prefix eviction=%.1f%% mean hit rate=%.3f F1=%.4f (tp%d fp%d fn%d) %.0fs' % (kb, n_level, r['l1_buckets'], r['avg_prefixes_per_bucket'], r['n_replace_l1'], r['n_drop_l1'], r['pct_active_evicted'], r['mean_hit_ratio'], r['f1'], r['tp'], r['fp'], r['fn'], r['wall_s']), flush=True)
    out = os.path.join(OUT, args.tag + '.csv')
    with open(out, 'w', newline='', encoding='utf-8') as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    rc.write_meta(out, experiment='e5_scale', command='python3 -u e5_scale.py --levels %s --budgets %s' % (args.levels, args.budgets), full_scale=True, sampling='none', seed=SEED, seed_note='mapping is deterministic (ordering by pfx_hash(., seed=0)); the code uses no RNG', workers=1, datasets=dict(benign=dict(file=os.path.basename(BENIGN), packets=n_benign, distinct_prefixes=len(real_pfx), span_s=round(blast - bfirst, 1)), attack=dict(files=len(files), packets=sum((p['n'] for p in plan)), distinct_prefixes=len(kmap))), design=dict(prefix_remap='real /24s are sorted by pfx_hash(., 0) and mapped to synthetic slots block=[i*N//P,(i+1)*N//P); streams are split per prefix round-robin when N>P and merged when N<=P; the packet count is unchanged', attack_placement='55 attack /24s mapped to 11.j.0.0/24 (distinct /16s), inserted concurrently into the benign timeline at uniform positions', per_prefix_rate_note='total volume is fixed, so the per-prefix rate is proportional to 1/N (CIC benign traffic is already thin); this is a memory-pressure experiment, not the 20k x 40 pps rate envelope', detection='production construction make_sketch(512/1024KB), h=9.2, entity-level /24 F1 (E1 definition)', probes='L1 bucket replacements and drops, per-prefix bucket hit rate, evicted attack prefixes'), start=start, end=datetime.now().astimezone().isoformat(timespec='seconds'), wall_s=round(time.time() - t_all, 1), log=rc.rel(os.path.join(LOG, 'e5_scale.log')), notes=['F1 definition differs from EXP1 (E5 inserts attacks concurrently; EXP1 concatenates them serially)', 'P_MIN=200 > 40pps x 4.29s = 172, so a bucket at the lowest rate of the deployment envelope never leaves the cold state and the cold-eviction guard never triggers (discussed in docs)'])
    print('\nwrote %s (%d rows) in %.0fs' % (rc.rel(out), len(rows), time.time() - t_all), flush=True)
if __name__ == '__main__':
    main()
