from __future__ import annotations
import argparse
import csv
import json
import math
import os
import random
import statistics
import sys
import time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import rev_common as rc
rc.add_impl_path()
from sweepsketch.hash import pfx_hash
from sweepsketch.sketch import _hll_r_rho
EXP = 'e9'
RES = rc.ensure(EXP)
LOG = os.path.join(rc.LOGS, EXP)
SEEDS = [0, 1, 2, 3, 4]
WINDOWS = 1000
S_VALUES = [4, 8, 12, 16, 24, 32]
STRUCTURES = ['fresh_uniform', 'persistent', 'bursty_fresh', 'gap8_return', 'heavy_tail']
MAPPINGS = ['production', 'injection']
BASE = 174325760
METHODS = {'thll': {'bits': 32 * 8, 'clear_rmw': 0, 'rmw_per_pkt': 1, 'kind': 'event_count', 'desc': 'T-HLL 32x8b {tag3, rho5}: event counter, cleared to zero'}, 'bitmap256_lazy': {'bits': 256, 'clear_rmw': 8, 'rmw_per_pkt': 1, 'kind': 'popcount', 'desc': '256-bit bitmap; the first packet of a window clears 255 bits (8x32b writes)'}, 'sliding_hll2': {'bits': 2 * 32 * 5, 'clear_rmw': 32, 'rmw_per_pkt': 1, 'kind': 'hll_estimate', 'desc': 'two-generation sliding HLL (32x5b x2); 32 registers of the current generation are cleared per window'}, 'hll_epoch': {'bits': 32 * 5 + 32 * 3, 'clear_rmw': 0, 'rmw_per_pkt': 2, 'kind': 'hll_estimate', 'desc': 'HLL 32x5b plus a 32x3b epoch array (2 RMW per packet, no explicit clearing)'}, 'hll_reset': {'bits': 32 * 5 + 3, 'clear_rmw': 32, 'rmw_per_pkt': 1, 'kind': 'hll_estimate', 'desc': 'HLL 32x5b plus a single epoch word, explicit reset of 32 registers'}}
METHOD_ORDER = ['thll', 'bitmap256_lazy', 'sliding_hll2', 'hll_epoch', 'hll_reset']
_RR = {}

def rr(host):
    v = _RR.get(host)
    if v is None:
        v = _hll_r_rho(host)
        _RR[host] = v
    return v

def alpha_m(m):
    return 0.7213 / (1.0 + 1.079 / m)

def hll_estimate(regs, active=None, m=32):
    if active is None:
        V = sum((1 for x in regs if x == 0))
        vals = regs
    else:
        V = 0
        vals = []
        for i, x in enumerate(regs):
            if not active[i] or x == 0:
                V += 1
            else:
                vals.append(x)
    if V > 0:
        return m * math.log(m / V)
    z = sum((2.0 ** (-x) for x in vals))
    return alpha_m(m) * m * m / z if z else 0.0

class Primitive:

    def __init__(self, method):
        self.method = method

    def start_window(self, w):
        return 0

    def touch(self, host, slot, r, rho, w):
        raise NotImplementedError

    def estimate(self, exact):
        raise NotImplementedError

class THLL(Primitive):

    def __init__(self):
        super().__init__('thll')
        self.hll = [0] * 32
        self.n = 0

    def start_window(self, w):
        self.n = 0
        return 0

    def touch(self, host, slot, r, rho, w):
        tag = w & 7
        cell = self.hll[r]
        tag_old = cell >> 5
        rho_old = cell & 31
        if tag_old != tag:
            self.hll[r] = tag << 5 | rho
            self.n += 1
            return 1
        if rho > rho_old:
            self.hll[r] = tag << 5 | rho
            self.n += 1
            return 1
        return 0

    def estimate(self, exact):
        return float(self.n)

class Bitmap256(Primitive):

    def __init__(self):
        super().__init__('bitmap256_lazy')
        self.bits = 0

    def start_window(self, w):
        self.bits = 0
        return METHODS['bitmap256_lazy']['clear_rmw']

    def touch(self, host, slot, r, rho, w):
        b = pfx_hash(host, 85) & 255 if self.slot_from_hash else slot & 255
        m = 1 << b
        new = 0 if self.bits & m else 1
        self.bits |= m
        return new
    slot_from_hash = True

    def estimate(self, exact):
        return float(bin(self.bits).count('1'))

class SlidingHLL2(Primitive):

    def __init__(self):
        super().__init__('sliding_hll2')
        self.gens = [[0] * 32, [0] * 32]
        self.cur = 0

    def start_window(self, w):
        self.cur = w & 1
        self.gens[self.cur] = [0] * 32
        return METHODS['sliding_hll2']['clear_rmw']

    def touch(self, host, slot, r, rho, w):
        g = self.gens[self.cur]
        if rho > g[r]:
            g[r] = rho
            return 1
        return 0

    def estimate(self, exact):
        return hll_estimate(self.gens[self.cur])

class HLLEpoch(Primitive):

    def __init__(self):
        super().__init__('hll_epoch')
        self.rho = [0] * 32
        self.ep = [-1] * 32

    def start_window(self, w):
        return 0

    def touch(self, host, slot, r, rho, w):
        tag = w & 7
        if self.ep[r] != tag:
            self.ep[r] = tag
            self.rho[r] = rho
            return 1
        if rho > self.rho[r]:
            self.rho[r] = rho
            return 1
        return 0

    def estimate(self, exact):
        tag = self.cur_tag
        active = [self.ep[i] == tag for i in range(32)]
        return hll_estimate(self.rho, active)

    def start_window(self, w):
        self.cur_tag = w & 7
        return 0

class HLLReset(Primitive):

    def __init__(self):
        super().__init__('hll_reset')
        self.rho = [0] * 32

    def start_window(self, w):
        self.rho = [0] * 32
        return METHODS['hll_reset']['clear_rmw']

    def touch(self, host, slot, r, rho, w):
        if rho > self.rho[r]:
            self.rho[r] = rho
            return 1
        return 0

    def estimate(self, exact):
        return hll_estimate(self.rho)
PRIM_CLS = {'thll': THLL, 'bitmap256_lazy': Bitmap256, 'sliding_hll2': SlidingHLL2, 'hll_epoch': HLLEpoch, 'hll_reset': HLLReset}

class HostGen:

    def __init__(self, structure, S, seed):
        self.structure, self.S, self.seed = (structure, S, seed)
        self.rng = random.Random(seed * 1000003 + S * 7919 + hash(structure) % 1000)
        self.seq = 0
        self.hist = []
        self.persistent = [BASE + 1 + i for i in range(S)]

    def _fresh(self, n):
        out = []
        for _ in range(n):
            self.seq += 1
            out.append(BASE + self.seq)
        return out

    def window(self, w):
        S = self.S
        if self.structure == 'persistent':
            hosts = list(self.persistent)
        elif self.structure == 'gap8_return':
            n_rec = max(1, S // 4)
            rec = []
            if len(self.hist) >= 8:
                rec = list(self.hist[-8])[:n_rec]
            fresh = self._fresh(S - len(rec))
            hosts = rec + fresh
        else:
            hosts = self._fresh(S)
        self.hist.append(list(hosts))
        if len(self.hist) > 8:
            self.hist.pop(0)
        if self.structure == 'bursty_fresh':
            self.rng.shuffle(hosts)
        elif self.structure == 'heavy_tail':
            self.rng.shuffle(hosts)
        return hosts

def map_hosts(hosts, mapping):
    if mapping == 'injection':
        order = sorted(range(len(hosts)), key=lambda i: hosts[i])
        slot_of = {i: j for j, i in enumerate(order)}
        out = []
        for i, h in enumerate(hosts):
            slot = slot_of[i] % 32
            rho = rr(h)[1] + 1
            out.append((h, slot, slot, rho))
        return out
    out = []
    for h in hosts:
        r, rho = rr(h)
        slot = pfx_hash(h, 85) & 255
        out.append((h, slot, r, rho + 1))
    return out

def run_one(method, mapping, structure, S, seed, windows=WINDOWS):
    gen = HostGen(structure, S, seed)
    prim = PRIM_CLS[method]()
    lam = 4 * S
    errs = []
    wrap_misses = 0
    last_seen = {}
    events_total = 0
    exact_total = 0
    for w in range(1, windows + 1):
        hosts = gen.window(w)
        prim.start_window(w)
        ev = 0
        for h, slot, r, rho in map_hosts(hosts, mapping):
            before = None
            if method in ('thll', 'hll_epoch'):
                tag = w & 7
                if method == 'thll':
                    cell = prim.hll[r]
                    to, ro = (cell >> 5, cell & 31)
                else:
                    to = prim.ep[r] if prim.ep[r] >= 0 else None
                    ro = prim.rho[r]
                    tag_ok = to == tag
                if method == 'thll':
                    is_wrap = to == tag and rho <= ro
                else:
                    is_wrap = to == tag and rho <= ro
                e = prim.touch(h, slot, r, rho, w)
                if is_wrap and last_seen.get(h) == w - 8:
                    wrap_misses += 1
            else:
                e = prim.touch(h, slot, r, rho, w)
            ev += e
            last_seen[h] = w
        exact = len(set(hosts))
        est = prim.estimate(exact)
        errs.append(est - exact)
        events_total += ev
        exact_total += exact
    n = len(errs)
    abs_errs = sorted((abs(e) for e in errs))
    cost = METHODS[method]
    row = {'method': method, 'estimate_kind': cost['kind'], 'mapping': mapping, 'structure': structure, 'S': S, 'seed': seed, 'windows': n, 'lambda_per_window': lam, 'exact_mean': round(exact_total / n, 3), 'estimate_mean': round(statistics.mean((x + exact_total / n for x in [0])) if False else statistics.mean([errs[i] + exact_total / n for i in range(n)]), 3), 'mean_signed_error': round(statistics.mean(errs), 3), 'mean_abs_error': round(statistics.mean((abs(e) for e in errs)), 3), 'rmse': round(math.sqrt(statistics.mean((e * e for e in errs))), 3), 'p95_abs_error': round(abs_errs[min(n - 1, int(0.95 * n))], 3), 'rel_bias_pct': round(statistics.mean(errs) / (exact_total / n) * 100, 3), 'wrap_misses': wrap_misses, 'wrap_error_rate': round(wrap_misses / n, 5), 'clear_rmw_per_window': cost['clear_rmw'], 'rmw_per_packet': cost['rmw_per_pkt'], 'total_rmw_per_window': cost['clear_rmw'] + lam * cost['rmw_per_pkt'], 'register_bits': cost['bits']}
    return row

def run_all(seeds=SEEDS, windows=WINDOWS):
    rows = []
    t0 = time.time()
    total = len(METHOD_ORDER) * len(MAPPINGS) * len(STRUCTURES) * len(S_VALUES) * len(seeds)
    k = 0
    for method in METHOD_ORDER:
        for mapping in MAPPINGS:
            for structure in STRUCTURES:
                for S in S_VALUES:
                    for seed in seeds:
                        rows.append(run_one(method, mapping, structure, S, seed, windows))
                        k += 1
        print('[E9] %s done (%d/%d, %.0fs)' % (method, k, total, time.time() - t0), flush=True)
    return rows

def aggregate(rows):
    keys = ['method', 'estimate_kind', 'mapping', 'structure', 'S']
    groups = {}
    for r in rows:
        groups.setdefault(tuple((r[k] for k in keys)), []).append(r)
    out = []
    for key, rs in groups.items():
        rec = dict(zip(keys, key))
        rec['seeds'] = len(rs)
        rec['windows_per_seed'] = rs[0]['windows']
        for f in ('mean_signed_error', 'mean_abs_error', 'rmse', 'p95_abs_error', 'rel_bias_pct', 'wrap_error_rate', 'clear_rmw_per_window', 'rmw_per_packet', 'total_rmw_per_window', 'register_bits', 'lambda_per_window'):
            rec[f] = round(statistics.median([r[f] for r in rs]), 5)
        rec['wrap_misses_med'] = statistics.median([r['wrap_misses'] for r in rs])
        out.append(rec)
    out.sort(key=lambda r: (METHOD_ORDER.index(r['method']), r['mapping'], STRUCTURES.index(r['structure']), r['S']))
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--windows', type=int, default=WINDOWS)
    ap.add_argument('--seeds', type=int, default=len(SEEDS))
    args = ap.parse_args()
    seeds = SEEDS[:args.seeds]
    t0 = time.time()
    rows = run_all(seeds, args.windows)
    p = os.path.join(RES, 'e9_thll.csv')
    rc.write_csv(p, rows)
    rc.write_meta(p, experiment='E9-thll-microbench', seeds=seeds, windows_per_seed=args.windows, methods=METHODS, structures=STRUCTURES, mappings=MAPPINGS, S=S_VALUES, lambda_model='lambda = 4*S packets/window', metrics=['per-window estimate vs exact distinct', 'clear RMW per window', 'RMW per packet', 'total RMW per window', 'register bits', '8-window tag wrap error rate'], note='the injection branch only checks the exactness claim of T-HLL; the randomization assumption of HLL estimators does not hold under injection, so cross-method comparisons use the production rows', reference='T-HLL follows the HLL semantics of sweepsketch/bucket.py', workers=os.environ.get('SWEEPSKETCH_WORKERS', '4'), wall_s=round(time.time() - t0, 1))
    print('[E9] wrote', p, len(rows), 'rows', flush=True)
    agg = aggregate(rows)
    p2 = os.path.join(RES, 'e9_summary.csv')
    rc.write_csv(p2, agg)
    rc.write_meta(p2, experiment='E9-thll-summary', seeds=seeds, windows_per_seed=args.windows, aggregation='median across seeds', wall_s=round(time.time() - t0, 1))
    print('[E9] wrote', p2, len(agg), 'rows', flush=True)
    print('[E9] production-basis quick view (median over seeds):', flush=True)
    for r in agg:
        if r['mapping'] == 'production' and r['structure'] in ('fresh_uniform', 'gap8_return') and (r['S'] in (8, 16, 32)):
            print('  %-15s %-12s S=%-2d  est_err=%+.2f  abs=%.2f  wrap=%.4f  clear=%d  rmw/pkt=%d  total_rmw/win=%d  bits=%d' % (r['method'], r['structure'], r['S'], r['mean_signed_error'], r['mean_abs_error'], r['wrap_error_rate'], r['clear_rmw_per_window'], r['rmw_per_packet'], int(r['total_rmw_per_window']), r['register_bits']), flush=True)
    print('[E9] done %.0fs' % (time.time() - t0), flush=True)
    return 0
if __name__ == '__main__':
    sys.exit(main())
