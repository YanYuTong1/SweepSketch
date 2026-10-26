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
from collections import Counter
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import rev_common as rc
rc.add_impl_path()
from sweepsketch import config as sscfg
from sweepsketch.llr import make_llr_table
from sweepsketch.sketch import _hll_r_rho
EXP = 'e2'
RES = rc.ensure(EXP)
LOG = os.path.join(rc.LOGS, EXP)
SEEDS = [0, 1, 2, 3, 4]
EPOCH_S = (1 << 32) / 1000000000.0
P_MIN = sscfg.P_MIN
K_FLOOD = sscfg.K_FLOOD
K_ALARM = sscfg.K_ALARM
K_ALARM_QUIET = sscfg.K_ALARM_QUIET
N_EWMA_QUIET = sscfg.N_EWMA_QUIET
H_FP = sscfg.H_FP
D2_MULT = sscfg.D2_MULT
EWMA_SHIFT = sscfg.EWMA_SHIFT
C_MAX = sscfg.C_MAX
WIN_MASK = sscfg.WIN_MASK
RHO_BITS = sscfg.RHO_BITS
USE_GATE = sscfg.USE_GATE
USE_D1 = sscfg.USE_D1
USE_D2 = sscfg.USE_D2
LLR = make_llr_table(sscfg.THETA0)
NEW, REP = (LLR['new'], LLR['rep'])
assert LLR == {'new': 38, 'rep': -26}, LLR
VICTIM_HOSTS = 254
BASE16 = 174325760
COV_MAX = int(round(0.9 * VICTIM_HOSTS))
X_LIST = [25, 50, 75, 90]
THRESH = {x: int(math.ceil(x / 100.0 * VICTIM_HOSTS)) for x in X_LIST}
BG_PKTS = 20
S_VALUES = [4, 5, 6, 8, 10, 11, 12, 13, 14, 16, 20, 24, 32]
LAM_VALUES = [8, 16, 32, 64, 128, 192, 256, 512, 1024]
ORDERS = ['rotation', 'burst2', 'burst3', 'burst5', 'split7030']
TARGETS = ['single', 'adj2', 'rot16', 'switch1', 'switch2']
RATES = [40, 100, 400]
_RR = {}

def rr(dst):
    v = _RR.get(dst)
    if v is None:
        v = _hll_r_rho(dst)
        _RR[dst] = v
    return v

class FastBucket:
    __slots__ = ('win', 'epoch', 'n_new', 'n_ewma', 'C', 'pkt', 'pkt_ewma', 'hll', 'd2_held', 'trace', 'miti', 'd2_hist')

    def __init__(self, epoch=1, diag=False, miti=None):
        self.win = 1
        self.epoch = epoch
        self.n_new = self.n_ewma = self.C = 0
        self.pkt = self.pkt_ewma = 0
        self.d2_held = False
        self.hll = [0] * sscfg.HLL_M
        self.trace = [] if diag else None
        self.miti = miti or {'mode': 'none'}
        self.d2_hist = []

    def process_window(self, touches, n_pkts, epoch):
        if self.epoch != epoch:
            gate_hold = self.pkt >= max(P_MIN, D2_MULT * self.pkt_ewma) and self.n_new >= max(K_FLOOD, 2 * self.n_ewma if USE_GATE else 0)
            if self.miti.get('mode') == 'd2hold':
                self.d2_hist.append(1 if gate_hold else 0)
                W = int(self.miti.get('W', 2))
                self.d2_held = any(self.d2_hist[-W:])
            else:
                self.d2_held = gate_hold
            self.n_ewma += self.n_new - self.n_ewma >> EWMA_SHIFT
            self.pkt_ewma += self.pkt - self.pkt_ewma >> EWMA_SHIFT
            self.n_new = self.pkt = self.C = 0
            self.win = self.win + 1 & WIN_MASK
            self.epoch = epoch
        gate = K_ALARM
        if USE_GATE:
            q = 2 * self.n_ewma
            if q > gate:
                gate = q
            if self.n_ewma < N_EWMA_QUIET and K_ALARM_QUIET > gate:
                gate = K_ALARM_QUIET
        a1_pos = None
        gate_pos = None
        fgate = max(K_FLOOD, 2 * self.n_ewma if USE_GATE else 0)
        fgate_pos = None
        prev = 0
        for pos, r, rho in touches:
            gap = pos - prev - 1
            if gap > 0:
                self.C += REP * gap
                if self.C < 0:
                    self.C = 0
            prev = pos
            cell = self.hll[r]
            tag_old = cell >> RHO_BITS
            rho_old = cell & (1 << RHO_BITS) - 1
            if tag_old != self.win:
                event = True
                self.hll[r] = self.win << RHO_BITS | rho
            elif rho > rho_old:
                event = True
                self.hll[r] = self.win << RHO_BITS | rho
            else:
                event = False
            if event:
                self.C += NEW
                if self.C > C_MAX:
                    self.C = C_MAX
                if self.n_new < 255:
                    self.n_new += 1
            else:
                self.C += REP
                if self.C < 0:
                    self.C = 0
            self.pkt += 1
            if gate_pos is None and self.n_new >= gate:
                gate_pos = pos
            if fgate_pos is None and self.n_new >= fgate:
                fgate_pos = pos
            if USE_D1 and a1_pos is None and (self.n_new >= gate) and (self.C >= H_FP or self.miti.get('mode') == 'nnew_only'):
                a1_pos = pos
        tail = n_pkts - prev
        if tail > 0:
            self.C += REP * tail
            if self.C < 0:
                self.C = 0
        self.pkt = n_pkts
        a2_pos = None
        if USE_D2 and self.pkt >= P_MIN and (self.pkt >= D2_MULT * self.pkt_ewma) and (self.n_new >= max(K_FLOOD, 2 * self.n_ewma if USE_GATE else 0)) and self.d2_held:
            need_pkt = max(P_MIN, D2_MULT * self.pkt_ewma)
            a2_pos = max(int(need_pkt), fgate_pos or 1)
            if a2_pos > n_pkts:
                a2_pos = n_pkts
        if self.trace is not None:
            self.trace.append((epoch, self.n_new, self.C, self.pkt, self.win, self.n_ewma, self.pkt_ewma, int(self.d2_held)))
        return (a1_pos is not None, a2_pos is not None, a1_pos, a2_pos)

def v_main(V):
    return (V - 1) // 10 * 7 + min((V - 1) % 10 + 1, 7) if V > 0 else 0

def split_main_hosts(s_eff):
    if s_eff >= 2:
        m = int(round(s_eff * 0.7))
        return max(1, min(s_eff - 1, m))
    return s_eff

def n_hosts_cap(ordering, S, V):
    if ordering == 'rotation':
        return min(S, V)
    if ordering.startswith('burst'):
        k = int(ordering[5:])
        return min(S, (V + k - 1) // k)
    if ordering == 'split7030':
        m = split_main_hosts(S)
        a = S - m
        vm = v_main(V)
        return min(m, vm) + max(0, min(a, V - vm))
    raise ValueError(ordering)

def target_pfx(target, w):
    if target == 'single':
        return BASE16 | 256
    if target == 'adj2':
        return BASE16 | (256 if w % 2 == 1 else 512)
    if target == 'rot16':
        return BASE16 | 1 + (w - 1) % 4 << 8
    if target == 'switch1':
        return BASE16 + (w - 1 << 16) + 256
    if target == 'switch2':
        return BASE16 + ((w - 1) // 2 << 16) + 256
    raise ValueError(target)

def adj_pfx_of(pfx, target, w):
    if target == 'single':
        return BASE16 | 512
    if target == 'adj2':
        return BASE16 | 512 if pfx & 65280 == 256 else BASE16 | 256
    if target == 'rot16':
        idx = pfx >> 8 & 255
        return BASE16 | idx % 4 + 1 << 8
    return pfx & 4294901760 | 512

def make_plan(pol, cov_max=COV_MAX, max_windows=220):
    counters = {}
    plan = []
    touched = 0
    w = 0
    while touched < cov_max and w < max_windows:
        w += 1
        need = cov_max - touched
        s_eff = min(pol.S, need)
        pfx = target_pfx(pol.target, w)
        if pol.ordering == 'split7030' and s_eff >= 2:
            apfx = adj_pfx_of(pfx, pol.target, w)
            m_alloc = split_main_hosts(s_eff)
            a_alloc = s_eff - m_alloc
            vm = v_main(pol.V)
            va = pol.V - vm
            nm = min(m_alloc, vm, VICTIM_HOSTS - counters.get(pfx, 0))
            na = min(a_alloc, va, VICTIM_HOSTS - counters.get(apfx, 0))
            if nm <= 0:
                nm = 0
            if na <= 0:
                na = 0
            entries = []
            if nm > 0:
                c = counters.get(pfx, 0)
                hosts = [pfx | c + i + 1 for i in range(nm)]
                counters[pfx] = c + nm
                entries.append({'pfx': pfx, 'hosts': hosts, 'npkts': vm, 'role': 'main'})
            if na > 0:
                c = counters.get(apfx, 0)
                hosts = [apfx | c + i + 1 for i in range(na)]
                counters[apfx] = c + na
                entries.append({'pfx': apfx, 'hosts': hosts, 'npkts': va, 'role': 'adj'})
        else:
            cap = n_hosts_cap(pol.ordering, s_eff, pol.V)
            n = min(cap, VICTIM_HOSTS - counters.get(pfx, 0))
            if n <= 0:
                break
            c = counters.get(pfx, 0)
            hosts = [pfx | c + i + 1 for i in range(n)]
            counters[pfx] = c + n
            entries = [{'pfx': pfx, 'hosts': hosts, 'npkts': pol.V, 'role': 'main'}]
        gained = sum((len(e['hosts']) for e in entries))
        if gained <= 0:
            break
        touched += gained
        max24 = max(counters.values()) if counters else 0
        plan.append({'w': w, 'attacks': entries, 'cum_cov': touched, 'max24': max24})
    return plan

def slot_positions(ordering, n_hosts, V):
    if ordering == 'rotation':
        return [j + 1 for j in range(n_hosts)]
    if ordering.startswith('burst'):
        k = int(ordering[5:])
        return [j * k + 1 for j in range(n_hosts)]
    if ordering == 'split7030':
        return [j + 1 for j in range(n_hosts)]
    raise ValueError(ordering)

def bg_pe(nb):
    pe = [0]
    v = 0
    for _ in range(400):
        v = v + (BG_PKTS * nb - v >> EWMA_SHIFT)
        pe.append(v)
    return pe
_PE_CACHE = {}

def make_bg_bucket(k, bg_hosts, diag=False):
    nb = len(bg_hosts)
    b = FastBucket(epoch=k)
    b.win = k
    hll = {}
    n_new = 0
    for r, rho in bg_hosts:
        if r not in hll:
            n_new += 1
            hll[r] = rho
        elif rho > hll[r]:
            n_new += 1
            hll[r] = rho
    for r, rho in hll.items():
        b.hll[r] = k << RHO_BITS | rho
    b.n_new = n_new
    b.n_ewma = 0
    b.C = 0
    b.pkt = BG_PKTS * nb
    pe = _PE_CACHE.get(nb)
    if pe is None:
        pe = bg_pe(nb)
        _PE_CACHE[nb] = pe
    b.pkt_ewma = pe[max(0, k - 1)]
    b.d2_held = False
    if diag:
        b.trace = [(k, b.n_new, b.C, b.pkt, b.win, b.n_ewma, b.pkt_ewma, 0)]
    return b

class Policy:
    __slots__ = ('S', 'lam', 'ordering', 'target', 'rate', 'V')

    def __init__(self, S, lam, ordering, target, rate):
        self.S, self.lam, self.ordering, self.target, self.rate = (S, lam, ordering, target, rate)
        self.V = min(lam, int(rate * EPOCH_S))

    def key(self):
        return (self.S, self.lam, self.ordering, self.target, self.rate)

    def as_dict(self):
        return {'S': self.S, 'lam': self.lam, 'ordering': self.ordering, 'target': self.target, 'rate': self.rate, 'V': self.V}

def simulate(pol, pid, seed, plan, bg=True, diag=False, miti=None):
    persistent = pol.target in ('single', 'adj2', 'rot16')
    planned = sorted({e['pfx'] for wnd in plan for e in wnd['attacks']})
    l1, l2 = ({}, {})
    alarms = []
    x16_hist = []
    miti = miti or {'mode': 'none'}
    rseed = pid * 2654435761 + seed * 7919 & 4294967295
    for wnd in plan:
        w = wnd['w']
        rng = random.Random(rseed ^ w * 2246822519 & 4294967295)
        attack = {}
        for e in wnd['attacks']:
            hl = list(e['hosts'])
            rng.shuffle(hl)
            attack[e['pfx']] = {'hosts': hl, 'npkts': e['npkts'], 'role': e['role']}
        if not bg:
            bgp = []
        elif persistent:
            bgp = planned
        else:
            bgp = sorted(attack)
        for pfx in sorted(set(bgp) | set(attack)):
            nbg = 1 if pfx in bgp else 0
            touches = []
            npkts = nbg * BG_PKTS
            if nbg:
                r, rho = rr(pfx | 255)
                touches.append((1, r, rho))
            if pfx in attack:
                at = attack[pfx]
                hl, npk = (at['hosts'], at['npkts'])
                pos = slot_positions(pol.ordering, len(hl), npk)
                for j, h in enumerate(hl):
                    r, rho = rr(h)
                    touches.append((npkts + pos[j], r, rho))
                npkts += npk
            touches.sort(key=lambda t: t[0])
            b = l1.get(pfx)
            if b is None:
                if bg and (not persistent) and (w > 1):
                    b = make_bg_bucket(w - 1, [rr(pfx | 255)], diag=diag)
                else:
                    b = FastBucket(epoch=w, diag=diag, miti=miti)
                l1[pfx] = b
            a1, a2, p1, p2 = b.process_window(touches, npkts, w)
            if a1:
                alarms.append((w, p1, 'D1', 1, pfx, npkts))
            if a2:
                alarms.append((w, p2, 'D2', 1, pfx, npkts))
        groups = {}
        for pfx in sorted(set(bgp) | set(attack)):
            groups.setdefault(pfx >> 16 << 16, []).append(pfx)
        for key16, pfxs in groups.items():
            bg_here = [p for p in pfxs if p in bgp]
            B = BG_PKTS * len(bg_here)
            touches = []
            for i, p in enumerate(bg_here):
                r, rho = rr(p | 255)
                touches.append((BG_PKTS * i + 1, r, rho))
            atts = [(p, attack[p]) for p in pfxs if p in attack]
            npkts = B + sum((at['npkts'] for _, at in atts))
            if len(atts) == 2 and pol.ordering == 'split7030':
                main = [at for _, at in atts if at['role'] == 'main']
                adj = [at for _, at in atts if at['role'] == 'adj']
                assert len(main) == 1 and len(adj) == 1, atts
                for j, h in enumerate(main[0]['hosts']):
                    pos = j // 7 * 10 + 1 + j % 7
                    r, rho = rr(h)
                    touches.append((B + pos, r, rho))
                for j, h in enumerate(adj[0]['hosts']):
                    pos = j // 3 * 10 + 8 + j % 3
                    r, rho = rr(h)
                    touches.append((B + pos, r, rho))
            elif len(atts) == 1:
                at = atts[0][1]
                pos = slot_positions(pol.ordering, len(at['hosts']), at['npkts'])
                for j, h in enumerate(at['hosts']):
                    r, rho = rr(h)
                    touches.append((B + pos[j], r, rho))
            else:
                raise RuntimeError('unsupported attack set: %r' % [p for p, _ in atts])
            touches.sort(key=lambda t: t[0])
            b = l2.get(key16)
            if b is None:
                if bg and (not persistent) and (w > 1):
                    b = make_bg_bucket(w - 1, [rr(p | 255) for p in bg_here], diag=diag)
                else:
                    b = FastBucket(epoch=w, diag=diag, miti=miti)
                l2[key16] = b
            a1, a2, p1, p2 = b.process_window(touches, npkts, w)
            if a1:
                alarms.append((w, p1, 'D1', 2, key16, npkts))
            if a2:
                alarms.append((w, p2, 'D2', 2, key16, npkts))
        if miti.get('mode') == 'x16':
            hit16 = {k16 for k16, b in l2.items() if b.epoch == w and b.n_new >= K_ALARM_QUIET}
            x16_hist.append(hit16)
            W = int(miti.get('W', 4))
            K = int(miti.get('K', 2))
            union = set()
            for s_ in x16_hist[-W:]:
                union |= s_
            if len(union) >= K:
                alarms.append((w, 10 ** 6, 'X16', 2, 0, 1))
    return {'alarms': alarms, 'cum_cov': [e['cum_cov'] for e in plan], 'l1': l1, 'l2': l2}

def checkpoints(plan):
    cum = [e['cum_cov'] for e in plan]
    max24 = [e['max24'] for e in plan]
    cps = {}
    for X in X_LIST:
        th = THRESH[X]
        cps[X, 'union'] = next((i + 1 for i, c in enumerate(cum) if c >= th), None)
        cps[X, 'single24'] = next((i + 1 for i, c in enumerate(max24) if c >= th), None)
    return cps

def eval_at(res, plan, wX, basis):
    if wX is None:
        return {'feasible': False}
    entry = plan[wX - 1]
    hosts = entry['cum_cov'] if basis == 'union' else entry['max24']
    out = {'feasible': True, 'windows': wX, 'hosts': hosts, 'coverage_pct': round(hosts / VICTIM_HOSTS * 100, 2)}
    al = [a for a in res['alarms'] if a[0] <= wX]
    if al:
        fw, fp, reason, lvl, key, npk = min(al, key=lambda a: (a[0], a[1]))
        frac = (fp - 1) / npk if npk else 0.0
        out.update({'detected': 1, 'first_w': fw, 'first_pos': fp, 'first_ms': round((fw - 1 + frac) * EPOCH_S * 1000, 1), 'first_reason': 'L%d-%s' % (lvl, reason)})
    else:
        out.update({'detected': 0, 'first_w': None, 'first_pos': None, 'first_ms': None, 'first_reason': ''})
    return out

def eval_policy(pol, pid, seeds, bg=True, diag=False, miti=None):
    plan = make_plan(pol)
    cps = checkpoints(plan)
    acc = {k: {'det': [], 'first_w': [], 'first_ms': [], 'reasons': []} for k in cps}
    for seed in seeds:
        res = simulate(pol, pid, seed, plan, bg=bg, diag=diag, miti=miti)
        for (X, basis), wX in cps.items():
            s = eval_at(res, plan, wX, basis)
            if not s.get('feasible'):
                continue
            a = acc[X, basis]
            a['det'].append(s['detected'])
            if s['detected']:
                a['first_w'].append(s['first_w'])
                a['first_ms'].append(s['first_ms'])
                a['reasons'].append(s['first_reason'])
    rows = {}
    for (X, basis), wX in cps.items():
        if wX is None:
            rows[X, basis] = {'feasible': False}
            continue
        a = acc[X, basis]
        det = a['det']
        n = len(det)
        hosts = plan[wX - 1]['cum_cov'] if basis == 'union' else plan[wX - 1]['max24']
        sent = wX * pol.V
        rows[X, basis] = {'feasible': True, 'windows': wX, 'duration_s': round(wX * EPOCH_S, 2), 'hosts': hosts, 'coverage_pct': round(hosts / VICTIM_HOSTS * 100, 2), 'packets_sent': sent, 'actual_pps': round(pol.V / EPOCH_S, 2), 'per_host_packets': round(sent / hosts, 2) if hosts else 0.0, 'detect_rate': round(sum(det) / n, 4) if n else None, 'detected_seeds': ';'.join(map(str, det)), 'first_w_med': statistics.median(a['first_w']) if a['first_w'] else None, 'first_ms_med': statistics.median(a['first_ms']) if a['first_ms'] else None, 'first_reason': Counter(a['reasons']).most_common(1)[0][0] if a['reasons'] else ''}
    return (rows, plan)

def objective(rows, X, basis):
    r = rows.get((X, basis))
    if not r or not r.get('feasible'):
        return (9.0, 10 ** 9, 0.0)
    return (r['detect_rate'], r['windows'], -r['packets_sent'])

def base_policy_rows(pol, pid, kind, seeds, bg=True):
    rows, plan = eval_policy(pol, pid, seeds, bg=bg)
    out = []
    for X in X_LIST:
        r = rows[X]
        if not r.get('feasible'):
            continue
        row = {'strategy_id': 'p%05d' % pid, 'kind': kind, **pol.as_dict(), 'X': X, 'bg': int(bg), **r}
        out.append(row)
    return (out, rows)

def run_grid(seeds=SEEDS):
    configs = []
    seen = set()

    def add(pol, kind):
        if pol.key() in seen:
            return
        seen.add(pol.key())
        configs.append((pol, kind))
    for S in S_VALUES:
        for lam in LAM_VALUES:
            for order in ORDERS:
                for target in TARGETS:
                    for rate in RATES:
                        add(Policy(S, lam, order, target, rate), 'grid')
    for S in range(4, 33):
        for order in ORDERS:
            for rate in (40, 400):
                for lam in (192, 1024):
                    add(Policy(S, lam, order, 'single', rate), 'floor_probe')
                    add(Policy(S, lam, order, 'rot16', rate), 'floor_probe')
    rows = []
    cache = {}
    t0 = time.time()
    for i, (pol, kind) in enumerate(configs):
        pid = i
        r, _ = eval_policy(pol, pid, seeds)
        cache[pol.key()] = r
        for X in X_LIST:
            for basis in ('union', 'single24'):
                rr_ = r[X, basis]
                if not rr_.get('feasible'):
                    continue
                rows.append({'strategy_id': 'p%05d' % pid, 'kind': kind, **pol.as_dict(), 'X': X, 'damage_basis': basis, 'bg': 1, **rr_})
        if (i + 1) % 500 == 0:
            print('[E2] grid %d/%d  %.0fs' % (i + 1, len(configs), time.time() - t0), flush=True)
    return (configs, cache, rows)

def neighbors(pol):
    out = []
    for dS in (-2, -1, 1, 2):
        if 4 <= pol.S + dS <= 32:
            out.append(Policy(pol.S + dS, pol.lam, pol.ordering, pol.target, pol.rate))
    idx = LAM_VALUES.index(pol.lam) if pol.lam in LAM_VALUES else None
    idxs = []
    if idx is not None:
        idxs = [idx - 1, idx + 1]
    for j in idxs:
        if 0 <= j < len(LAM_VALUES):
            out.append(Policy(pol.S, LAM_VALUES[j], pol.ordering, pol.target, pol.rate))
    for lam in (max(8, pol.lam // 2), min(1024, pol.lam * 2)):
        if lam != pol.lam:
            out.append(Policy(pol.S, lam, pol.ordering, pol.target, pol.rate))
    for o in ORDERS:
        if o != pol.ordering:
            out.append(Policy(pol.S, pol.lam, o, pol.target, pol.rate))
    for t in TARGETS:
        if t != pol.target:
            out.append(Policy(pol.S, pol.lam, pol.ordering, t, pol.rate))
    for rt in RATES:
        if rt != pol.rate:
            out.append(Policy(pol.S, pol.lam, pol.ordering, pol.target, rt))
    return out

def greedy(ref, X, basis, cache, seeds, pid_start, max_iter=40):
    cur = ref
    cur_rows = cache[cur.key()]
    trace = []
    for it in range(max_iter):
        best = cur
        best_obj = objective(cur_rows, X, basis)
        best_rows = cur_rows
        for nb in neighbors(cur):
            if nb.key() in cache:
                r = cache[nb.key()]
            else:
                pid = pid_start + len(cache)
                r, _ = eval_policy(nb, pid, seeds)
                cache[nb.key()] = r
            ob = objective(r, X, basis)
            if ob < best_obj:
                best_obj, best, best_rows = (ob, nb, r)
        if best is cur:
            trace.append({'X': X, 'damage_basis': basis, 'step': it, 'moved': 0, **cur.as_dict(), 'objective': list(best_obj)})
            break
        trace.append({'X': X, 'damage_basis': basis, 'step': it, 'moved': 1, **best.as_dict(), 'objective': list(best_obj)})
        cur, cur_rows = (best, best_rows)
    return (cur, cur_rows, trace)

def materialize(pol, pid, seed, plan, bg=True):
    persistent = pol.target in ('single', 'adj2', 'rot16')
    planned = sorted({e['pfx'] for wnd in plan for e in wnd['attacks']})
    streams = {}
    rseed = pid * 2654435761 + seed * 7919 & 4294967295
    for wnd in plan:
        w = wnd['w']
        rng = random.Random(rseed ^ w * 2246822519 & 4294967295)
        attack = {}
        for e in wnd['attacks']:
            hl = list(e['hosts'])
            rng.shuffle(hl)
            attack[e['pfx']] = {'hosts': hl, 'npkts': e['npkts'], 'role': e['role']}
        bgp = planned if bg else []

        def seq_of(ordering, hosts, npkts):
            n = len(hosts)
            if ordering.startswith('burst'):
                k = int(ordering[5:])
                return [hosts[p // k % n] for p in range(npkts)]
            return [hosts[p % n] for p in range(npkts)]
        for pfx in sorted(set(bgp) | set(attack)):
            seq = []
            if pfx in bgp:
                seq += [pfx | 255] * BG_PKTS
            if pfx in attack:
                at = attack[pfx]
                seq += seq_of(pol.ordering, at['hosts'], at['npkts'])
            streams.setdefault((1, pfx), {})[w] = [rr(d) for d in seq]
        groups = {}
        for pfx in sorted(set(bgp) | set(attack)):
            groups.setdefault(pfx >> 16 << 16, []).append(pfx)
        for key16, pfxs in groups.items():
            seq = []
            for p in pfxs:
                if p in bgp:
                    seq += [p | 255] * BG_PKTS
            atts = [(p, attack[p]) for p in pfxs if p in attack]
            if len(atts) == 2 and pol.ordering == 'split7030':
                main = [at for _, at in atts if at['role'] == 'main'][0]
                adj = [at for _, at in atts if at['role'] == 'adj'][0]
                nm, na = (len(main['hosts']), len(adj['hosts']))
                im = ia = 0
                for p in range(pol.V):
                    if p % 10 < 7:
                        seq.append(main['hosts'][im % nm])
                        im += 1
                    else:
                        seq.append(adj['hosts'][ia % na])
                        ia += 1
            elif len(atts) == 1:
                at = atts[0][1]
                seq += seq_of(pol.ordering, at['hosts'], at['npkts'])
            elif len(atts) == 0:
                pass
            else:
                raise RuntimeError('bad atts')
            streams.setdefault((2, key16), {})[w] = [rr(d) for d in seq]
    return streams

def validate(seed=0):
    from sweepsketch.bucket import Bucket
    tbl = make_llr_table(sscfg.THETA0)
    cases = []
    for S in (8, 12):
        for order in ORDERS:
            for target in ('single', 'switch1'):
                for rate in (40, 400):
                    cases.append(Policy(S, 64, order, target, rate))
    bad = 0
    checks = 0
    windows_checked = 0
    for cid, pol in enumerate(cases):
        for bg in (True, False):
            plan = make_plan(pol, cov_max=THRESH[25])
            fast = simulate(pol, cid, seed, plan, bg=bg, diag=True)
            streams = materialize(pol, cid, seed, plan, bg=bg)
            ref = {}
            ref_alarms = []
            for (lvl, key), wins in streams.items():
                b = None
                for w in sorted(wins):
                    if b is None:
                        b = Bucket(key, w)
                    for i, (r, rho) in enumerate(wins[w]):
                        a1, a2, _ = b.process(r, rho, w, tbl)
                        if a1:
                            ref_alarms.append((w, i + 1, 'D1', lvl, key))
                        if a2:
                            ref_alarms.append((w, i + 1, 'D2', lvl, key))
                    ref[lvl, key, w] = (b.n_new, b.C, b.pkt, b.win, b.n_ewma, b.pkt_ewma, int(b.d2_held))
                    windows_checked += 1
            fast_set = {(a[0], a[2], a[3], a[4]) for a in fast['alarms']}
            ref_set = {(a[0], a[2], a[3], a[4]) for a in ref_alarms}
            checks += 1
            if fast_set != ref_set:
                bad += 1
                print('[validate] ALARM MISMATCH', pol.key(), 'bg', bg, 'fast', sorted(fast_set)[:4], 'ref', sorted(ref_set)[:4], file=sys.stderr)
            for lv, bucket_map in ((1, fast['l1']), (2, fast['l2'])):
                for key, b in bucket_map.items():
                    tl = b.trace or []
                    for epoch, n_new, C, pkt, win, n_ewma, pkt_ewma, held in tl:
                        got = (n_new, C, pkt, win, n_ewma, pkt_ewma, held)
                        exp = ref.get((lv, key, epoch))
                        checks += 1
                        if exp is None or got != exp:
                            bad += 1
                            if bad < 8:
                                print('[validate] STATE MISMATCH', pol.key(), 'bg', bg, 'lvl', lv, 'key', hex(key), 'w', epoch, 'got', got, 'exp', exp, file=sys.stderr)
                            break
    result = {'cases': len(cases), 'bg_variants': 2, 'window_state_checks': windows_checked, 'checks': checks, 'mismatches': bad, 'seed': seed, 'policies': [p.key() for p in cases]}
    print('[E2] validation: %d policies x {bg on/off}, %d window-states -> %d mismatches' % (len(cases), windows_checked, bad), flush=True)
    with open(os.path.join(LOG, 'e2_validation.json'), 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    return bad == 0
COLS_FULL = ['strategy_id', 'kind', 'S', 'lam', 'ordering', 'target', 'rate', 'V', 'X', 'damage_basis', 'bg', 'feasible', 'windows', 'duration_s', 'hosts', 'coverage_pct', 'packets_sent', 'actual_pps', 'per_host_packets', 'detect_rate', 'detected_seeds', 'first_w_med', 'first_ms_med', 'first_reason']
COLS_WORST = ['X', 'damage_basis', 'kind', 'strategy_id', 'S', 'lam', 'ordering', 'target', 'rate', 'V', 'bg', 'windows', 'duration_s', 'hosts', 'coverage_pct', 'packets_sent', 'actual_pps', 'per_host_packets', 'detect_rate', 'detected_seeds', 'first_w_med', 'first_ms_med', 'first_reason']

def row_from(pol, pid, kind, X, basis, r, bg=1):
    row = {'strategy_id': 'p%05d' % pid, 'kind': kind, **pol.as_dict(), 'X': X, 'damage_basis': basis, 'bg': bg}
    row.update(r)
    return row

def run_worstcase(grid_rows, cache, seeds):
    naive = Policy(32, 1024, 'rotation', 'single', 400)
    naive_rows, _ = eval_policy(naive, 900001, seeds)
    out = []
    trace = []
    for X in X_LIST:
        for basis in ('union', 'single24'):
            cands = [r for r in grid_rows if r['X'] == X and r['damage_basis'] == basis and r.get('feasible')]
            if not cands:
                continue
            cands.sort(key=lambda r: (r['detect_rate'], r['windows'], -r['packets_sent']))
            ref_row = cands[0]
            ref = Policy(ref_row['S'], ref_row['lam'], ref_row['ordering'], ref_row['target'], ref_row['rate'])
            g, grows, tr = greedy(ref, X, basis, cache, seeds, pid_start=910000 + X * 1000 + (0 if basis == 'union' else 500))
            trace.extend(tr)
            if naive_rows[X, basis].get('feasible'):
                out.append(row_from(naive, 900001, 'naive_400pps_rotation_S32', X, basis, naive_rows[X, basis]))
            out.append(dict(ref_row, kind='grid_best'))
            out.append(row_from(g, 920000 + X, 'greedy_best', X, basis, grows[X, basis]))
            cold_rows, _ = eval_policy(g, 930000 + X, seeds, bg=False)
            out.append(row_from(g, 930000 + X, 'greedy_best_no_benign_bg', X, basis, cold_rows[X, basis], bg=0))
            und = [r for r in cands if r['detect_rate'] == 0.0]
            und.sort(key=lambda r: (r['windows'], -r['packets_sent']))
            for rank, r in enumerate(und[:3]):
                out.append(dict(r, kind='undetected_top%d' % (rank + 1)))
    return (out, trace)

def floor_probe(seeds=SEEDS):
    rows = []
    pid = 880000
    for order in ORDERS:
        for rate in (40, 400):
            V = min(1024, int(rate * EPOCH_S))
            for S in range(4, 33):
                pol = Policy(S, 1024, order, 'single', rate)
                plan = make_plan(pol, cov_max=COV_MAX)
                cps = checkpoints(plan)
                nn, cc, gate, d1w1, d2w1, det90, fw = ([], [], [], [], [], [], [])
                for seed in seeds:
                    res = simulate(pol, pid, seed, plan, bg=True, diag=True)
                    b = res['l1'][BASE16 | 256]
                    tr = b.trace[0] if b.trace else None
                    if tr:
                        nn.append(tr[1])
                        cc.append(tr[2])
                        gate.append(max(K_ALARM, 2 * tr[5], K_ALARM_QUIET if tr[5] < N_EWMA_QUIET else 0))
                    al1 = [a for a in res['alarms'] if a[0] == 1]
                    d1w1.append(1 if any((a[2] == 'D1' and a[3] == 1 for a in al1)) else 0)
                    d2w1.append(1 if any((a[2] == 'D2' for a in al1)) else 0)
                    s90 = eval_at(res, plan, cps[90, 'union'], 'union')
                    det90.append(s90['detected'])
                    if s90['detected']:
                        fw.append(s90['first_w'])
                    pid += 1
                rows.append({'ordering': order, 'rate': rate, 'V': V, 'S': S, 'L1_n_new_w1_med': statistics.median(nn) if nn else None, 'L1_C_max_w1_med': statistics.median(cc) if cc else None, 'L1_gate_w1': gate[0] if gate else None, 'L1_D1_w1_rate': round(sum(d1w1) / len(d1w1), 3), 'L1_D2_w1_rate': round(sum(d2w1) / len(d2w1), 3), 'detect90_rate': round(sum(det90) / len(det90), 3), 'first_w_med': statistics.median(fw) if fw else None, 'bg': 1})
    return rows

def run_mitigation(seeds=SEEDS):
    policies = [('worst_union_switch1', Policy(32, 1024, 'burst3', 'switch1', 400)), ('worst_single24_burst3_40', Policy(32, 192, 'burst3', 'single', 40)), ('naive_400pps_rotation', Policy(32, 1024, 'rotation', 'single', 400)), ('switch2_burst3_40', Policy(32, 192, 'burst3', 'switch2', 40)), ('single_burst3_100', Policy(32, 512, 'burst3', 'single', 100))]
    modes = [('none', None), ('d2hold_W2', {'mode': 'd2hold', 'W': 2}), ('d2hold_W4', {'mode': 'd2hold', 'W': 4}), ('nnew_only', {'mode': 'nnew_only'}), ('x16_K2_W4', {'mode': 'x16', 'K': 2, 'W': 4}), ('x16_K3_W4', {'mode': 'x16', 'K': 3, 'W': 4}), ('x16_K2_W8', {'mode': 'x16', 'K': 2, 'W': 8})]
    rows = []
    pid = 950000
    for name, pol in policies:
        for mname, miti in modes:
            r, _ = eval_policy(pol, pid, seeds, miti=miti)
            pid += 1
            for X in X_LIST:
                for basis in ('union', 'single24'):
                    rr_ = r[X, basis]
                    if not rr_.get('feasible'):
                        continue
                    rows.append({'policy': name, 'mitigation': mname, 'X': X, 'damage_basis': basis, **pol.as_dict(), **rr_})
    return rows

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('cmd', choices=['all', 'grid', 'validate', 'plot', 'mitigation'], default='all', nargs='?')
    ap.add_argument('--seeds', type=int, default=5)
    args = ap.parse_args()
    seeds = SEEDS[:args.seeds]
    t0 = time.time()
    if args.cmd == 'validate':
        ok = validate()
        return 0 if ok else 1
    if args.cmd == 'plot':
        make_figures()
        return 0
    if args.cmd == 'mitigation':
        print('[E2] mitigation evaluation ...', flush=True)
        rows = run_mitigation(seeds)
        p = os.path.join(RES, 'e2_mitigation.csv')
        rc.write_csv(p, rows)
        rc.write_meta(p, experiment='E2-mitigation', seeds=seeds, modes=['none', 'd2hold_W2', 'd2hold_W4', 'nnew_only', 'x16_K2_W4', 'x16_K3_W4', 'x16_K2_W8'], note='minimal mitigations: recent-W-window memory for d2_held; n_new-only D1 (CUSUM removed); cross-/16 correlation. All are analytical upper bounds without benign FP calibration.', wall_s=round(time.time() - t0, 1))
        print('[E2] wrote', p, flush=True)
        return 0
    print('[E2] validate fast simulator against reference Bucket.process ...', flush=True)
    if not validate():
        print('[E2] validation FAILED - abort', file=sys.stderr)
        return 2
    print('[E2] grid: %d S x %d lambda x %d order x %d target x %d rate' % (len(S_VALUES), len(LAM_VALUES), len(ORDERS), len(TARGETS), len(RATES)), flush=True)
    configs, cache, grid_rows = run_grid(seeds)
    print('[E2] grid done: %d configs, %d rows, %.0fs' % (len(configs), len(grid_rows), time.time() - t0), flush=True)
    print('[E2] floor probe ...', flush=True)
    probe_rows = floor_probe(seeds)
    print('[E2] worst-case greedy search ...', flush=True)
    worst_rows, trace = run_worstcase(grid_rows, cache, seeds)
    p_full = os.path.join(RES, 'e2_detection_vs_damage.csv')
    rc.write_csv(p_full, grid_rows, COLS_FULL)
    rc.write_meta(p_full, experiment='E2-detection-vs-damage', seeds=seeds, grid={'S': S_VALUES, 'lam': LAM_VALUES, 'ordering': ORDERS, 'target': TARGETS, 'rate': RATES}, floor_probe_S=list(range(4, 33)), victim_space='10.100.0.0/16 (BASE16=0x0A640000), 254 hosts per /24', damage_definition={'union': 'distinct victim hosts = union of all attacked /24s; X%% (threshold %s) of 254' % THRESH, 'single24': 'hosts reached inside any single victim /24 >= X% x 254; strict "one /24 fully swept" definition'}, damage_note='detection rates under both definitions are truncated at the window where the damage threshold is reached; with switch1/switch2 target hopping, the single24 definition attacks at most S hosts in one /24 (S<=32, i.e. <=12.6%), so X>=25% is infeasible (no such row)', ordering_randomization='host slots are shuffled with random.Random for every (policy, seed, window); 5 seeds', benign_bg='20 packets per window per /24 sent to .255 (quiet prefixes); the background runs concurrently with the attack inside attack windows', reference_validated=True, workers=os.environ.get('SWEEPSKETCH_WORKERS', '4'), wall_s=round(time.time() - t0, 1))
    print('[E2] wrote', p_full, len(grid_rows), 'rows', flush=True)
    p_worst = os.path.join(RES, 'e2_worstcase.csv')
    rc.write_csv(p_worst, worst_rows, COLS_WORST)
    rc.write_meta(p_worst, experiment='E2-worstcase', seeds=seeds, objective='lexicographic order on (detect_rate, windows_to_X, -packets_sent)', naive_anchor='S=32, lambda=1024, rotation, single target, 400 pps (the naive attack of the EXP8 family)', note='greedy_best_no_benign_bg = the same policy with the benign background removed (sensitivity)', wall_s=round(time.time() - t0, 1))
    print('[E2] wrote', p_worst, len(worst_rows), 'rows', flush=True)
    p_probe = os.path.join(RES, 'e2_floor_probe.csv')
    rc.write_csv(p_probe, probe_rows)
    rc.write_meta(p_probe, experiment='E2-floor-probe', seeds=seeds, note='single /24; first attack window at L1; n_new/C are medians over 5 seeds; gate = max(8, 2*n_ewma, 12*[n_ewma<4])')
    print('[E2] wrote', p_probe, flush=True)
    p_trace = os.path.join(RES, 'e2_greedy_trace.csv')
    rc.write_csv(p_trace, trace)
    rc.write_meta(p_trace, experiment='E2-greedy-trace', seeds=seeds)
    print('[E2] wrote', p_trace, flush=True)
    print('[E2] mitigation evaluation ...', flush=True)
    mit_rows = run_mitigation(seeds)
    p_mit = os.path.join(RES, 'e2_mitigation.csv')
    rc.write_csv(p_mit, mit_rows)
    rc.write_meta(p_mit, experiment='E2-mitigation', seeds=seeds, modes=['none', 'd2hold_W2', 'd2hold_W4', 'nnew_only', 'x16_K2_W4', 'x16_K3_W4', 'x16_K2_W8'], note='minimal mitigations: recent-W-window memory for d2_held; n_new-only D1 (CUSUM removed); cross-/16 correlation. All are analytical upper bounds without benign FP calibration.', wall_s=round(time.time() - t0, 1))
    print('[E2] wrote', p_mit, len(mit_rows), 'rows', flush=True)
    make_figures()
    print('[E2] done %.0fs' % (time.time() - t0), flush=True)
    return 0

def make_figures():
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except Exception as e:
        print('[E2] matplotlib unavailable (%s); skipping plots, CSV files are written' % e, flush=True)
        return
    worst = os.path.join(RES, 'e2_worstcase.csv')
    full = os.path.join(RES, 'e2_detection_vs_damage.csv')
    if not (os.path.exists(worst) and os.path.exists(full)):
        print('[E2] required CSV files are missing; skipping plots', flush=True)
        return
    rows = list(csv.DictReader(open(worst, encoding='utf-8')))
    grid = list(csv.DictReader(open(full, encoding='utf-8')))
    by = {}
    for r in rows:
        by.setdefault((r['kind'], r['damage_basis']), {})[int(r['X'])] = r
    xs = X_LIST
    styles = {'union': '-', 'single24': '--'}
    colors = {'naive_400pps_rotation_S32': 'tab:red', 'grid_best': 'tab:orange', 'greedy_best': 'tab:blue', 'greedy_best_no_benign_bg': 'tab:green'}
    markers = {'naive_400pps_rotation_S32': 'o', 'grid_best': 's', 'greedy_best': 'D', 'greedy_best_no_benign_bg': '^'}
    fig, axes = plt.subplots(1, 3, figsize=(13, 3.8))
    ax = axes[0]
    for (kind, basis), d in sorted(by.items()):
        if kind not in colors:
            continue
        ys = [float(d[x]['detect_rate']) if d.get(x, {}).get('detect_rate') not in (None, '', 'None') else 0.0 for x in xs]
        ax.plot(xs, ys, styles[basis], marker=markers[kind], color=colors[kind], markersize=4, lw=1.2, label='%s / %s' % (kind.replace('_', ' '), basis))
    ax.set_xlabel('damage target X (% of 254 victim hosts)')
    ax.set_ylabel('detection rate (5 seeds)')
    ax.set_ylim(-0.05, 1.05)
    ax.set_title('E2 detection vs damage')
    ax.grid(alpha=0.3)
    ax.legend(fontsize=5.5, loc='best')
    ax = axes[1]
    import numpy as _np
    pos = _np.arange(len(xs))
    for basis, off, color, hatch in (('union', -0.2, 'tab:blue', None), ('single24', 0.2, 'tab:cyan', '//')):
        d = by.get(('greedy_best', basis))
        if not d:
            continue
        ys = [float(d[x]['windows']) for x in xs]
        ax.bar(pos + off, ys, width=0.38, color=color, alpha=0.85, hatch=hatch, label=basis)
        for i, x in enumerate(xs):
            ax.text(pos[i] + off, ys[i] + 0.15, '%.0fs' % float(d[x]['duration_s']), ha='center', fontsize=6)
    ax.set_xticks(pos)
    ax.set_xticklabels([str(x) for x in xs])
    ax.set_xlabel('damage target X (% of 254 hosts)')
    ax.set_ylabel('windows needed (= X coverage)')
    ax.set_title('greedy worst case: time to reach X')
    ax.legend(fontsize=7)
    ax = axes[2]
    for basis, off, color in (('union', -0.2, 'tab:purple'), ('single24', 0.2, 'tab:pink')):
        d = by.get(('greedy_best', basis))
        if not d:
            continue
        ys = [float(d[x]['per_host_packets']) for x in xs]
        ax.bar(pos + off, ys, width=0.38, color=color, alpha=0.85, label=basis)
    ax.set_xticks(pos)
    ax.set_xticklabels([str(x) for x in xs])
    ax.set_xlabel('damage target X (% of 254 hosts)')
    ax.set_ylabel('packets per reached host')
    ax.set_title('residual intensity after bypass')
    ax.legend(fontsize=7)
    fig.tight_layout()
    for ext in ('png', 'pdf'):
        p = os.path.join(RES, 'e2_frontier.' + ext)
        fig.savefig(p, dpi=180)
        print('[E2] wrote', p, flush=True)
    plt.close(fig)
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        pts = [r for r in grid if r['kind'] == 'grid' and r['feasible'] == 'True']
        if pts:
            fig, axes = plt.subplots(1, 2, figsize=(11, 4.0), sharey=True)
            for ax, basis in zip(axes, ('union', 'single24')):
                for X, color in zip(X_LIST, ('tab:blue', 'tab:green', 'tab:orange', 'tab:red')):
                    sub = [r for r in pts if int(r['X']) == X and r['damage_basis'] == basis]
                    ax.scatter([float(r['windows']) for r in sub], [float(r['detect_rate']) for r in sub], s=4, alpha=0.25, color=color, label='X=%d%%' % X)
                ax.set_xlabel('windows needed to reach X')
                ax.set_title('damage basis = %s' % basis)
                ax.grid(alpha=0.3)
                ax.legend(markerscale=3, fontsize=7)
            axes[0].set_ylabel('detection rate (5 seeds)')
            fig.tight_layout()
            for ext in ('png', 'pdf'):
                p = os.path.join(RES, 'e2_grid_scatter.' + ext)
                fig.savefig(p, dpi=180)
                print('[E2] wrote', p, flush=True)
            plt.close(fig)
    except Exception as e:
        print('[E2] second figure skipped:', e, flush=True)
if __name__ == '__main__':
    sys.exit(main())
