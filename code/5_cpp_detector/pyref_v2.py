from __future__ import annotations
import argparse
import json
import os
import struct
import sys
HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.normpath(os.path.join(HERE, '..', '..'))
IMPL = os.path.join(REV, 'code', '1_reference_implementation')
sys.path.insert(0, IMPL)
from sweepsketch.bucket import Bucket
from sweepsketch.hash import pfx_hash
from sweepsketch.llr import make_llr_table
from sweepsketch.pcapio import iter_pcap
from sweepsketch.sketch import Level
N_L1, N_L2 = (7943, 3972)
HLL_M = 32
H_FP, P_MIN = (74, 200)
LLR = make_llr_table(0.0345)
assert LLR == {'new': 38, 'rep': -26}, LLR
AGE_WIN = 4
COOLDOWN_WIN = 20
D2_CONFIRM_WINDOWS = 3
D2_CONFIRM_COUNT = 2
Q_LOOKBACK_WIN = 1677
Q_WINDOW_WIN = 20117
Q_MAX_K = 16
Q_GROWTH_MULT = 1.25
CROSS_W, CROSS_K, CROSS_NNEW_FLOOR = (4, 2, 12)
DIST_LEVEL = 3

class Bucket2(Bucket):
    __slots__ = ()

class RawCollector:

    def __init__(self):
        self.alerts = []
        self._seen = set()

    def add(self, ts_ns, E, level, key, reason, n_new, C, pkt):
        k = (level, key, E, reason)
        if k in self._seen:
            return
        self._seen.add(k)
        self.alerts.append({'ts': ts_ns, 'epoch': E, 'level': level, 'key': key, 'reason': reason, 'n_new': n_new, 'C': C, 'pkt': pkt})

class AlarmManager:

    def __init__(self, enabled=True, quarantine=True):
        self.enabled = enabled
        self.quarantine = quarantine
        self._d2 = {}
        self._last = {}
        self._eps = {}
        self._q = {}
        self.stats = {'raw_processed': 0, 'd2_unconfirmed': 0, 'd2_confirmed': 0, 'suppressed_cooldown': 0, 'suppressed_quarantine': 0, 'emitted': 0, 'quarantined': 0}

    @staticmethod
    def _key(a):
        return (a['level'], a['key'])

    def _d2_ok(self, a):
        if not self.enabled or a['reason'] != 'D2':
            return True
        k2 = self._key(a)
        h = self._d2.setdefault(k2, [])
        h.append(a['epoch'])
        if len(h) > 8:
            del h[:-8]
        lo = a['epoch'] - (D2_CONFIRM_WINDOWS - 1)
        recent = {e for e in h if lo <= e <= a['epoch']}
        if len(recent) < D2_CONFIRM_COUNT:
            self.stats['d2_unconfirmed'] += 1
            return False
        self.stats['d2_confirmed'] += 1
        return True

    @staticmethod
    def _attack_evidence(recent):
        ks = [e[2] for e in recent]
        if ks and max(ks) > Q_MAX_K:
            return True
        if len(ks) >= 3 and ks[-1] > Q_GROWTH_MULT * max(1, ks[0]):
            return True
        return False

    def process(self, a):
        if a['reason'] not in ('D1', 'D2'):
            return None
        self.stats['raw_processed'] += 1
        k2 = self._key(a)
        if not self._d2_ok(a):
            return None
        exp = self._q.get(k2)
        if self.quarantine and exp is not None and (a['epoch'] < exp):
            self.stats['suppressed_quarantine'] += 1
            return None
        last = self._last.get(k2)
        if last is not None and 0 <= a['epoch'] - last < COOLDOWN_WIN:
            self.stats['suppressed_cooldown'] += 1
            return None
        self._last[k2] = a['epoch']
        eps = self._eps.setdefault(k2, [])
        eps.append((a['epoch'], a['reason'], a['n_new']))
        if len(eps) > 64:
            del eps[:-64]
        if self.quarantine:
            lo = a['epoch'] - Q_LOOKBACK_WIN
            recent = [e for e in eps if lo <= e[0] <= a['epoch']]
            if len(recent) >= 3 and (not self._attack_evidence(recent)):
                self._q[k2] = a['epoch'] + Q_WINDOW_WIN
                self.stats['quarantined'] += 1
        self.stats['emitted'] += 1
        out = dict(a)
        out['level'] = a['level']
        return out

class Cross16:

    def __init__(self, enabled=True):
        self.enabled = enabled
        self._hits = {}
        self._last = {}
        self.stats = {'n12': 0, 'd1': 0, 'windows': 0, 'dist_emitted': 0, 'dist_suppressed_cooldown': 0}

    @staticmethod
    def pfx16_of(key24):
        return key24 >> 16 << 16

    def _prune(self, e):
        if len(self._hits) <= CROSS_W + 2:
            return
        lo = e - CROSS_W
        for e0 in [x for x in self._hits if x <= lo]:
            del self._hits[e0]

    def observe(self, a):
        if not self.enabled or a['level'] != 1:
            return []
        if a['reason'] == 'N12':
            if a['n_new'] < CROSS_NNEW_FLOOR:
                return []
            self.stats['n12'] += 1
        elif a['reason'] == 'D1':
            self.stats['d1'] += 1
        else:
            return []
        e = a['epoch']
        hit = self._hits.get(e)
        if hit is None:
            hit = self._hits[e] = {}
            self.stats['windows'] += 1
            self._prune(e)
        p16 = self.pfx16_of(a['key'])
        hit.setdefault(p16, set()).add(a['key'])
        lo = e - CROSS_W + 1
        union = set()
        for e0, h in self._hits.items():
            if lo <= e0 <= e:
                union.update(h)
        out = []
        if len(union) >= CROSS_K:
            for p in hit:
                last = self._last.get(p)
                if last is not None and 0 <= e - last < COOLDOWN_WIN:
                    self.stats['dist_suppressed_cooldown'] += 1
                    continue
                self._last[p] = e
                out.append({'ts': a['ts'], 'epoch': e, 'level': DIST_LEVEL, 'key': p, 'reason': 'DIST', 'n_new': len(union), 'C': 0, 'pkt': 0})
                self.stats['dist_emitted'] += 1
        return out

def finalize(raw_alerts):
    am = AlarmManager()
    cx = Cross16()
    episodes = []
    raws = sorted(raw_alerts, key=lambda x: (x['ts'], x['epoch'], x['level'], x['key'], x['reason']))
    for a in raws:
        if a['level'] == 1 and a['reason'] in ('D1', 'N12'):
            episodes.extend(cx.observe(a))
        ep = am.process(a)
        if ep is not None:
            episodes.append(ep)
    episodes.sort(key=lambda x: (x['ts'], x['level'], x['key']))
    return (episodes, {'alarm': am.stats, 'cross16': cx.stats, 'raw': len(raws)})

class DetectorV2:

    def __init__(self, v1=False):
        self.v1 = v1
        self.l1 = Level(N_L1, lambda d: d >> 8 << 8, 17)
        self.l2 = Level(N_L2, lambda d: d >> 16 << 16, 34)
        self.raw = RawCollector()
        self.v1_alarms = []
        self.v1_seen = set()
        self.n_pkts = 0
        self.raw_d1 = self.raw_d2 = self.raw_n12 = 0

    def process(self, ts_ns, dst, src):
        g = ts_ns >> 32 & 255
        E = ts_ns >> 32
        h = pfx_hash(dst, 51)
        r = h & HLL_M - 1
        rho = 27 - (h >> 5).bit_length()
        self._up(self.l1, 1, dst >> 8 << 8, r, rho, g, E, ts_ns)
        self._up(self.l2, 2, dst >> 16 << 16, r, rho, g, E, ts_ns)
        self.n_pkts += 1

    def _up(self, level, lev, key, r, rho, g, E, ts_ns):
        i = level.idx(key)
        b = level.buckets[i]
        if b is None:
            b = level.buckets[i] = Bucket2(key, g)
        elif b.key != key:
            replace = b.pkt < P_MIN and b.C < H_FP
            if not replace and (not self.v1):
                replace = g - b.epoch & 31 >= AGE_WIN
            if not replace:
                return
            b = level.buckets[i] = Bucket2(key, g)
        prev = b.n_new
        a1, a2, _ = b.process(r, rho, g, LLR)
        if self.v1:
            if a1:
                self._v1_emit(lev, key, E, ts_ns, b, 'D1')
            if a2:
                self._v1_emit(lev, key, E, ts_ns, b, 'D2')
            return
        if lev == 1 and prev < CROSS_NNEW_FLOOR <= b.n_new:
            self.raw.add(ts_ns, E, 1, key, 'N12', b.n_new, b.C, b.pkt)
            self.raw_n12 += 1
        if a1:
            self.raw.add(ts_ns, E, lev, key, 'D1', b.n_new, b.C, b.pkt)
            self.raw_d1 += 1
        if a2:
            self.raw.add(ts_ns, E, lev, key, 'D2', b.n_new, b.C, b.pkt)
            self.raw_d2 += 1

    def _v1_emit(self, lev, key, E, ts_ns, b, reason):
        k = (lev, key, E)
        if k in self.v1_seen:
            return
        self.v1_seen.add(k)
        self.v1_alarms.append({'ts': ts_ns, 'epoch': E, 'level': lev, 'key': key, 'reason': reason, 'n_new': b.n_new, 'C': b.C, 'pkt': b.pkt})

    def episodes(self):
        if self.v1:
            return (self.v1_alarms, {})
        return finalize(self.raw.alerts)

def iter_bin(path, max_pkts=1 << 60, fmt='16'):
    with open(path, 'rb') as f:
        n = 0
        rec_size = 16 if fmt == '16' else 12
        while n < max_pkts:
            rec = f.read(rec_size)
            if len(rec) < rec_size:
                break
            if rec_size == 16:
                ts, dst, src = struct.unpack('<QII', rec)
            else:
                ts, dst = struct.unpack('<QI', rec)
                src = 0
            n += 1
            yield (ts, dst, src)

def export_trace(pcap, n, out_bin):
    cnt = 0
    with open(out_bin, 'wb') as f:
        for s, d, ts in iter_pcap(pcap, n, with_flow=False):
            ts_ns = int(round(ts * 1000000000.0))
            f.write(struct.pack('<QII', ts_ns, d, s))
            cnt += 1
    print('[export] %s -> %s (%d packets)' % (pcap, out_bin, cnt))
    return cnt

def replay(bin_path, out_csv, v1=False, max_pkts=1 << 60, fmt='16'):
    det = DetectorV2(v1=v1)
    for ts, dst, src in iter_bin(bin_path, max_pkts, fmt):
        det.process(ts, dst, src)
    eps, stats = det.episodes()
    with open(out_csv, 'w', encoding='utf-8') as f:
        f.write('ts,level,key,reason,n_new,C,pkt,epoch\n')
        for a in eps:
            f.write('%d,%d,%d,%s,%d,%d,%d,%d\n' % (a['ts'], a['level'], a['key'], a['reason'], a['n_new'], a['C'], a['pkt'], a['epoch']))
    if v1:
        print('[replay-v1] %s -> %s n=%d alarms=%d' % (bin_path, out_csv, det.n_pkts, len(eps)))
    else:
        print('[replay-v2] %s -> %s n=%d raw=%d(d1=%d d2=%d n12=%d) episodes=%d quarantined=%d' % (bin_path, out_csv, det.n_pkts, len(det.raw.alerts), det.raw_d1, det.raw_d2, det.raw_n12, len(eps), stats.get('alarm', {}).get('quarantined', 0)))
    return (det, eps, stats)
CANON = {'ts': 'ts_ns', 'ts_ns': 'ts_ns', 'epoch': 'epoch_full', 'epoch_full': 'epoch_full', 'key': 'key_int', 'key_int': 'key_int', 'level': 'level', 'reason': 'reason', 'n_new': 'n_new', 'C': 'C', 'pkt': 'pkt'}

def read_canon(path):
    with open(path, encoding='utf-8') as f:
        head = f.readline().strip().split(',')
        idx = {}
        for i, h in enumerate(head):
            if h in CANON:
                idx[CANON[h]] = i
        need = ['ts_ns', 'epoch_full', 'level', 'key_int', 'reason', 'n_new', 'C', 'pkt']
        for n in need:
            if n not in idx:
                raise SystemExit('missing column %s in %s (header %r)' % (n, path, head))
        rows = []
        for line in f:
            if not line.strip():
                continue
            p = line.rstrip('\n').split(',')
            rows.append(tuple((p[idx[n]] for n in need)))
    return rows

def compare(py_csv, cpp_csv, out_json, canonical=False):
    if canonical:
        r1 = read_canon(py_csv)
        r2 = read_canon(cpp_csv)
    else:

        def rd(path):
            with open(path, encoding='utf-8') as f:
                f.readline()
                return [tuple(line.rstrip('\n').split(',')) for line in f if line.strip()]
        r1, r2 = (rd(py_csv), rd(cpp_csv))
    res = {'py_csv': py_csv, 'cpp_csv': cpp_csv, 'py_rows': len(r1), 'cpp_rows': len(r2), 'canonical': canonical, 'match': False, 'n_diff': 0, 'first_diff': None}
    n_diff = 0
    first = None
    for i in range(min(len(r1), len(r2))):
        if r1[i] != r2[i]:
            n_diff += 1
            if first is None:
                lo = max(0, i - 2)
                first = {'row_index': i, 'py': r1[i], 'cpp': r2[i], 'context_py': r1[lo:i + 3], 'context_cpp': r2[lo:i + 3]}
    n_diff += abs(len(r1) - len(r2))
    if first is None and len(r1) != len(r2):
        first = {'kind': 'length', 'py_rows': len(r1), 'cpp_rows': len(r2)}
    res['n_diff'] = n_diff
    res['first_diff'] = first
    res['match'] = n_diff == 0
    with open(out_json, 'w', encoding='utf-8') as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print('[compare] match=%s py_rows=%d cpp_rows=%d n_diff=%d' % (res['match'], len(r1), len(r2), res['n_diff']))
    if not res['match'] and first:
        print('[compare] first diff:', json.dumps(first, ensure_ascii=False)[:1500])
    return res

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('cmd', choices=['export', 'replay', 'compare', 'compare-can'])
    ap.add_argument('--pcap', default='')
    ap.add_argument('--bin', default='')
    ap.add_argument('--alarms', default='')
    ap.add_argument('--n', type=int, default=1000000)
    ap.add_argument('--max-pkts', type=int, default=1 << 60)
    ap.add_argument('--fmt', choices=['16', '12'], default='16')
    ap.add_argument('--v1', action='store_true')
    ap.add_argument('--py', default='')
    ap.add_argument('--cpp', default='')
    ap.add_argument('--json', default='')
    args = ap.parse_args()
    if args.cmd == 'export':
        export_trace(args.pcap, args.n, args.bin)
    elif args.cmd == 'replay':
        replay(args.bin, args.alarms, v1=args.v1, max_pkts=args.max_pkts, fmt=args.fmt)
    elif args.cmd == 'compare':
        compare(args.py, args.cpp, args.json, canonical=False)
    elif args.cmd == 'compare-can':
        compare(args.py, args.cpp, args.json, canonical=True)
    return 0
if __name__ == '__main__':
    sys.exit(main())
