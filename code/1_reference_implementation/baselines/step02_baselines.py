

import csv
import heapq
import math
import os
import struct
import sys
import time
from array import array
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from baselines._support import (attack_file_meta, base_argparser, eval_static,
                                parallel_map, save_csv, bob_hash, read_pcap,
                                stitch_flows, pfx_mask, pfx_str)

SOURCE_METHODS = ("segsketch", "spreadsketch", "couper", "trw")   
DST_METHODS = ("rhhh", "elastic", "heavykeeper", "mrb", "lakhina", "entropy")
ALL_METHODS = SOURCE_METHODS + DST_METHODS
MEMORY_METHODS = tuple(m for m in ALL_METHODS if m != "lakhina")   

_PACK = struct.pack
_POP8 = tuple(bin(i).count("1") for i in range(256))       
_POP16 = tuple(bin(i).count("1") for i in range(65536))    



def _tz(v: int) -> int:
    
    return (v & -v).bit_length() - 1


def _lc(ones: int, m: int) -> float:
    
    z = m - ones
    if z <= 0:
        z = 1
    return m * math.log(m / z)


def _hll_est(regs):
    
    m = len(regs)
    s = sum(2.0 ** -r for r in regs if r > 0) + (m - sum(1 for r in regs if r > 0))
    res = (0.7213 / (1 + 1.079 / m)) * m * m / s
    if res < 2.5 * m:
        z = sum(1 for r in regs if r == 0)
        res = m * math.log(m / max(z, 1))
    return res


def _auc(scores, gt):
    
    n_pos = sum(1 for k in gt if k in scores)
    n_neg = len(scores) - n_pos
    if n_pos == 0:
        return 0.0
    if n_neg == 0:
        return 1.0
    auc, prev = 0.0, (0.0, 0.0)
    tp = fp = 0
    for k, s in sorted(scores.items(), key=lambda kv: -kv[1]):
        if k in gt:
            tp += 1
        else:
            fp += 1
        tpr, fpr = tp / n_pos, fp / n_neg
        auc += (fpr - prev[1]) * (tpr + prev[0]) / 2
        prev = (tpr, fpr)
    return round(auc, 4)


def _prf1(tp, fp, fn):
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return prec, rec, f1



class SegSketch:
    

    G = 4                  
    SUB_BITS = 256         
    HOST_BITS = 4096       
    R = 3                  
    ALPHA = 0.5            
    BUCKET_BYTES = 4 + SUB_BITS // 8 + HOST_BITS // 8   

    def __init__(self, cols):
        self.cols = cols
        self.buckets = [[[0, bytearray(self.SUB_BITS // 8), bytearray(self.HOST_BITS // 8)]
                         for _ in range(cols)] for _ in range(self.R)]

    
    def insert(self, s, d, pkt_i=0):
        cands = [self.buckets[i][bob_hash(_PACK("<I", s), 0x1100 + i) % self.cols]
                 for i in range(self.R)]
        for b in cands:
            if b[0] == s:
                self._mark(b, d)
                return
        empty = next((b for b in cands if b[0] == 0), None)
        if empty is not None:
            empty[0] = s
            self._mark(empty, d)
            return
        
        cand = min(cands, key=self._est)
        nhat = max(self._est(cand), 1.0)
        r = bob_hash(_PACK("<II", s, pkt_i), 0x9900) / 2 ** 32
        if r < 1.0 / (math.log(nhat) + 1.0):
            cand[0] = s
            cand[1][:] = b"\x00" * (self.SUB_BITS // 8)   
            cand[2][:] = b"\x00" * (self.HOST_BITS // 8)
            self._mark(cand, d)

    def _mark(self, b, d):
        
        bit = 0
        for k in range(8):
            seg = (d >> (28 - 4 * k)) & 0xF          
            bit = (bit << 1) | (bob_hash(_PACK("<I", seg), 0x2100) & 1)
        b[1][bit >> 3] |= 0x80 >> (bit & 7)
        h = bob_hash(_PACK("<I", d), 0x3300) % self.HOST_BITS
        b[2][h >> 3] |= 0x80 >> (h & 7)

    def _est(self, b):
        return _lc(sum(_POP8[x] for x in b[2]), self.HOST_BITS)

    def _prefix(self, b):
        
        lo, hi, depth = 0, self.SUB_BITS, 0
        while depth < 7:
            mid = (lo + hi) >> 1
            lh = any(b[1][i >> 3] & (0x80 >> (i & 7)) for i in range(lo, mid))
            rh = any(b[1][i >> 3] & (0x80 >> (i & 7)) for i in range(mid, hi))
            if lh and rh:
                return depth * self.G
            lo, hi = (lo, mid) if lh else (mid, hi)
            depth += 1
        return 28

    def query(self):
        return {b[0]: self._est(b) for row in self.buckets for b in row if b[0]}

    def detect_native(self):
        
        out = set()
        for row in self.buckets:
            for b in row:
                if b[0] and self._est(b) > self.ALPHA * (2 ** (32 - self._prefix(b))):
                    out.add(b[0])
        return out

    def clone(self):
        
        out = SegSketch(self.cols)
        out.buckets = [[[k, bytearray(sb), bytearray(hb)] for k, sb, hb in row]
                       for row in self.buckets]
        return out



class SpreadSketch:
    

    M = 512                
    ROWS = 4               

    def __init__(self, cols):
        self.cols = cols
        self.buckets = [[[0, 0, bytearray(self.M // 8)] for _ in range(cols)]
                        for _ in range(self.ROWS)]

    def insert(self, s, d, pkt_i=0):
        p = (bob_hash(_PACK("<II", s, d), 0x5500) << 32) | bob_hash(_PACK("<II", s, d), 0x5501)
        lvl = self._loghash(p)
        pos = ((p >> 32) * self.M) >> 32
        for i in range(self.ROWS):
            b = self.buckets[i][bob_hash(_PACK("<I", s), 0x6600 + i) % self.cols]
            if b[1] < lvl:
                b[1], b[0] = lvl, s
            b[2][pos >> 3] |= 0x80 >> (pos & 7)

    @staticmethod
    def _loghash(p):
        
        t = 0
        while p & 1:
            t += 1
            p >>= 1
        return t + 1

    def query(self):
        
        keys = {b[0] for row in self.buckets for b in row if b[0]}
        out = {}
        for k in keys:
            est = None
            for i in range(self.ROWS):
                b = self.buckets[i][bob_hash(_PACK("<I", k), 0x6600 + i) % self.cols]
                e = _lc(sum(_POP8[x] for x in b[2]), self.M)
                est = e if est is None or e < est else est
            out[k] = est
        return out

    def clone(self):
        
        out = SpreadSketch(self.cols)
        out.buckets = [[[k, lv, bytearray(bm)] for k, lv, bm in row]
                       for row in self.buckets]
        return out



class Couper:
    

    B, T, K1, K2, MU, C = 12, 9, 2, 2, 0.6, 48   
    HLL_BITS = 288                              

    def __init__(self, l1, l2, tsc):
        self.l1, self.l2, self.tsc_len = l1, l2, tsc
        self.bm = array("H", [0]) * l1            
        self.regs = array("B", [0]) * (l2 * self.C)   
        self.tsc = [(0, 0.0)] * tsc               

    def _cell(self, f, seed):
        return bob_hash(_PACK("<I", f), seed) % self.l1

    def _est_hll(self, f):
        g1 = bob_hash(_PACK("<I", f), 0x7400) % self.l2
        g2 = bob_hash(_PACK("<I", f), 0x7401) % self.l2
        off1, off2 = g1 * self.C, g2 * self.C
        fgm = [max(self.regs[off1 + i], self.regs[off2 + i]) for i in range(self.C)]
        return fgm

    def insert(self, f, e, pkt_i=0):
        c1, c2 = self._cell(f, 0x7100), self._cell(f, 0x7101)
        if _POP16[self.bm[c1] | self.bm[c2]] < self.T:
            q = bob_hash(_PACK("<II", f, e), 0x7200) % self.B
            self.bm[c1] |= 1 << q
            self.bm[c2] |= 1 << q
            return
        self._record_l2(f, e)

    def _record_l2(self, f, e):
        h = bob_hash(_PACK("<II", f, e), 0x7300)
        reg = h % self.C
        rho = _tz((h // self.C) | 1) + 1           
        offs = [bob_hash(_PACK("<I", f), 0x7400 + i) % self.l2 for i in range(self.K2)]
        lam = None
        for g in offs:
            idx = g * self.C + reg
            if self.regs[idx] < rho:
                self.regs[idx] = rho
            dg = sum(self.regs[g * self.C:(g + 1) * self.C])
            lam = dg if lam is None or dg < lam else lam
        self._tsc_insert(f, lam)

    def _tsc_insert(self, f, lam):
        
        i = bob_hash(_PACK("<I", f), 0x7500) % self.tsc_len
        j = bob_hash(_PACK("<I", f), 0x7501) % self.tsc_len
        if self.tsc[i][0] in (0, f):
            self.tsc[i] = (f, lam)
            return
        if self.tsc[j][0] in (0, f):
            self.tsc[j] = (f, lam)
            return
        k = i if self.tsc[i][1] <= self.tsc[j][1] else j
        if self.tsc[k][1] <= lam:
            self.tsc[k] = (f, lam)

    def estimate(self, f):
        
        c1, c2 = self._cell(f, 0x7100), self._cell(f, 0x7101)
        merged = self.bm[c1] | self.bm[c2]
        coupon = _POP16[merged]
        base = self.B * math.log(self.B / max(self.B - self.T, 1))
        if coupon < self.T:
            return self.B * math.log(self.B / max(self.B - coupon, 1))
        fgm = self._est_hll(f)
        
        bm2 = 0
        for r in range(self.C):
            if fgm[r] > 0:
                bm2 |= 1 << (r % self.B)
        tmp = _POP16[merged & bm2]
        omega = min(self.B * math.log(self.B / max(self.B - tmp, 1)), base)
        return _hll_est(fgm) + base - omega

    def query(self):
        
        return {f: self.estimate(f) for f, _ in self.tsc if f}

    def clone(self):
        
        out = Couper(self.l1, self.l2, self.tsc_len)
        out.bm = self.bm[:]
        out.regs = self.regs[:]
        out.tsc = self.tsc[:]
        return out



class RHHH:
    

    MASKS = (0xFFFFFFFF, 0xFFFFFF00, 0xFFFF0000, 0xFF000000)   
    PLENS = (32, 24, 16, 8)
    Z = 4                   

    def __init__(self, counters_per_level):
        self.C = counters_per_level
        self.levels = [dict() for _ in range(4)]     
        self.base = [0] * 4                          

    def insert(self, s, d, pkt_i=0):
        lv = bob_hash(_PACK("<II", s, d), 0x8100) & 3   
        item = d & self.MASKS[lv]
        ct = self.levels[lv]
        if item in ct:
            ct[item] += 1
        elif len(ct) < self.C:
            ct[item] = self.base[lv] + 1
        else:
            self.base[lv] += 1
            for k in [k for k, c in ct.items() if c <= self.base[lv]]:
                del ct[k]
            if len(ct) == self.C:                     
                del ct[min(ct, key=ct.get)]
            ct[item] = self.base[lv] + 1

    def _eff(self, lv, item):
        c = self.levels[lv].get(item)
        return c - self.base[lv] if c else 0

    def report(self, theta):
        
        adj = theta / 4.0
        child_sum = [defaultdict(float) for _ in range(4)]
        reported = []
        for i in range(4):
            for item, c in self.levels[i].items():
                eff = c - self.base[i]
                s = child_sum[i].get(item, 0.0)
                if eff - s + 2 * self.Z * math.sqrt(max(2 * eff, 0.0)) >= adj:
                    lower = max(0.0, eff - self.base[i])
                    reported.append((i, item, eff, lower))
                    if i + 1 < 4:
                        child_sum[i + 1][item & self.MASKS[i + 1]] += lower
        return reported

    def query(self):
        
        return {item: self._eff(1, item) for item in self.levels[1]}

    def clone(self):
        
        out = RHHH(self.C)
        out.levels = [dict(d) for d in self.levels]
        out.base = self.base[:]
        return out



class ElasticSketch:
    

    CELLS = 8               
    SWAP_SHIFT = 3          

    def __init__(self, bucket_num, light_bytes):
        self.bucket_num = bucket_num
        self.keys = [[0] * self.CELLS for _ in range(bucket_num)]
        self.vals = [[0] * self.CELLS for _ in range(bucket_num)]
        self.light = bytearray(max(light_bytes, 1))

    def _key(self, d):
        return (d >> 8) << 8

    def _light_insert(self, key, f):
        pos = bob_hash(_PACK("<I", key), 0x9200) % len(self.light)
        self.light[pos] = min(255, self.light[pos] + f)

    def _light_swap(self, key, f):
        pos = bob_hash(_PACK("<I", key), 0x9200) % len(self.light)
        if self.light[pos] < f:
            self.light[pos] = min(255, f)

    def insert(self, s, d, pkt_i=0):
        key = self._key(d)
        pos = bob_hash(_PACK("<I", key), 0x9100) % self.bucket_num
        keys, vals = self.keys[pos], self.vals[pos]
        for i in range(self.CELLS - 1):                    
            if keys[i] == key:
                vals[i] += 1
                return
        for i in range(self.CELLS - 1):                    
            if keys[i] == 0:
                keys[i], vals[i] = key, 1
                return
        
        min_i = min(range(self.CELLS - 1), key=lambda i: vals[i] & 0x7FFFFFFF)
        guard = vals[self.CELLS - 1] + 1
        if guard <= ((vals[min_i] & 0x7FFFFFFF) << self.SWAP_SHIFT):
            vals[self.CELLS - 1] = guard                   
            self._light_insert(key, 1)
            return
        ev_key, ev_val = keys[min_i], vals[min_i]          
        vals[self.CELLS - 1] = 0
        keys[min_i], vals[min_i] = key, 0x80000001
        if ev_val & 0x80000000:                            
            self._light_insert(ev_key, ev_val & 0x7FFFFFFF)
        else:
            self._light_swap(ev_key, ev_val)

    def _query_one(self, key):
        pos = bob_hash(_PACK("<I", key), 0x9100) % self.bucket_num
        for i in range(self.CELLS - 1):
            if self.keys[pos][i] == key:
                v = self.vals[pos][i]
                if v & 0x80000000:
                    return (v & 0x7FFFFFFF) + self.light[bob_hash(_PACK("<I", key), 0x9200)
                                                       % len(self.light)]
                return v
        return 0

    def query(self):
        
        out = {}
        for pos in range(self.bucket_num):
            for i in range(self.CELLS - 1):
                key = self.keys[pos][i]
                if key and key not in out:
                    out[key] = self._query_one(key)
        return out

    def clone(self):
        
        out = ElasticSketch(self.bucket_num, len(self.light))
        out.keys = [r[:] for r in self.keys]
        out.vals = [r[:] for r in self.vals]
        out.light = bytearray(self.light)
        return out



class HeavyKeeper:
    

    D = 3                   
    DECAY = 1.0 / 1.08      
    K = 512                 

    def __init__(self, width):
        self.width = width
        self.buckets = [[[0, 0] for _ in range(width)] for _ in range(self.D)]
        self.heap = []       
        self.pos = {}        

    
    def _swap(self, i, j):
        self.pos[self.heap[i][1]] = j
        self.pos[self.heap[j][1]] = i
        self.heap[i], self.heap[j] = self.heap[j], self.heap[i]

    def _sift_up(self, i):
        while i > 0:
            p = (i - 1) >> 1
            if self.heap[i] < self.heap[p]:
                self._swap(i, p)
                i = p
            else:
                break

    def _sift_down(self, i):
        n = len(self.heap)
        while True:
            l, r, m = 2 * i + 1, 2 * i + 2, i
            if l < n and self.heap[l] < self.heap[m]:
                m = l
            if r < n and self.heap[r] < self.heap[m]:
                m = r
            if m == i:
                break
            self._swap(i, m)
            i = m

    def _push(self, count, key):
        self.heap.append((count, key))
        self.pos[key] = len(self.heap) - 1
        self._sift_up(len(self.heap) - 1)

    def _replace_min(self, count, key):
        del self.pos[self.heap[0][1]]
        self.heap[0] = (count, key)
        self.pos[key] = 0
        self._sift_down(0)

    def _fix(self, key, count):
        i = self.pos[key]
        old = self.heap[i][0]
        self.heap[i] = (count, key)
        if count < old:
            self._sift_up(i)
        else:
            self._sift_down(i)

    def insert(self, s, d, pkt_i=0):
        key = (d >> 8) << 8
        in_heap = key in self.pos
        hmin = self.heap[0][0] if self.heap else 0
        max_count = 0
        for i in range(self.D):
            b = self.buckets[i][bob_hash(_PACK("<I", key), 0xA100 + i) % self.width]
            if b[1] == 0:
                b[0], b[1] = key, 1
                if 1 > max_count:
                    max_count = 1
            elif b[0] == key:
                if in_heap or b[1] <= hmin:                
                    b[1] += 1
                if b[1] > max_count:
                    max_count = b[1]
            else:
                r = bob_hash(_PACK("<III", key, pkt_i, i), 0xA200) / 2 ** 32
                if r < self.DECAY ** b[1]:
                    b[1] -= 1
                    if b[1] == 0:
                        b[0], b[1] = key, 1
                        if 1 > max_count:
                            max_count = 1
        if in_heap:
            self._fix(key, max_count)
        elif len(self.heap) < self.K:
            self._push(max_count, key)
        elif max_count > self.heap[0][0]:
            self._replace_min(max_count, key)

    def query(self):
        
        return {k: c for c, k in self.heap}

    def clone(self):
        
        out = HeavyKeeper(self.width)
        out.buckets = [[b[:] for b in row] for row in self.buckets]
        out.heap = list(self.heap)
        out.pos = dict(self.pos)
        return out



class TRW:
    

    TH0, TH1 = 0.8, 0.2    
    ETA1, ETA0 = 5.0, -5.0  
    D_NEW = math.log((1 - TH1) / (1 - TH0))   
    D_REP = math.log(TH1 / TH0)               

    def __init__(self, max_entries):
        self.max_entries = max_entries
        self.lam = {}        
        self.seen = {}       
        self.pairs = set()   
        self.ver = {}        
        self.heap = []       

    def _push(self, s):
        heapq.heappush(self.heap, (self.lam[s], self.ver[s], s))
        if len(self.heap) > 4 * max(len(self.lam), 1):     
            self.heap = [(l, self.ver[k], k) for k, l in self.lam.items()]
            heapq.heapify(self.heap)

    def _evict(self):
        
        while True:
            if not self.heap:                      
                self.heap = [(l, self.ver[k], k) for k, l in self.lam.items()]
                heapq.heapify(self.heap)
            _, v, s = heapq.heappop(self.heap)
            if self.ver.get(s) == v and s in self.lam:
                del self.lam[s]
                del self.seen[s]
                return

    def insert(self, s, d, pkt_i=0):
        pair = (s, d)
        if pair in self.pairs:                      
            return
        self.pairs.add(pair)
        if s in self.lam:
            lam = self.lam[s] + (self.D_REP if d in self.seen[s] else self.D_NEW)
            if lam <= self.ETA0:                       
                del self.lam[s]
                del self.seen[s]
            else:
                self.lam[s] = lam
                self.ver[s] += 1
                self.seen[s].add(d)
                self._push(s)
            return
        if len(self.lam) >= self.max_entries:          
            self._evict()
        self.lam[s] = self.D_NEW
        self.ver[s] = self.ver.get(s, 0) + 1
        self.seen[s] = {d}
        self._push(s)

    def query(self):
        
        return dict(self.lam)

    def clone(self):
        
        out = TRW(self.max_entries)
        out.lam = dict(self.lam)
        out.seen = {k: set(v) for k, v in self.seen.items()}
        out.pairs = set(self.pairs)
        out.ver = dict(self.ver)
        out.heap = list(self.heap)
        return out



class MRB:
    

    C = 3                   
    RATIO = 0.93105         

    def __init__(self, b):
        self.b = b
        self.lastb = max(2 * b, 1)
        self.bm = {}         

    @staticmethod
    def _loghash(p):
        t = 0
        while p & 1:
            t += 1
            p >>= 1
        return t + 1

    def insert(self, s, d, pkt_i=0):
        pfx = (d >> 8) << 8
        bms = self.bm.get(pfx)
        if bms is None:
            bms = [bytearray((self.b + 7) // 8) for _ in range(self.C - 1)] + \
                  [bytearray((self.lastb + 7) // 8)]
            self.bm[pfx] = bms
        p = bob_hash(_PACK("<I", d), 0xB100)
        lvl = self._loghash(p)
        if lvl < self.C - 1:                           
            pos = ((p & 0xFFFFFFFF) * self.b) >> 32
            bms[lvl][pos >> 3] |= 0x80 >> (pos & 7)
        else:                                          
            pos = ((p & 0xFFFFFFFF) * self.lastb) >> 32
            bms[-1][pos >> 3] |= 0x80 >> (pos & 7)

    def _zeros(self, bm, bits):
        ones = sum(_POP8[x] for x in bm)
        return bits - ones

    def _est_one(self, bms):
        
        setmax = int(self.b * self.RATIO + 0.5)
        factor, base = 1, 0
        for base in range(self.C - 1):
            z = self._zeros(bms[base], self.b)
            if self.b - z <= setmax:
                break
            factor *= 2
        m, pos = 0.0, base - 1
        for i in range(base, self.C - 1):
            z = self._zeros(bms[i], self.b)
            if z == 0 or self.b - z > setmax:           
                pos, m = i, 0.0
            else:
                m += self.b * (math.log(self.b) - math.log(z))
        factor *= 1 << (pos - base + 1)
        z = self._zeros(bms[-1], self.lastb)
        m += self.lastb * (math.log(self.lastb) - (math.log(z) if z else 0.0))
        return factor * m

    def query(self):
        return {pfx: self._est_one(bms) for pfx, bms in self.bm.items()}



class Lakhina:
    

    def __init__(self):
        self.counts = defaultdict(lambda: defaultdict(int))

    def insert(self, s, d, pkt_i=0):
        self.counts[(d >> 8) << 8][d] += 1

    def query(self):
        out = {}
        for pfx, cnt in self.counts.items():
            tot = sum(cnt.values())
            out[pfx] = -sum((c / tot) * math.log2(c / tot) for c in cnt.values())
        return out

    def state_kb(self):
        
        n_dst = sum(len(v) for v in self.counts.values())
        return round((len(self.counts) * 4 + n_dst * 8) / 1024, 1)



class EntropySketch:
    

    def __init__(self, z):
        self.z = z
        self.g = min(3, max(1, z // 4))   
        self.bm = {}                      

    def insert(self, s, d, pkt_i=0):
        pfx = (d >> 8) << 8
        ctrs = self.bm.get(pfx)
        if ctrs is None:
            ctrs = self.bm[pfx] = array("I", [0]) * self.z
        for i in range(self.g):
            ctrs[bob_hash(_PACK("<I", d), 0xC100 + i) % self.z] += 1

    def _score(self, ctrs):
        m = sum(ctrs) / self.g                
        if m <= 0:
            return 0.0
        gz = self.g / self.z
        s = sum((c - m * gz) ** 2 for c in ctrs)
        fhat = s / (m * m * self.g * (1.0 - gz))
        fhat = min(max(fhat, 1.0 / 2 ** 16), 1.0)   
        return -math.log2(fhat)

    def query(self):
        return {pfx: self._score(ctrs) for pfx, ctrs in self.bm.items()}



def _build(method, budget_kb, n_pfx=None):
    
    if method == "segsketch":
        cols = max(2, budget_kb * 1024 // (SegSketch.R * SegSketch.BUCKET_BYTES))
        sk = SegSketch(cols)
        mem = SegSketch.R * cols * SegSketch.BUCKET_BYTES / 1024
        return sk, mem, f"r={SegSketch.R}×c={cols}"
    if method == "spreadsketch":
        cols = max(2, budget_kb * 1024 // (SpreadSketch.ROWS * (8 + SpreadSketch.M // 8)))
        sk = SpreadSketch(cols)
        mem = SpreadSketch.ROWS * cols * (8 + SpreadSketch.M // 8) / 1024
        return sk, mem, f"d={SpreadSketch.ROWS}×w={cols}×m={SpreadSketch.M}"
    if method == "couper":
        l1 = max(8, int(budget_kb * 1024 * Couper.MU * 8 / Couper.B))
        l2 = max(8, int(budget_kb * 1024 * (1 - Couper.MU) * 8 / Couper.HLL_BITS))
        tsc = max(64, l2)
        sk = Couper(l1, l2, tsc)
        bits = l1 * 16 + l2 * Couper.HLL_BITS + tsc * 48
        return sk, bits / 8192, f"L1={l1}×16b L2={l2}×HLL TSC={tsc}"
    if method == "rhhh":
        c = max(16, budget_kb * 1024 // (4 * 12))
        sk = RHHH(c)
        return sk, 4 * c * 12 / 1024, f"4layer×{c}counters"
    if method == "elastic":
        heavy_bytes = max(64, budget_kb * 1024 // 4)
        bn = max(1, heavy_bytes // 64)
        light_bytes = max(64, budget_kb * 1024 - bn * 64)
        sk = ElasticSketch(bn, light_bytes)
        return sk, (bn * 64 + light_bytes) / 1024, f"heavy={bn}×8cell light={light_bytes}B"
    if method == "heavykeeper":
        w = max(2, budget_kb * 1024 // (HeavyKeeper.D * 8))
        sk = HeavyKeeper(w)
        return sk, HeavyKeeper.D * w * 8 / 1024, f"d={HeavyKeeper.D}×w={w},top-{HeavyKeeper.K}"
    if method == "trw":
        n = max(16, budget_kb * 1024 // 8)
        sk = TRW(n)
        return sk, n * 8 / 1024, f"table cap ={n}source"
    if method == "mrb":
        n_pfx = max(n_pfx or 1, 1)
        per_pfx = max(4 * 8, budget_kb * 1024 * 8 // n_pfx)   
        b = max(8, per_pfx // 4)                              
        sk = MRB(b)
        return sk, n_pfx * (2 * b + sk.lastb) / 8192, f"per-/24: 2×{b}b+{sk.lastb}b"
    if method == "entropy":
        n_pfx = max(n_pfx or 1, 1)
        per_pfx = max(2 * 32, budget_kb * 1024 * 8 // n_pfx)  
        z = max(2, per_pfx // 32)
        sk = EntropySketch(z)
        return sk, n_pfx * z * 4 / 1024, f"per-/24: z={z}×32b g={sk.g}"
    if method == "lakhina":
        sk = Lakhina()
        return sk, 0.0, "exact (per-/24 dst→count)"


def run_method(method, flows, budget_kb):
    
    n_pfx = None
    if method in ("mrb", "entropy"):
        n_pfx = len({(d >> 8) << 8 for s, d, *_ in flows})
    sk, mem, structure = _build(method, budget_kb, n_pfx)
    for pkt_i, (s, d, *_) in enumerate(flows):
        sk.insert(s, d, pkt_i)
    scores = sk.query()
    if method == "lakhina":
        mem = sk.state_kb()
    return scores, mem, structure


def _gt_for(method, attack_srcs, attack_pfxs):
    return attack_srcs if method in SOURCE_METHODS else attack_pfxs



def _attack_file(task):
    
    fp, fn, max_pkts = task
    raw = read_pcap(fp, max_pkts)
    return fn, raw


def _benign_file(task):
    
    fp, fn, max_pkts = task
    return fn, read_pcap(fp, max_pkts)


def _worker_detect(task):
    
    flows, attack_srcs, attack_pfxs, method, budget_kb = task
    scores, mem, structure = run_method(method, flows, budget_kb)
    gt = _gt_for(method, attack_srcs, attack_pfxs)
    hi = max(scores.values()) if scores else 1.0
    best = None
    for i in range(201):                              
        r = eval_static(scores, gt, hi * i / 200)
        if best is None or r["f1"] > best["f1"]:
            best = r
    best.update(method=method, target="src IP" if method in SOURCE_METHODS else "/24 prefix",
                structure=structure, memory_kb=round(mem, 1), n_entities=len(scores),
                auc=_auc(scores, gt),
                precision=round(best["precision"], 3), recall=round(best["recall"], 3),
                f1=round(best["f1"], 3), tau=round(best["tau"], 2))
    return best


def _native_detect(method, sk, theta):
    
    if method == "segsketch":
        return sk.detect_native()
    if method == "trw":
        return {k for k, v in sk.query().items() if v >= TRW.ETA1}
    return {k for k, v in sk.query().items() if v >= theta}


def _build_benign_state(task):
    
    method, ben, budget_kb = task
    sk, _, _ = _build(method, budget_kb)
    if method in SOURCE_METHODS:
        for pkt_i, (s, d, *_) in enumerate(ben):
            sk.insert(s, d, pkt_i)
    else:
        for s, d, *_ in ben:
            sk.insert(s, d)
    return method, sk


def _spoof_rows(method, states, ben_len, theta, att, fname, atype, base24, agg,
                gt_srcs):
    
    rows = []
    for spoof in (0, 1):
        flows = ([(0xE0000000 + i, d, ts, rest[0] if rest else 0)
                  for i, (s, d, ts, *rest) in enumerate(att)] if spoof else att)
        sk = states[method].clone()
        for i, (s, d, *_) in enumerate(flows):
            sk.insert(s, d, ben_len + i)          
        det = _native_detect(method, sk, theta)
        tp = len(det & gt_srcs)
        prec, rec, f1 = _prf1(tp, len(det - gt_srcs), len(gt_srcs - det))
        rows.append({"file": fname, "type": atype,
                     "file_aggregation_ratio": round(agg, 4), "method": method,
                     "spoofed": spoof, "gt_entities": len(gt_srcs),
                     "detected": tp,
                     "precision": round(prec, 3), "recall": round(rec, 3),
                     "f1": round(f1, 3)})
    return rows


def _trw_rows(state, ben_len, att, fname, atype, base24, agg, gt_srcs):
    
    rows = []
    for spoof in (0, 1):
        flows = ([(0xE0000000 + i, d, ts, rest[0] if rest else 0)
                  for i, (s, d, ts, *rest) in enumerate(att)] if spoof else att)
        sk = state.clone()
        for i, (s, d, *_) in enumerate(flows):
            sk.insert(s, d, ben_len + i)
        det = {k for k, v in sk.query().items() if v >= TRW.ETA1}
        tp = len(det & gt_srcs)
        prec, rec, f1 = _prf1(tp, len(det - gt_srcs), len(gt_srcs - det))
        rows.append({"file": fname, "type": atype,
                     "file_aggregation_ratio": round(agg, 4), "method": "trw",
                     "spoofed": spoof, "gt_entities": len(gt_srcs),
                     "detected": tp,
                     "precision": round(prec, 3), "recall": round(rec, 3),
                     "f1": round(f1, 3)})
    return rows


def _worker_spoof(task):
    
    states, ben_len, ben_pairs_n, att, fname, atype, base24 = task
    srcs, src24s = set(), set()
    for s, *_ in att:
        srcs.add(s)
        src24s.add((s >> 8) << 8)
    agg = len(src24s) / max(len(srcs), 1)
    gt_srcs = srcs
    theta = 0.001 * (ben_pairs_n + len({(s, d) for s, d, *_ in att}))
    rows = []
    for method in ("segsketch", "spreadsketch", "couper"):   
        rows += _spoof_rows(method, states, ben_len, theta, att, fname, atype,
                            base24, agg, gt_srcs)
    n_stream = ben_len + len(att)
    for method in ("rhhh", "elastic", "heavykeeper"):
        sk = states[method].clone()
        for s, d, *_ in att:
            sk.insert(s, d)
        if method == "rhhh":
            det = {item for lv, item, *_ in sk.report(0.005 * n_stream) if lv == 1}
        else:   
            det = {p for p, v in sk.query().items() if v >= 0.005 * n_stream}
        gt = {base24}
        tp = len(det & gt)
        prec, rec, f1 = _prf1(tp, len(det - gt), len(gt - det))
        for spoof in (0, 1):
            rows.append({"file": fname, "type": atype,
                         "file_aggregation_ratio": round(agg, 4), "method": method,
                         "spoofed": spoof, "gt_entities": len(gt),
                         "detected": tp,
                         "precision": round(prec, 3), "recall": round(rec, 3),
                         "f1": round(f1, 3)})
    return rows


def _worker_memory(task):
    
    flows, attack_srcs, attack_pfxs, method, budgets = task
    gt = _gt_for(method, attack_srcs, attack_pfxs)
    rows = []
    for kb in budgets:
        scores, mem, structure = run_method(method, flows, kb)
        hi = max(scores.values()) if scores else 1.0
        best = None
        for i in range(201):
            r = eval_static(scores, gt, hi * i / 200)
            if best is None or r["f1"] > best["f1"]:
                best = r
        rows.append({"method": method, "structure": structure,
                     "memory_kb": round(mem, 1), "tau": round(best["tau"], 2),
                     "precision": round(best["precision"], 3),
                     "recall": round(best["recall"], 3),
                     "f1": round(best["f1"], 3)})
    return rows



def _fig15_flows():
    
    flows = []
    base = 0xC0A80000                                   
    for sub in range(4):
        for i in range(64):
            for j in range(2):
                flows.append((0x0A000001 + j, base + (sub << 8) + (sub * 64 + i), 0.0, 0))
    for j in range(3000):                               
        flows.append((0x0B000000 + j, base + (5 << 8) + 5, 0.0, 0))
    return flows, base


def _fig15_rows():
    
    flows, base = _fig15_flows()
    rows = []

    
    rhhh = RHHH(512)
    for s, d, *_ in flows:
        rhhh.insert(s, d)
    reps = {(lv, it) for lv, it, *_ in rhhh.report(0.005 * len(flows))}
    chain = {1: [base + (i << 8) for i in range(4)],     
             2: [base & pfx_mask(16)], 3: [base & pfx_mask(8)]}
    for lv, items in chain.items():
        for it in items:
            eff = rhhh._eff(lv, it)
            rows.append({"level": RHHH.PLENS[lv], "prefix": pfx_str(it, RHHH.PLENS[lv]),
                         "method": "rhhh", "score": round(eff, 1),
                         "lower": round(max(0.0, eff - rhhh.base[lv]), 1), "upper": eff,
                         "reported": 1 if (lv, it) in reps else 0, "gt": 1})
    for lv, it, eff, lower in rhhh.report(0.005 * len(flows)):     
        if any(r["method"] == "rhhh" and r["level"] == RHHH.PLENS[lv] and
               r["prefix"] == pfx_str(it, RHHH.PLENS[lv]) for r in rows):
            continue
        rows.append({"level": RHHH.PLENS[lv], "prefix": pfx_str(it, RHHH.PLENS[lv]),
                     "method": "rhhh", "score": round(eff, 1), "lower": round(lower, 1),
                     "upper": eff, "reported": 1, "gt": 0})
    return rows



def _synth_mixed():
    
    att = ([(0x0A000001, 0xC0000100 + i, 0.0, 0) for i in range(200)] +
           [(0x0A000002, 0xC0000100 + i, 0.0, 0) for i in range(200)])
    ben = []
    for b in range(4):
        base = 0xC1000000 + (b << 8)
        ben += [(0x0B000000 + b * 100 + j, base + 1, 0.0, 0) for j in range(10)]
        ben += [(0x0B000000 + b * 100 + 10 + j, base + 2, 0.0, 0) for j in range(10)]
        ben += [(0x0B000000 + b * 100 + 20 + j, base + 10 + j, 0.0, 0) for j in range(5)]
    return ben + att, {0x0A000001, 0x0A000002}, {0xC0000100}, ben, att


def selfcheck():
    
    flows, att_srcs, att_pfxs, ben, att = _synth_mixed()

    
    det_tasks = [(flows, att_srcs, att_pfxs, m, 64) for m in ALL_METHODS]
    det_rows = [r for r in parallel_map(_worker_detect, det_tasks, jobs=2, desc="selfcheck")]
    assert len(det_rows) == 10, det_rows
    for r in det_rows:
        assert r["f1"] == 1.0 and r["auc"] == 1.0, r
    p = save_csv("/tmp/02_baselines_detection_selfcheck.csv", det_rows,
                 ["method", "target", "structure", "memory_kb", "n_entities", "tau",
                  "tp", "fp", "fn", "tn", "precision", "recall", "f1", "auc"])
    assert os.path.exists(p)

    
    states = dict(_build_benign_state((m, ben, 512))
                  for m in SOURCE_METHODS + ("rhhh", "elastic", "heavykeeper"))
    trw_state = states.pop("trw")
    rows = _worker_spoof((states, len(ben), len({(s, d) for s, d, *_ in ben}),
                          att, "synth.pcap", "SYN-test", 0xC0000100))
    rows += _trw_rows(trw_state, len(ben), att, "synth.pcap", "SYN-test",
                      0xC0000100, 0.5, {0x0A000001, 0x0A000002})
    by = {(r["method"], r["spoofed"]): r for r in rows}
    assert by[("segsketch", 0)]["f1"] == 1.0, by       
    assert by[("segsketch", 1)]["recall"] == 0.0, by   
    assert by[("spreadsketch", 0)]["recall"] == 1.0 and by[("spreadsketch", 1)]["recall"] == 0.0
    assert by[("couper", 0)]["f1"] == 1.0 and by[("couper", 1)]["recall"] == 0.0
    assert by[("trw", 0)]["f1"] == 1.0, by            
    assert by[("trw", 1)]["recall"] == 0.0, by        
    assert by[("rhhh", 0)]["f1"] == by[("rhhh", 1)]["f1"]
    assert by[("elastic", 0)]["f1"] == by[("elastic", 1)]["f1"]
    assert by[("heavykeeper", 0)]["f1"] == by[("heavykeeper", 1)]["f1"]
    p = save_csv("/tmp/02_baselines_spoofing_selfcheck.csv", rows,
                 ["file", "type", "file_aggregation_ratio", "method", "spoofed",
                  "gt_entities", "detected", "precision", "recall", "f1"])
    assert os.path.exists(p)

    
    hrows = _fig15_rows()
    rep = {(r["level"], r["prefix"]) for r in hrows if r["method"] == "rhhh" and r["reported"]}
    assert (24, pfx_str(0xC0A80500)) in rep, rep        
    assert (24, pfx_str(0xC0A80000)) in rep, rep        
    p = save_csv("/tmp/02_baselines_hierarchy_selfcheck.csv", hrows,
                 ["level", "prefix", "method", "score", "lower", "upper", "reported", "gt"])
    assert os.path.exists(p)

    
    mem_rows = [r for m in MEMORY_METHODS
                for r in _worker_memory((flows, att_srcs, att_pfxs, m, [32, 128]))]
    assert len(mem_rows) == 18, mem_rows
    p = save_csv("/tmp/02_baselines_memory_selfcheck.csv", mem_rows,
                 ["method", "structure", "memory_kb", "tau", "precision", "recall", "f1"])
    assert os.path.exists(p)
    print("p4 self-check ok: E1 F1/AUC=1.0, E2 spoofed sources collapse / destination side unchanged, E3 RHHH hierarchy, E4 grid written")



def main():
    ap = base_argparser("P4 — baseline comparison (9 baselines reproduced; CSV behind the paper's baseline tables)")
    ap.add_argument("--outdir", default=None, help="CSV output directory (default <repo>/results)")
    ap.add_argument("--budget-kb", type=int, default=512, help="shared memory budget of the E1 main table (KB)")
    ap.add_argument("--budgets", default="32,64,128,256,512,1024",
                    help="E4 memory grid in KB (comma-separated)")
    ap.add_argument("--selfcheck", action="store_true", help="self-check on synthetic data (reads no pcap)")
    args = ap.parse_args()
    if args.selfcheck:
        selfcheck()
        return
    outdir = args.outdir or os.path.join(ROOT, "results")
    t_start = time.time()

    print("=" * 72 + "\nP4: baseline comparison — 10 baselines (SegSketch/SpreadSketch/Couper/TRW/Elastic/"
          "HeavyKeeper/RHHH/MRB/Lakhina/EntropySketch)\n" + "=" * 72)

    
    adir = os.path.join(args.db, "attack", "normal_single24")
    atasks = [(os.path.join(adir, f), f, args.attack_max)
              for f in sorted(os.listdir(adir)) if f.endswith(".pcap")]
    print(f"\n[Attack] {len(atasks)} pcaps")
    ares = [(fn, raw) for fn, raw in parallel_map(_attack_file, atasks, args.jobs, desc="attack")
            if raw]
    ares.sort(key=lambda x: x[0])       
    attack_parts, att_by_file, attack_srcs, attack_pfxs = [], {}, set(), set()
    for fi, (fn, raw) in enumerate(ares):
        base24, atype, _ = attack_file_meta(fn)
        attack_parts.append([(s, d, ts, fi) for s, d, ts in raw])
        att_by_file[fn] = {"flows": raw, "type": atype, "base24": base24}
        attack_srcs |= {s for s, *_ in raw}
        if base24:
            attack_pfxs.add(base24)

    bdir = os.path.join(args.db, "benign")
    btasks = [(os.path.join(bdir, f), f, args.benign_max)
              for f in args.benign_files.split(",")
              if os.path.exists(os.path.join(bdir, f.strip()))]
    print(f"\n[Benign] {len(btasks)} pcaps")
    bres = [(fn, raw) for fn, raw in parallel_map(_benign_file, btasks, args.jobs, desc="benign")
            if raw]
    bres.sort(key=lambda x: x[0])
    benign_parts = [[(s, d, ts, fi) for s, d, ts in raw] for fi, (fn, raw) in enumerate(bres)]
    benign_flows = stitch_flows(benign_parts)
    all_flows = stitch_flows(benign_parts + attack_parts)
    n_att = sum(len(p) for p in attack_parts)
    n_ben = sum(len(p) for p in benign_parts)
    print(f"\n  mixed traffic: attack {n_att} packets / {len(attack_srcs)} sources / {len(attack_pfxs)} /24"
          f" + benign {n_ben} packets ({len(benign_parts)} files)")

    
    print(f"\n[E1] detection main table (shared {args.budget_kb}KB budget, best-τ grid)")
    det_tasks = [(all_flows, attack_srcs, attack_pfxs, m, args.budget_kb) for m in ALL_METHODS]
    det_rows = [r for r in parallel_map(_worker_detect, det_tasks, args.jobs, desc="E1")]
    det_rows.sort(key=lambda r: -r["f1"])
    save_csv(os.path.join(outdir, "02_baselines_detection.csv"), det_rows,
             ["method", "target", "structure", "memory_kb", "n_entities", "tau",
              "tp", "fp", "fn", "tn", "precision", "recall", "f1", "auc"])
    print(f"  {'method':<14}{'target':<12}{'memKB':>8}{'τ':>7}{'P':>7}{'R':>7}{'F1':>7}{'AUC':>7}")
    for r in det_rows:
        print(f"  {r['method']:<14}{r['target']:<12}{r['memory_kb']:>8.0f}{r['tau']:>7.2f}"
              f"{r['precision']:>7.3f}{r['recall']:>7.3f}{r['f1']:>7.3f}{r['auc']:>7.3f}")

    
    print(f"\n[E2] source-IP spoofing robustness ({len(ares)} files × 7 methods: 4 source-side × real/spoofed + 3 destination-side flat)")
    print("  [E2a] benign final state: insert the benign stream once per method (per-file state copy + attack replay)")
    state_tasks = [(m, benign_flows, 512) for m in
                   SOURCE_METHODS + ("rhhh", "elastic", "heavykeeper")]
    states = {m: sk for m, sk in parallel_map(_build_benign_state, state_tasks,
                                              args.jobs, desc="E2 states")}
    trw_state = states.pop("trw")
    ben_pairs_n = len({(s, d) for s, d, *_ in benign_flows})
    spoof_tasks = [(states, len(benign_flows), ben_pairs_n,
                    att_by_file[fn]["flows"], fn, att_by_file[fn]["type"],
                    att_by_file[fn]["base24"]) for fn, _ in ares]
    spoof_rows = [r for rows in parallel_map(_worker_spoof, spoof_tasks, args.jobs,
                                             desc="E2")
                  for r in rows]
    print("  [E2b] TRW replayed serially in the main process (pairs/seen state too large for the pool)")
    trw_rows = []
    for fn, _ in ares:
        att = att_by_file[fn]["flows"]
        srcs = {s for s, *_ in att}
        agg = len({(s >> 8) << 8 for s in srcs}) / max(len(srcs), 1)
        trw_rows += _trw_rows(trw_state, len(benign_flows), att, fn,
                              att_by_file[fn]["type"], att_by_file[fn]["base24"],
                              agg, srcs)
    spoof_rows += trw_rows
    
    type_agg = {}
    p0f = os.path.join(outdir, "01_dataset_table1_attack_stats.csv")
    if os.path.exists(p0f):
        with open(p0f, newline="") as f:
            for row in csv.DictReader(f):
                type_agg[row["attack_type"]] = row["mean_src24_aggregation_ratio"]
    for r in spoof_rows:
        r["type_aggregation_ratio"] = type_agg.get(r["type"], "")
    save_csv(os.path.join(outdir, "02_baselines_spoofing.csv"), spoof_rows,
             ["file", "type", "file_aggregation_ratio", "type_aggregation_ratio", "method",
              "spoofed", "gt_entities", "detected", "precision", "recall", "f1"])
    print("  per-type means (real-source / spoofed-source F1; destination-side methods list real sources only):")
    by_type = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for r in spoof_rows:
        by_type[r["type"]][r["method"]][r["spoofed"]].append(r["f1"])
    print(f"  {'type':<32}" + "".join(f"{m:>16}" for m in ("segsketch", "spreadsketch",
          "couper", "trw")))
    for t in sorted(by_type):
        m = by_type[t]
        cells = []
        for method in ("segsketch", "spreadsketch", "couper", "trw"):
            n0 = max(len(m[method][0]), 1)
            cells.append(f"{sum(m[method][0]) / n0:.2f}/{sum(m[method][1]) / n0:.2f}")
        print(f"  {t:<32}" + "".join(f"{c:>16}" for c in cells))

    
    print("\n[E3] hierarchy philosophy: RHHH volume hierarchy vs SIUP uniformity breakpoint on a /22 staggered attack")
    hier_rows = _fig15_rows()
    save_csv(os.path.join(outdir, "02_baselines_hierarchy.csv"), hier_rows,
             ["level", "prefix", "method", "score", "lower", "upper", "reported", "gt"])
    siup_rep = [r for r in hier_rows if r["method"] == "siup" and r["reported"]]
    rhhh_rep = [r for r in hier_rows if r["method"] == "rhhh" and r["reported"]
                and r["level"] <= 24]                 
    print(f"  SIUP report {len(siup_rep)} entries: " + ", ".join(f"{r['prefix']} (E_u={r['score']})"
          for r in siup_rep))
    print(f"  RHHH report {len(rhhh_rep)} entries: " + ", ".join(f"{r['prefix']} (vol={r['score']})"
          for r in rhhh_rep))

    
    budgets = [int(b) for b in args.budgets.split(",")]
    print(f"\n[E4] memory-F1 (shared grid {budgets} KB × {len(MEMORY_METHODS)} methods)")
    mem_tasks = [(all_flows, attack_srcs, attack_pfxs, m, budgets) for m in MEMORY_METHODS]
    mem_rows = [r for rows in parallel_map(_worker_memory, mem_tasks, args.jobs, desc="E4")
                for r in rows]
    save_csv(os.path.join(outdir, "02_baselines_memory.csv"), mem_rows,
             ["method", "structure", "memory_kb", "tau", "precision", "recall", "f1"])
    print(f"  {'method':<14}" + "".join(f"{kb:>9}KB" for kb in budgets))
    for m in MEMORY_METHODS:
        mr = sorted((r for r in mem_rows if r["method"] == m), key=lambda r: r["memory_kb"])
        print(f"  {m:<14}" + "".join(f"{r['f1']:>11.3f}" for r in mr))

    print(f"\nelapsed {time.time() - t_start:.0f}s")


if __name__ == "__main__":
    main()
