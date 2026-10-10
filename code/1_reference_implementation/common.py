
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sweepsketch import config
from sweepsketch.digest import Collector
from sweepsketch.epoch import epoch_of
from sweepsketch.sketch import Level, SweepSketch

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.normpath(os.path.join(HERE, "..", "..", "database"))
ATT_DIR = os.path.join(DB, "attack", "normal_single24")
BENIGN = os.path.join(DB, "benign", "CIC-IDS-2017-Benign.pcap")
RES = os.path.join(HERE, "..", "..", "results", "csv")
STAGGER = 12.0                       
EXP4_TARGETS = [0xC0A80A00, 0xACD90A00, 0xACD90C00, 0x36C02500, 0x23BAE300, 0x5C2D6A00]


DUMMY = Collector()                  
config_defaults = {k: v for k, v in vars(config).items()
                   if k.isupper() and not k.startswith("_")}   


def ip24(s):
    a, b, c, _ = s.split(".")
    return (int(a) << 24) | (int(b) << 16) | (int(c) << 8)


def make_sketch(theta0, budget_kb):
    total = budget_kb * 1024 // 44
    n1 = total * 2 // 3
    sk = SweepSketch(theta0)
    sk.l1 = Level(n1, lambda d: (d >> 8) << 8, 0x11)
    sk.l2 = Level(total - n1, lambda d: (d >> 16) << 16, 0x22)
    return sk


def _fold(stats, key, r):
    s = stats.setdefault(key, [-1, 0])      
    if r[2] > s[0]:                         
        s[0] = r[2]
    
    if r[4] >= max(config.P_MIN, config.D2_MULT * r[3]) and \
            r[1] >= max(config.K_FLOOD, 2 * r[0]) and r[7]:
        s[1] = 1


def _d1_gate(b):
    q = 2 * b.n_ewma
    return max(config.K_ALARM, q,
               config.K_ALARM_QUIET if b.n_ewma < config.N_EWMA_QUIET else 0)


def _rec(stats, cur, b, key, lvl, e_old, g):
    
    if b is None or b.key != key:
        return                      
    k = (lvl, key)
    r = cur.get(k)
    if r is None or b.epoch != e_old:       
        if r is not None:
            _fold(stats, k, r)
        r = [b.n_ewma, b.n_new, -1, b.pkt_ewma, b.pkt, 0, b.win, b.d2_held]
        cur[k] = r
        if b.n_new >= _d1_gate(b):
            r[2], r[5] = b.C, 1
        return
    r[1] = b.n_new
    r[4] = b.pkt
    if not r[5] and b.n_new >= _d1_gate(b):
        r[2], r[5] = b.C, 1
    elif r[5] and b.C > r[2]:
        r[2] = b.C


def feed(sk, stats, cur, s, d, ts, collector):
    g = epoch_of(ts)
    key1 = sk.l1.key_of(d)
    key2 = sk.l2.key_of(d)
    i1 = sk.l1.idx(key1)
    i2 = sk.l2.idx(key2)
    e1o = sk.l1.buckets[i1].epoch if sk.l1.buckets[i1] is not None else -1
    e2o = sk.l2.buckets[i2].epoch if sk.l2.buckets[i2] is not None else -1
    sk.process(s, d, ts, collector)
    _rec(stats, cur, sk.l1.buckets[i1], key1, 1, e1o, g)
    _rec(stats, cur, sk.l2.buckets[i2], key2, 2, e2o, g)


def flush(stats, cur):
    for key, r in cur.items():
        _fold(stats, key, r)
    cur.clear()


def attack_files():
    return sorted(f for f in os.listdir(ATT_DIR) if f.endswith(".pcap"))


def f1_of(flagged, gt_attack, gt_benign):
    tp = sum(1 for p in gt_attack if flagged.get(p))
    fp = sum(1 for p in gt_benign if flagged.get(p))
    fn = len(gt_attack) - tp
    return tp, fp, fn, (2 * tp / (2 * tp + fn + fp)) if (2 * tp + fn + fp) else 0.0


def h_flag(scale):
    return lambda s: s[0] >= round(scale * 8) or s[1]
