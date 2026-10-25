import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sweepsketch import config
from sweepsketch.digest import Collector
from sweepsketch.epoch import epoch_of
from sweepsketch.sketch import Level, SweepSketch
HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.normpath(os.environ.get('SWEEPSKETCH_DB', os.path.join(HERE, '..', '..', 'database')))
ATT_DIR = os.path.join(DB, 'attack', 'normal_single24')
TRACE_EXTS = ('.pcap', '.pcapng', '.csv', '.csv.gz')
BENIGN = os.path.join(DB, 'benign', 'CIC-IDS-2017-Benign.pcap')
RES = os.path.normpath(os.environ.get('SWEEPSKETCH_RES', os.path.join(HERE, '..', '..', 'results')))
STAGGER = 12.0
EXP4_TARGETS = [3232238080, 2899905024, 2899905536, 918562048, 599450368, 1546480128]
WORKERS = int(os.environ.get('SWEEPSKETCH_WORKERS', '4'))
DUMMY = Collector()
config_defaults = {k: v for k, v in vars(config).items() if k.isupper() and (not k.startswith('_'))}

def ip24(s):
    a, b, c, _ = s.split('.')
    return int(a) << 24 | int(b) << 16 | int(c) << 8

def make_sketch(theta0, budget_kb):
    total = budget_kb * 1024 // 44
    n1 = total * 2 // 3
    sk = SweepSketch(theta0)
    sk.l1 = Level(n1, lambda d: d >> 8 << 8, 17)
    sk.l2 = Level(total - n1, lambda d: d >> 16 << 16, 34)
    return sk

def _fold(stats, key, r):
    s = stats.setdefault(key, [-1, 0])
    if r[2] > s[0]:
        s[0] = r[2]
    if r[4] >= max(config.P_MIN, config.D2_MULT * r[3]) and r[1] >= max(config.K_FLOOD, 2 * r[0]) and r[7]:
        s[1] = 1

def _d1_gate(b):
    q = 2 * b.n_ewma
    return max(config.K_ALARM, q, config.K_ALARM_QUIET if b.n_ewma < config.N_EWMA_QUIET else 0)

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
            r[2], r[5] = (b.C, 1)
        return
    r[1] = b.n_new
    r[4] = b.pkt
    if not r[5] and b.n_new >= _d1_gate(b):
        r[2], r[5] = (b.C, 1)
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
    return sorted((f for f in os.listdir(ATT_DIR) if f.lower().endswith(TRACE_EXTS)))

def f1_of(flagged, gt_attack, gt_benign):
    tp = sum((1 for p in gt_attack if flagged.get(p)))
    fp = sum((1 for p in gt_benign if flagged.get(p)))
    fn = len(gt_attack) - tp
    return (tp, fp, fn, 2 * tp / (2 * tp + fn + fp) if 2 * tp + fn + fp else 0.0)

def h_flag(scale):
    return lambda s: s[0] >= round(scale * 8) or s[1]

def run_selfcheck():
    from sweepsketch.selfcheck_all import run as sca
    sca()
    sk = make_sketch(config.THETA0, 512)
    stats, cur = ({}, {})
    for i in range(600):
        d = 174325765 if i < 500 else 174325770 + i % 5
        feed(sk, stats, cur, 0, d, 1.0 + i * 1e-06, DUMMY)
    flush(stats, cur)
    s = stats.get((1, 174325760))
    assert s is not None and s[0] < config.H_FP, s
    pass
