from . import config
from .bucket import Bucket
from .digest import Alert
from .epoch import epoch_full, epoch_of
from .hash import pfx_hash
from .llr import make_llr_table

def _hll_r_rho(d):
    h = pfx_hash(d, 51)
    r = h & config.HLL_M - 1
    v = h >> 5
    rho = 27 - v.bit_length()
    return (r, rho)

class Level:

    def __init__(self, nb, key_of, seed):
        self.nb, self.key_of, self.seed = (nb, key_of, seed)
        self.buckets = [None] * nb

    def idx(self, key):
        return pfx_hash(key, self.seed) % self.nb

class SweepSketch:

    def __init__(self, theta0=config.THETA0):
        self.l1 = Level(config.N_L1, lambda d: d >> 8 << 8, 17)
        self.l2 = Level(config.N_L2, lambda d: d >> 16 << 16, 34)
        self.llr = make_llr_table(theta0)

    def process(self, s, d, ts, collector):
        g = epoch_of(ts)
        gf = epoch_full(ts)
        r, rho = _hll_r_rho(d)
        self._up(self.l1, self.l1.key_of(d), r, rho, 1, g, gf, ts, collector)
        if config.USE_L2:
            self._up(self.l2, self.l2.key_of(d), r, rho, 2, g, gf, ts, collector)

    def _up(self, level, key, r, rho, lvl, g, gf, ts, collector):
        i = level.idx(key)
        b = level.buckets[i]
        if b is None:
            b = level.buckets[i] = Bucket(key, g)
        elif b.key != key:
            replace = b.pkt < config.P_MIN and b.C < config.H_FP
            if not replace and config.AGE_ENABLE:
                replace = g - b.epoch & 31 >= config.AGE_WIN
            if not replace:
                return
            b = level.buckets[i] = Bucket(key, g)
        prev_nnew = b.n_new
        a1, a2, _ = b.process(r, rho, g, self.llr)
        if a1:
            collector.add(Alert(lvl, key, b.n_new, b.C, b.pkt, gf, 'D1', ts))
        if a2:
            collector.add(Alert(lvl, key, b.n_new, b.C, b.pkt, gf, 'D2', ts))
        if config.CROSS16 and lvl == 1 and (prev_nnew < config.CROSS_NNEW_FLOOR <= b.n_new):
            collector.add(Alert(lvl, key, b.n_new, b.C, b.pkt, gf, 'N12', ts))
if __name__ == '__main__':
    from .digest import Collector
    _cross16 = config.CROSS16
    config.CROSS16 = False
    sk = SweepSketch()
    c = Collector()
    ts = 0.0
    for p24 in range(4):
        for dst in range(20):
            sk.process(16909056, 3232235520 + (p24 << 8) + dst, ts, c)
            ts += 0.0001
    a1s = [a for a in c.alerts if a.level == 1 and a.reason == 'D1']
    a2s = [a for a in c.alerts if a.level == 2 and a.reason == 'D1']
    assert len(a1s) == 4, len(a1s)
    assert len(a2s) == 1, len(a2s)
    assert all((a.k >= 8 for a in a1s)) and a2s[0].k >= 8
    sk2 = SweepSketch()
    c2 = Collector()
    for e in range(2):
        ts = e * 4.3
        for p24 in range(4):
            for dst in range(16):
                for _ in range(13):
                    sk2.process(16909056, 3232235520 + (p24 << 8) + dst, ts, c2)
                    ts += 0.0001
    b1 = [a for a in c2.alerts if a.level == 1 and a.reason == 'D1']
    d2l1 = [a for a in c2.alerts if a.level == 1 and a.reason == 'D2']
    d2l2 = [a for a in c2.alerts if a.level == 2 and a.reason == 'D2']
    assert len(b1) == 0, b1
    assert len(d2l1) == 4 and len(d2l2) == 1, (len(d2l1), len(d2l2))
    lv = Level(1, lambda d: d >> 8 << 8, 17)
    sk2b = SweepSketch()
    sk2b.l1 = lv
    c3 = Collector()
    for i in range(512):
        sk2b.process(0, 167772416 + i % 256, 0.0, c3)
    hot = lv.buckets[0]
    assert hot.pkt == 512 and hot.key == 167772416
    for _ in range(100):
        sk2b.process(0, 184549893, 0.0, c3)
    assert lv.buckets[0].key == 167772416 and lv.buckets[0].pkt == 512
    lv2 = Level(1, lambda d: d >> 8 << 8, 17)
    sk3 = SweepSketch()
    sk3.l1 = lv2
    for _ in range(100):
        sk3.process(0, 201327109, 0.0, c3)
    assert lv2.buckets[0].key == 201327104
    sk3.process(0, 218104065, 0.0, c3)
    assert lv2.buckets[0].key == 218104064
    sk4 = SweepSketch()
    c4 = Collector()
    ts = 0.0
    for e in range(12):
        t0 = e * 4.3
        for i in range(1024):
            sk4.process(0, 3325231104 + i % 256, t0 + i % 1024 * 1e-06, c4)
        if e >= 3:
            for i in range(2048):
                sk4.process(0, 2130706688 + i % 256, t0 + 3.0 + i * 1e-06, c4)

    def sets(key):
        d1 = {a.epoch for a in c4.alerts if a.level == 1 and a.key == key and (a.reason == 'D1')}
        d2 = {a.epoch for a in c4.alerts if a.level == 1 and a.key == key and (a.reason == 'D2')}
        return (d1, d2)
    cdn1, cdn2 = sets(3325231104)
    assert cdn1 == {0, 1, 2, 3, 4, 5}, cdn1
    assert cdn2 == set(), cdn2
    assert cdn1 | cdn2 == {0, 1, 2, 3, 4, 5}
    atk1, atk2 = sets(2130706688)
    assert atk1 == {3, 4, 5, 6, 7, 8}, atk1
    assert atk2 == set(), atk2
    assert atk1 | atk2 == {3, 4, 5, 6, 7, 8}
    config.CROSS16 = _cross16
    print('sketch self-check ok; cdn D1=%s D2=%s; atk D1=%s D2=%s' % (sorted(cdn1), sorted(cdn2), sorted(atk1), sorted(atk2)))
