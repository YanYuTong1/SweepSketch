from .digest import Collector
from .sketch import SweepSketch
CDN, OFF, ATK = (3325231104, 174325760, 2130706688)

def run():
    sk = SweepSketch()
    c = Collector()
    ts = 0.0
    for e in range(8):
        t0 = e * 4.3
        for i in range(1024):
            sk.process(0, CDN + i % 256, t0 + i % 1024 * 1e-06, c)
        for i in range(500):
            sk.process(0, OFF + 5, t0 + 1.0 + i * 1e-06, c)
        for i in range(100):
            sk.process(0, OFF + 10 + i % 5, t0 + 2.0 + i * 1e-06, c)
        if e >= 3:
            for i in range(2048):
                sk.process(0, ATK + i % 256, t0 + 3.0 + i * 1e-06, c)

    def sets(level, key):
        d1 = {a.epoch for a in c.alerts if a.level == level and a.key == key and (a.reason == 'D1')}
        d2 = {a.epoch for a in c.alerts if a.level == level and a.key == key and (a.reason == 'D2')}
        return (d1, d2)
    d1, d2 = sets(2, CDN)
    assert d1 == {0, 1, 2, 3, 4, 5} and d2 == set(), (d1, d2)
    d1, d2 = sets(1, OFF)
    assert d1 == set() and d2 == {1, 2, 3}, (d1, d2)
    d1, d2 = sets(1, ATK)
    assert d1 == {3} and d2 == set(), (d1, d2)
    n12 = {a.epoch for a in c.alerts if a.level == 1 and a.key == ATK and (a.reason == 'N12')}
    assert n12 == {4, 5, 6, 7}, n12
    print('selfcheck_all ok:', 'cdn L2 D1=%s' % sorted(sets(2, CDN)[0]), '| off L1 D2=%s' % sorted(sets(1, OFF)[1]), '| atk L1 D1=%s N12=%s' % (sorted(sets(1, ATK)[0]), sorted(n12)))
if __name__ == '__main__':
    run()
