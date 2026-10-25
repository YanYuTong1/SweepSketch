from . import config

class CrossPrefixCorrelator:
    __slots__ = ('W', 'K', 'floor', 'cooldown_win', '_hits', '_last', 'stats')

    def __init__(self, W=None, K=None, floor=None, cooldown_win=None):
        self.W = config.CROSS_W if W is None else W
        self.K = config.CROSS_K if K is None else K
        self.floor = config.CROSS_NNEW_FLOOR if floor is None else floor
        self.cooldown_win = config.COOLDOWN_WIN if cooldown_win is None else cooldown_win
        self._hits = {}
        self._last = {}
        self.stats = {'n12': 0, 'd1': 0, 'windows': 0, 'dist_emitted': 0, 'dist_suppressed_cooldown': 0}

    @staticmethod
    def pfx16_of(key24):
        return key24 >> 16 << 16

    def _prune(self, e):
        if len(self._hits) <= self.W + 2:
            return
        lo = e - self.W
        for e0 in [x for x in self._hits if x <= lo]:
            del self._hits[e0]

    def observe(self, a):
        from .digest import Alert
        if a.level != 1:
            return []
        if a.reason == 'N12':
            if a.k < self.floor:
                return []
            self.stats['n12'] += 1
        elif a.reason == 'D1':
            self.stats['d1'] += 1
        else:
            return []
        e = a.epoch
        hit = self._hits.get(e)
        if hit is None:
            hit = self._hits[e] = {}
            self.stats['windows'] += 1
            self._prune(e)
        p16 = self.pfx16_of(a.key)
        hit.setdefault(p16, set()).add(a.key)
        lo = e - self.W + 1
        union = set()
        for e0, h in self._hits.items():
            if lo <= e0 <= e:
                union.update(h)
        out = []
        if len(union) >= self.K:
            for p in hit:
                last = self._last.get(p)
                if last is not None and 0 <= e - last < self.cooldown_win:
                    self.stats['dist_suppressed_cooldown'] += 1
                    continue
                self._last[p] = e
                out.append(Alert(3, p, len(union), 0, 0, e, 'DIST', a.ts))
                self.stats['dist_emitted'] += 1
        return out
if __name__ == '__main__':
    from .digest import Alert
    cx = CrossPrefixCorrelator(W=4, K=2)
    assert cx.observe(Alert(1, 174326016, 32, 500, 200, 100, 'N12')) == []
    out = cx.observe(Alert(1, 174391552, 32, 500, 200, 101, 'N12'))
    assert len(out) == 1 and out[0].reason == 'DIST' and (out[0].level == 3)
    assert out[0].key == 174391296 and out[0].k == 2
    cx = CrossPrefixCorrelator(W=4, K=2)
    cx.observe(Alert(1, 174326016, 16, 500, 200, 100, 'D1'))
    assert cx.observe(Alert(1, 174326272, 16, 500, 200, 101, 'D1')) == []
    assert cx.observe(Alert(1, 174326528, 16, 500, 200, 102, 'D1')) == []
    cx = CrossPrefixCorrelator(W=4, K=2)
    cx.observe(Alert(1, 174326016, 32, 500, 200, 100, 'N12'))
    assert cx.observe(Alert(1, 174391552, 32, 500, 200, 105, 'N12')) == []
    out = cx.observe(Alert(1, 174457088, 32, 500, 200, 106, 'N12'))
    assert len(out) == 1 and out[0].k == 2
    cx = CrossPrefixCorrelator(W=8, K=2, cooldown_win=20)
    cx.observe(Alert(1, 174326016, 32, 500, 200, 100, 'N12'))
    out1 = cx.observe(Alert(1, 174391552, 32, 500, 200, 101, 'N12'))
    out2 = cx.observe(Alert(1, 174391808, 32, 500, 200, 102, 'N12'))
    assert len(out1) == 1 and out1[0].key == 174391296
    assert len(out2) == 0 or all((o.key != 174391296 for o in out2))
    print('cross16 self-check ok:', cx.stats)
