class Alert:
    __slots__ = ('level', 'key', 'k', 'C', 'pkt', 'epoch', 'reason', 'ts')

    def __init__(self, level, key, k, C, pkt, epoch, reason, ts=None):
        self.level, self.key, self.k = (level, key, k)
        self.C, self.pkt, self.epoch = (C, pkt, epoch)
        self.reason, self.ts = (reason, ts)

    def __repr__(self):
        return f'Alert(level={self.level}, key={self.key:#x}, k={self.k}, C={self.C}, pkt={self.pkt}, epoch={self.epoch}, {self.reason})'

class Collector:

    def __init__(self, keep_reason=False):
        self.alerts = []
        self._seen = set()
        self._keep_reason = keep_reason

    def add(self, a):
        kk = (a.level, a.key, a.epoch, a.reason) if self._keep_reason else (a.level, a.key, a.epoch)
        if kk in self._seen:
            return
        self._seen.add(kk)
        self.alerts.append(a)

    def n_prefixes(self):
        return len(set(((a.level, a.key) for a in self.alerts)))

    def by_reason(self, reason):
        return [a for a in self.alerts if a.reason == reason]
if __name__ == '__main__':
    c = Collector()
    c.add(Alert(1, 167772416, 16, 416, 16, 0, 'D1'))
    c.add(Alert(1, 167772416, 17, 442, 17, 0, 'D1'))
    c.add(Alert(2, 167772160, 64, 1664, 64, 0, 'D1'))
    c.add(Alert(1, 167772416, 16, 416, 16, 1, 'D1'))
    assert len(c.alerts) == 3 and c.n_prefixes() == 2
    assert len(c.by_reason('D1')) == 3
    c2 = Collector(keep_reason=True)
    c2.add(Alert(1, 167772416, 16, 416, 16, 0, 'D1'))
    c2.add(Alert(1, 167772416, 12, 420, 300, 0, 'D2'))
    c2.add(Alert(1, 167772416, 12, 420, 300, 0, 'D2'))
    assert len(c2.alerts) == 2, len(c2.alerts)
    print('digest self-check ok')
