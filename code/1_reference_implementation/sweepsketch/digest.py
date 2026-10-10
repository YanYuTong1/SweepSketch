


class Alert:
    __slots__ = ("level", "key", "k", "C", "pkt", "epoch", "reason", "ts")

    def __init__(self, level, key, k, C, pkt, epoch, reason, ts=None):
        self.level, self.key, self.k = level, key, k
        self.C, self.pkt, self.epoch = C, pkt, epoch
        self.reason, self.ts = reason, ts

    def __repr__(self):
        return (f"Alert(level={self.level}, key={self.key:#x}, k={self.k}, "
                f"C={self.C}, pkt={self.pkt}, epoch={self.epoch}, {self.reason})")


class Collector:
    def __init__(self):
        self.alerts = []
        self._seen = set()

    def add(self, a):
        kk = (a.level, a.key, a.epoch)
        if kk in self._seen:
            return
        self._seen.add(kk)
        self.alerts.append(a)

    def n_prefixes(self):
        return len(set((a.level, a.key) for a in self.alerts))

    def by_reason(self, reason):
        return [a for a in self.alerts if a.reason == reason]


if __name__ == "__main__":
    c = Collector()
    c.add(Alert(1, 0x0A000100, 16, 416, 16, 0, "D1"))
    c.add(Alert(1, 0x0A000100, 17, 442, 17, 0, "D1"))   
    c.add(Alert(2, 0x0A000000, 64, 1664, 64, 0, "D1"))
    c.add(Alert(1, 0x0A000100, 16, 416, 16, 1, "D1"))   
    assert len(c.alerts) == 3 and c.n_prefixes() == 2
    assert len(c.by_reason("D1")) == 3
    print("digest self-check ok")
