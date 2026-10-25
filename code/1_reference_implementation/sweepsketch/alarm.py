from . import config

class AlarmManager:
    __slots__ = ('confirm', 'cooldown_win', 'quarantine', '_d2', '_last', '_eps', '_q', 'stats')

    def __init__(self, confirm=None, cooldown_win=None, quarantine=None):
        self.confirm = config.ALARM_CONFIRM if confirm is None else confirm
        self.cooldown_win = config.COOLDOWN_WIN if cooldown_win is None else cooldown_win
        self.quarantine = config.QUARANTINE if quarantine is None else quarantine
        self._d2 = {}
        self._last = {}
        self._eps = {}
        self._q = {}
        self.stats = {'raw_processed': 0, 'd2_unconfirmed': 0, 'd2_confirmed': 0, 'suppressed_cooldown': 0, 'suppressed_quarantine': 0, 'emitted': 0, 'quarantined': 0}

    @staticmethod
    def _key(a):
        return (a.level, a.key)

    def _d2_ok(self, a):
        if not self.confirm or a.reason != 'D2':
            return True
        h = self._d2.get(self._key(a))
        if h is None:
            h = self._d2[self._key(a)] = []
        h.append(a.epoch)
        if len(h) > 8:
            del h[:-8]
        lo = a.epoch - (config.D2_CONFIRM_WINDOWS - 1)
        recent = {e for e in h if lo <= e <= a.epoch}
        if len(recent) < config.D2_CONFIRM_COUNT:
            self.stats['d2_unconfirmed'] += 1
            return False
        self.stats['d2_confirmed'] += 1
        return True

    def _attack_evidence(self, recent, a):
        ks = [e[2] for e in recent]
        if ks and max(ks) > config.Q_MAX_K:
            return True
        m = config.Q_GROWTH_MULT
        if m > 0 and len(ks) >= 3 and (ks[-1] > m * max(1, ks[0])):
            return True
        if config.Q_REQUIRE_NO_D1 and any((e[1] == 'D1' for e in recent)):
            return True
        return False

    def process(self, a):
        if a.reason not in ('D1', 'D2', 'DIST'):
            return None
        self.stats['raw_processed'] += 1
        k2 = self._key(a)
        if not self._d2_ok(a):
            return None
        exp = self._q.get(k2)
        if self.quarantine and exp is not None and (a.epoch < exp):
            self.stats['suppressed_quarantine'] += 1
            return None
        last = self._last.get(k2)
        if last is not None and 0 <= a.epoch - last < self.cooldown_win:
            self.stats['suppressed_cooldown'] += 1
            return None
        self._last[k2] = a.epoch
        eps = self._eps.get(k2)
        if eps is None:
            eps = self._eps[k2] = []
        eps.append((a.epoch, a.reason, a.k))
        if len(eps) > 64:
            del eps[:-64]
        if self.quarantine:
            lo = a.epoch - config.Q_LOOKBACK_WIN
            recent = [e for e in eps if lo <= e[0] <= a.epoch]
            if len(recent) >= config.Q_EPISODES and (not self._attack_evidence(recent, a)):
                self._q[k2] = a.epoch + config.Q_WINDOW_WIN
                self.stats['quarantined'] += 1
        self.stats['emitted'] += 1
        return a

    def is_quarantined(self, level, key, epoch):
        exp = self._q.get((level, key))
        return exp is not None and epoch < exp
if __name__ == '__main__':
    from .digest import Alert
    am = AlarmManager(confirm=True, cooldown_win=0, quarantine=False)
    a = Alert(1, 167772416, 12, 420, 300, 100, 'D2')
    assert am.process(a) is None
    a = Alert(1, 167772416, 12, 430, 320, 103, 'D2')
    assert am.process(a) is None
    a = Alert(1, 167772416, 12, 440, 330, 104, 'D2')
    assert am.process(a) is not None
    am = AlarmManager(confirm=True, cooldown_win=20, quarantine=False)
    assert am.process(Alert(1, 167772672, 16, 416, 800, 10, 'D1')) is not None
    assert am.process(Alert(1, 167772672, 16, 416, 800, 20, 'D1')) is None
    assert am.process(Alert(1, 167772672, 16, 416, 800, 31, 'D1')) is not None
    assert am.process(Alert(2, 167772672, 16, 416, 800, 10, 'D1')) is not None
    am = AlarmManager(confirm=True, cooldown_win=1, quarantine=True)
    for i, e in enumerate((10, 20, 30)):
        assert am.process(Alert(1, 167772928, 8 + i, 416, 800, e, 'D1')) is not None
    assert am.stats['quarantined'] == 1
    assert am.process(Alert(1, 167772928, 9, 416, 800, 40, 'D1')) is None
    assert am.stats['suppressed_quarantine'] >= 1
    assert am.process(Alert(1, 167772928, 9, 416, 800, 30 + config.Q_WINDOW_WIN + 1, 'D1')) is not None
    am = AlarmManager(confirm=True, cooldown_win=1, quarantine=True)
    for i, e in enumerate((10, 20, 30)):
        assert am.process(Alert(1, 167773184, 20 + i, 416, 800, e, 'D1')) is not None
    assert am.stats['quarantined'] == 0
    print('alarm self-check ok:', am.stats)
