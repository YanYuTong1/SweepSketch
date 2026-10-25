from . import config

class Bucket:
    __slots__ = ('key', 'epoch', 'win', 'n_new', 'n_ewma', 'C', 'pkt', 'pkt_ewma', 'hll', 'd2_held')

    def __init__(self, key, epoch=0):
        self.key, self.epoch = (key, epoch)
        self.win = 1
        self.n_new = self.n_ewma = self.C = 0
        self.pkt = self.pkt_ewma = 0
        self.d2_held = False
        self.hll = [0] * config.HLL_M

    def process(self, r, rho, global_epoch, llr_tbl):
        rollover = self.epoch != global_epoch
        if rollover:
            self.d2_held = self.pkt >= max(config.P_MIN, config.D2_MULT * self.pkt_ewma) and self.n_new >= max(config.K_FLOOD, 2 * self.n_ewma if config.USE_GATE else 0)
            self.n_ewma += self.n_new - self.n_ewma >> config.EWMA_SHIFT
            self.pkt_ewma += self.pkt - self.pkt_ewma >> config.EWMA_SHIFT
            self.n_new = self.pkt = self.C = 0
            self.win = self.win + 1 & config.WIN_MASK
        cell = self.hll[r]
        tag_old = cell >> config.RHO_BITS
        rho_old = cell & (1 << config.RHO_BITS) - 1
        event = 1 if tag_old != self.win or rho > rho_old else 0
        if tag_old != self.win:
            self.hll[r] = self.win << config.RHO_BITS | rho
        elif rho > rho_old:
            self.hll[r] = self.win << config.RHO_BITS | rho
        self.C = min(config.C_MAX, max(0, self.C + llr_tbl['new' if event else 'rep']))
        self.n_new = min(255, self.n_new + event)
        self.pkt = min(config.PKT_MAX, self.pkt + 1)
        self.epoch = global_epoch
        gate = max(config.K_ALARM, 2 * self.n_ewma if config.USE_GATE else 0, config.K_ALARM_QUIET if config.USE_GATE and self.n_ewma < config.N_EWMA_QUIET else 0)
        alarm1 = config.USE_D1 and self.C >= config.H_FP and (self.n_new >= gate)
        alarm2 = config.USE_D2 and self.pkt >= config.P_MIN and (self.pkt >= config.D2_MULT * self.pkt_ewma) and (self.n_new >= max(config.K_FLOOD, 2 * self.n_ewma if config.USE_GATE else 0)) and self.d2_held
        return (alarm1, alarm2, rollover)
if __name__ == '__main__':
    from .llr import make_llr_table
    tbl = make_llr_table()
    b = Bucket(167772416)
    first_a1 = first_a2 = None
    for e in range(2):
        for i in range(256):
            a1, a2, _ = b.process(i % 32, 1, e, tbl)
            if a1 and first_a1 is None:
                first_a1 = (e, i + 1)
            if a2 and first_a2 is None:
                first_a2 = (e, i + 1)
    assert first_a1 == (0, 12), first_a1
    assert first_a2 == (1, 200), first_a2
    assert b.n_new == 32 and b.C == 0, (b.n_new, b.C)
    b = Bucket(167772672)
    a1s = a2s = 0
    for i in range(1000):
        a1, a2, _ = b.process(0, 1, 0, tbl)
        a1s += a1
        a2s += a2
    assert a1s == 0, a1s
    assert a2s == 0, a2s
    cd = Bucket(167772928)
    alarm_windows = []
    for e in range(8):
        any_alarm = False
        for i in range(1000):
            a1, a2, _ = cd.process(i % 32 if i < 32 else i * 7 % 32, 1, e, tbl)
            any_alarm = any_alarm or a1 or a2
        if any_alarm:
            alarm_windows.append(e)
    assert alarm_windows == [0, 1, 2, 3, 4, 5, 6], alarm_windows
    atk = Bucket(167773184)
    atk_windows = []
    for e in range(12):
        any_alarm = False
        n = 256 if e >= 2 else 20
        for i in range(n):
            a1, a2, _ = atk.process(0 if e < 2 else i % 32, 1, e, tbl)
            any_alarm = any_alarm or a1 or a2
        if any_alarm:
            atk_windows.append(e)
    assert atk_windows[0] == 2 and atk_windows[-1] == 8, atk_windows
    print('bucket self-check ok', first_a1, alarm_windows, atk_windows)
