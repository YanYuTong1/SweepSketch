from . import config
from .alarm import AlarmManager
from .cross16 import CrossPrefixCorrelator

def finalize(raw_alerts, enable_alarm=True, enable_cross=None):
    if enable_cross is None:
        enable_cross = config.CROSS16
    am = AlarmManager() if enable_alarm else None
    cx = CrossPrefixCorrelator() if enable_cross else None
    episodes = []
    n = 0
    for a in sorted(raw_alerts, key=lambda x: (x.ts if x.ts is not None else 0, x.epoch, x.level, x.key, x.reason)):
        n += 1
        if cx is not None and a.level == 1 and (a.reason in ('D1', 'N12')):
            for d in cx.observe(a):
                if am is not None:
                    ep = am.process(d)
                    if ep is not None:
                        episodes.append(ep)
                else:
                    episodes.append(d)
        if am is not None:
            ep = am.process(a)
            if ep is not None:
                episodes.append(ep)
    episodes.sort(key=lambda x: (x.ts if x.ts is not None else 0, x.level, x.key))
    stats = {'raw': n, 'alarm': dict(am.stats) if am is not None else {}, 'cross16': dict(cx.stats) if cx is not None else {}}
    return (episodes, stats)

def raw_counts(raw_alerts):
    out = {'D1': 0, 'D2': 0, 'N12': 0}
    for a in raw_alerts:
        if a.reason in out:
            out[a.reason] += 1
    return out

def split_episodes(episodes):
    buckets = {}
    for a in episodes:
        buckets.setdefault((a.level, a.reason), []).append(a)
    return buckets
if __name__ == '__main__':
    from .digest import Alert
    raw = [Alert(1, 174326016, 12, 420, 300, 10, 'N12', 10.0), Alert(1, 174326016, 16, 416, 800, 20, 'D1', 20.0), Alert(1, 174391552, 12, 420, 300, 11, 'N12', 11.0)]
    eps, stats = finalize(raw)
    reasons = sorted(((a.level, a.reason) for a in eps))
    assert (3, 'DIST') in reasons, reasons
    assert (1, 'D1') in reasons, reasons
    print('runner self-check ok:', reasons, stats['cross16'])
