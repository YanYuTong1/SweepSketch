import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sweepsketch import config
from sweepsketch.alarm import AlarmManager
from sweepsketch.bucket import Bucket
from sweepsketch.cross16 import CrossPrefixCorrelator
from sweepsketch.digest import Alert, Collector
from sweepsketch.sketch import Level, SweepSketch
from sweepsketch.runner import finalize

def _hot_bucket_sketch():
    sk = SweepSketch()
    sk.l1 = Level(1, lambda d: d >> 8 << 8, 17)
    return sk

def test_aging_replace_stale_hot():
    old_enable, old_win = (config.AGE_ENABLE, config.AGE_WIN)
    config.AGE_ENABLE, config.AGE_WIN = (True, 4)
    try:
        sk = _hot_bucket_sketch()
        col = Collector()
        for i in range(512):
            sk.process(0, 167772160 | i % 256, 0.0, col)
        b = sk.l1.buckets[0]
        assert b.key == 167772160 and b.pkt == 512, (b.key, b.pkt)
        assert not (b.pkt < config.P_MIN and b.C < config.H_FP), ' '
        ts_stale = (4 << 32) * 1e-09 + 1e-06
        sk.process(0, 184549381, ts_stale, col)
        b2 = sk.l1.buckets[0]
        assert b2.key == 184549376, (hex(b2.key), 'stale hot bucket ')
        print('  aging: stale hot bucket replaced ok')
    finally:
        config.AGE_ENABLE, config.AGE_WIN = (old_enable, old_win)

def test_aging_keep_active_hot():
    old_enable, old_win = (config.AGE_ENABLE, config.AGE_WIN)
    config.AGE_ENABLE, config.AGE_WIN = (True, 4)
    try:
        sk = _hot_bucket_sketch()
        col = Collector()
        for i in range(512):
            sk.process(0, 167772160 | i % 256, 0.0, col)
        ts_next = (1 << 32) * 1e-09 + 1e-06
        sk.process(0, 184549381, ts_next, col)
        b = sk.l1.buckets[0]
        assert b.key == 167772160, (hex(b.key), 'active hot bucket ')
        assert b.pkt == 512, b.pkt
        print('  aging: active hot bucket kept ok')
    finally:
        config.AGE_ENABLE, config.AGE_WIN = (old_enable, old_win)

def test_aging_disabled():
    old_enable, old_win = (config.AGE_ENABLE, config.AGE_WIN)
    config.AGE_ENABLE, config.AGE_WIN = (False, 4)
    try:
        sk = _hot_bucket_sketch()
        col = Collector()
        for i in range(512):
            sk.process(0, 167772160 | i % 256, 0.0, col)
        ts_stale = (8 << 32) * 1e-09 + 1e-06
        sk.process(0, 184549381, ts_stale, col)
        assert sk.l1.buckets[0].key == 167772160, 'AGE_ENABLE=False '
        print('  aging: disabled beam keeps v1 semantics ok')
    finally:
        config.AGE_ENABLE, config.AGE_WIN = (old_enable, old_win)

def test_alarm_d2_2of3():
    am = AlarmManager(confirm=True, cooldown_win=0, quarantine=False)
    assert am.process(Alert(1, 167772416, 12, 420, 300, 100, 'D2')) is None
    assert am.process(Alert(1, 167772416, 12, 430, 320, 101, 'D2')) is not None
    am2 = AlarmManager(confirm=True, cooldown_win=0, quarantine=False)
    assert am2.process(Alert(1, 167772416, 12, 420, 300, 100, 'D2')) is None
    assert am2.process(Alert(1, 167772416, 12, 420, 300, 103, 'D2')) is None
    print('  alarm: D2 2-of-3 ok')

def test_alarm_cooldown_and_quarantine():
    am = AlarmManager(confirm=True, cooldown_win=20, quarantine=False)
    assert am.process(Alert(1, 167772672, 16, 416, 800, 10, 'D1')) is not None
    assert am.process(Alert(1, 167772672, 16, 416, 800, 29, 'D1')) is None
    assert am.process(Alert(1, 167772672, 16, 416, 800, 31, 'D1')) is not None
    am = AlarmManager(confirm=True, cooldown_win=1, quarantine=True)
    for e in (100, 200, 300):
        assert am.process(Alert(1, 167772928, 9, 416, 800, e, 'D1')) is not None
    assert am.stats['quarantined'] == 1
    assert am.process(Alert(1, 167772928, 9, 416, 800, 400, 'D1')) is None
    exp = 300 + config.Q_WINDOW_WIN
    assert am.process(Alert(1, 167772928, 9, 416, 800, exp + 1, 'D1')) is not None
    am = AlarmManager(confirm=True, cooldown_win=1, quarantine=True)
    for e in (100, 200, 300):
        am.process(Alert(1, 167773184, 20, 900, 2000, e, 'D1'))
    assert am.stats['quarantined'] == 0
    print('  alarm: cooldown + quarantine ok')

def test_cross16_switch1():
    cx = CrossPrefixCorrelator(W=4, K=2)
    got = []
    for w in range(1, 9):
        p16 = 174325760 + (w - 1) * 65536
        got.extend(cx.observe(Alert(1, p16 | 256, 32, 0, 171, w, 'N12', ts=w * 4.0)))
    assert len(got) == 7, len(got)
    assert got[0].epoch == 2 and got[0].level == 3 and (got[0].reason == 'DIST')
    cx = CrossPrefixCorrelator(W=4, K=2)
    for w in range(1, 9):
        assert cx.observe(Alert(1, 174326016, 32, 0, 171, w, 'N12')) == []
    print('  cross16: switch1 window-2 detection ok')

def test_cross16_no_l2_aggregation():
    cx = CrossPrefixCorrelator(W=4, K=2)
    for w in range(1, 6):
        for j in range(1, 6):
            assert cx.observe(Alert(1, 174325760 | j << 8, 9, 0, 500, w, 'D1')) == []
    print('  cross16: /24-floor semantics ok')

def test_pipeline_end_to_end():
    raw = [Alert(1, 174326016, 32, 0, 171, 10, 'N12', 10.0), Alert(1, 174391552, 32, 0, 171, 11, 'N12', 11.0), Alert(1, 174457088, 20, 500, 900, 12, 'D1', 12.0), Alert(1, 174457088, 20, 500, 900, 13, 'D2', 13.0)]
    eps, stats = finalize(raw)
    reasons = [(a.level, a.reason) for a in eps]
    assert (3, 'DIST') in reasons, reasons
    assert (1, 'D1') in reasons, reasons
    assert stats['raw'] == 4
    print('  pipeline: finalize ok', stats['cross16']['dist_emitted'])
if __name__ == '__main__':
    print('unit tests:')
    test_aging_replace_stale_hot()
    test_aging_keep_active_hot()
    test_aging_disabled()
    test_alarm_d2_2of3()
    test_alarm_cooldown_and_quarantine()
    test_cross16_switch1()
    test_cross16_no_l2_aggregation()
    test_pipeline_end_to_end()
    print('ALL UNIT TESTS PASSED')
