import os
HLL_M = 32
RHO_BITS = 5
WIN_MASK = 7
USE_L2 = True
USE_D1 = True
USE_D2 = True
USE_GATE = True
N_L1 = 7943
N_L2 = 3972
SCALE = 8
C_MAX = 65535
PKT_MAX = 65535
THETA0 = 0.0345
THETA1 = 0.9
H_BITS = 9.2
H_FP = 74
K_ALARM = 8
K_ALARM_QUIET = 12
N_EWMA_QUIET = 4
K_FLOOD = 6
EWMA_SHIFT = 3
P_MIN = 200
D2_MULT = 3
EPOCH_NS = 1 << 32
EPOCH_S = EPOCH_NS / 1000000000.0
WIN_PER_HOUR = int(round(3600.0 / EPOCH_S))
WIN_PER_2H = 2 * WIN_PER_HOUR
WIN_PER_24H = 24 * WIN_PER_HOUR

def _env_flag(name, default='1'):
    return os.environ.get(name, default).strip().lower() not in ('0', 'false', 'no', 'off')
AGE_ENABLE = _env_flag('SWEEPSKETCH_AGE', '1')
AGE_WIN = int(os.environ.get('SWEEPSKETCH_AGE_WIN', '4'))
ALARM_CONFIRM = _env_flag('SWEEPSKETCH_ALARM', '1')
D2_CONFIRM_WINDOWS = int(os.environ.get('SWEEPSKETCH_D2_WIN', '3'))
D2_CONFIRM_COUNT = int(os.environ.get('SWEEPSKETCH_D2_COUNT', '2'))
COOLDOWN_WIN = int(os.environ.get('SWEEPSKETCH_COOLDOWN', '20'))
QUARANTINE = _env_flag('SWEEPSKETCH_QUARANTINE', '1')
Q_EPISODES = int(os.environ.get('SWEEPSKETCH_Q_EPISODES', '3'))
Q_LOOKBACK_WIN = int(os.environ.get('SWEEPSKETCH_Q_LOOKBACK', str(WIN_PER_2H)))
Q_WINDOW_WIN = int(os.environ.get('SWEEPSKETCH_Q_WINDOW', str(WIN_PER_24H)))
Q_MAX_K = int(os.environ.get('SWEEPSKETCH_Q_MAXK', '16'))
Q_GROWTH_MULT = float(os.environ.get('SWEEPSKETCH_Q_GROWTH', '1.25'))
Q_REQUIRE_NO_D1 = _env_flag('SWEEPSKETCH_Q_NO_D1', '0')
CROSS16 = _env_flag('SWEEPSKETCH_CROSS16', '1')
CROSS_W = int(os.environ.get('SWEEPSKETCH_CROSS_W', '4'))
CROSS_K = int(os.environ.get('SWEEPSKETCH_CROSS_K', '2'))
CROSS_NNEW_FLOOR = int(os.environ.get('SWEEPSKETCH_CROSS_FLOOR', '12'))
DIST_LEVEL = 3
BENIGN_MAX = int(os.environ.get('SWEEPSKETCH_BENIGN_MAX', str(1 << 60)))
ATTACK_MAX = int(os.environ.get('SWEEPSKETCH_ATTACK_MAX', str(1 << 60)))
if __name__ == '__main__':
    assert N_L1 + N_L2 == 11915, (N_L1, N_L2)
    assert (N_L1 + N_L2) * 44 <= 512 * 1024
    assert H_FP == round(H_BITS * SCALE)
    assert 0 < THETA0 < THETA1 < 1 and K_ALARM >= 1 and (P_MIN >= 1)
    assert HLL_M == 32 and RHO_BITS == 5 and (WIN_MASK == 7)
    assert 1 <= AGE_WIN < 32 and D2_CONFIRM_COUNT <= D2_CONFIRM_WINDOWS
    assert COOLDOWN_WIN >= 1 and CROSS_W >= 1 and (CROSS_K >= 1)
    pass
