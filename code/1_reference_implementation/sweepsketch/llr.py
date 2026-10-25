import math
from . import config

def make_llr_table(theta0=config.THETA0, theta1=config.THETA1, scale=config.SCALE):
    v_new = int(round(math.log2(theta1 / theta0) * scale))
    v_rep = int(round(math.log2((1.0 - theta1) / (1.0 - theta0)) * scale))
    return {'new': max(-128, min(127, v_new)), 'rep': max(-128, min(127, v_rep))}
if __name__ == '__main__':
    t = make_llr_table()
    assert t == {'new': 38, 'rep': -26}, t
    print('llr self-check ok')
