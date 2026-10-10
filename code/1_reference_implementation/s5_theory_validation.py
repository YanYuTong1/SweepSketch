
import csv
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sweepsketch import config
from sweepsketch.bucket import Bucket
from sweepsketch.llr import make_llr_table

RES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "results", "csv")
TBL = make_llr_table(config.THETA0)


def _h(rho_seed, i):
    
    return (i * 2654435761 + rho_seed * 40503) % 32


def check_t1():
    
    rows = []
    for S in (2, 4, 6, 8, 12, 16, 24, 32, 48, 64):
        b = Bucket(0x0A000100)
        for i in range(S):
            b.process(_h(1, i) % 32, _h(1, i) % 8, 0, TBL)
        theory = 32 * (1 - math.exp(-S / 32))
        rows.append((S, b.n_new, round(theory, 2)))
        print("T1 S=%3d: n_new=%3d theory≈%.1f" % (S, b.n_new, theory))
    with open(os.path.join(RES, "THEORY_t1.csv"), "w", newline="") as fh:
        csv.writer(fh).writerows([("S", "n_new", "theory")] + rows)


def _gamma_star(theta0, t_new, t_rep):
    
    lo, hi = 0.0, 1.0
    for _ in range(60):
        mid = (lo + hi) / 2
        if theta0 * math.exp(mid * t_new) + (1 - theta0) * math.exp(mid * t_rep) <= 1:
            lo = mid
        else:
            hi = mid
    return lo


def check_t2a():
    
    rows = []
    for h_bits in (2, 4, 6, 8, 10):
        h = round(h_bits * 8)
        total = 0
        for trial in range(200):
            b = Bucket(0x0A000200)
            fired = False
            for e in range(50):
                for i in range(100):
                    
                    
                    
                    r = 5
                    rho = 1 if i == 0 else 0
                    b.process(r, rho, e, TBL)
                if b.C >= h and b.n_new >= max(config.K_ALARM, 2 * b.n_ewma):
                    fired = True
                    break
            total += 1 if fired else 0
        p = total / 200
        gamma = _gamma_star(config.THETA0, TBL["new"], TBL["rep"])
        bound = math.exp(-gamma * h)
        rows.append((h_bits, round(p, 4), round(bound, 4)))
        print("T2a h=%2d bit: measured α=%.3f bound e^{−γh}=%.3f (γ*=%.4f)" % (h_bits, p, bound, gamma))
    with open(os.path.join(RES, "THEORY_t2a.csv"), "w", newline="") as fh:
        csv.writer(fh).writerows([("h_bits", "alpha_measured", "alpha_bound")] + rows)


def check_t2b():
    
    mu1 = config.THETA1 * TBL["new"] + (1 - config.THETA1) * TBL["rep"]  
    h = config.H_FP
    rows = []
    for m in (2, 4, 8, 16):
        det = 0
        for trial in range(200):
            b = Bucket(0x0A000300)
            ok = False
            for i in range(m):
                b.process(_h(2, i) % 32, _h(2, i) % 8, 0, TBL)
                if b.C >= h and b.n_new >= config.K_ALARM:
                    ok = True
                    break
            det += 1 if ok else 0
        p = det / 200
        bound = 1 - math.exp(-((m * mu1 - h) ** 2) / (2 * m * 74 * 74)) if m * mu1 > h else 0.0
        rows.append((m, round(p, 4), round(bound, 4)))
        print("T2b m=%2d packets: measured P=%.3f bound≈%.3f" % (m, p, bound))
    with open(os.path.join(RES, "THEORY_t2b.csv"), "w", newline="") as fh:
        csv.writer(fh).writerows([("m", "p_measured", "p_bound")] + rows)


def check_t4():
    
    rows = []
    b = Bucket(0x0A000400)
    
    for e in range(8):
        for i in range(1000):
            b.process(i % 32 if i < 32 else (i * 7) % 32, 1, e, TBL)
        rows.append((e, b.n_ewma, b.n_new))
        print("T4 attack window e=%d: n_ewma=%d (theory converges to 32)" % (e, b.n_ewma))
    
    for e in range(8, 16):
        for i in range(20):
            b.process(5, 1, e, TBL)
        rows.append((e, b.n_ewma, b.n_new))
        print("T4 recovery window e=%d: n_ewma=%d (theory (7/8)^(e−7)·32)" % (e, b.n_ewma))
    with open(os.path.join(RES, "THEORY_t4.csv"), "w", newline="") as fh:
        csv.writer(fh).writerows([("window", "n_ewma", "n_new")] + rows)


def check_t5():
    
    rows = []
    for S in (4, 6, 8, 10, 12, 16):
        det = 0
        for trial in range(100):
            b = Bucket(0x0A000500)
            ok = False
            for i in range(S):
                b.process(_h(3 + trial, i) % 32, _h(3 + trial, i) % 8, 0, TBL)
                if (b.C >= config.H_FP and
                        b.n_new >= max(config.K_ALARM, 2 * b.n_ewma,
                                       config.K_ALARM_QUIET)):
                    ok = True
                    break
            det += 1 if ok else 0
        rows.append((S, det / 100))
        print("T5 S=%2d: detection rate %.2f" % (S, det / 100))
    with open(os.path.join(RES, "THEORY_t5.csv"), "w", newline="") as fh:
        csv.writer(fh).writerows([("S", "detection_rate")] + rows)


if __name__ == "__main__":
    os.makedirs(RES, exist_ok=True)
    check_t1()
    check_t2a()
    check_t2b()
    check_t4()
    check_t5()
    print("s5_theory_validation done")
