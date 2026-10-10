
import argparse
import csv
import os
from multiprocessing import Pool

from sweepsketch import config

from common import RES
from s6_2_exp1_exp5_cic_ids2017 import run_calibrate, run_compare, run_e1, run_e2, run_e7, run_matrix
from s7_1_exp9_backbone_scale import run_p8
from s6_4_exp6_exp8_synthetic import run_abl, run_adv, run_mech
from s6_3_table6_real_holdout import run_real


def run_e4(theta0, budgets):
    
    buds = [int(x) for x in budgets.split(",")]
    with Pool(min(8, len(buds))) as p:
        results = p.starmap(run_e1, [(theta0, [b], None) for b in buds])
    rows = sorted((r for _, rs in results for r in rs), key=lambda x: (x[0], x[1]))
    os.makedirs(RES, exist_ok=True)
    with open(os.path.join(RES, "EXP3_memory.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["kb", "h_bits", "tp", "fp", "fn", "f1"])
        w.writerows(rows)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["calibrate", "compare", "iot", "real"] +
                                    ["exp%d" % i for i in range(1, 10)])
    ap.add_argument("--theta0", type=float, default=config.THETA0)
    ap.add_argument("--budgets", default="32,64,128,256,512,1024")
    ap.add_argument("--dump", default=None)
    ap.add_argument("--all-benign", action="store_true",
                    help="calibrate with union sampling over the full benign corpus (the finalized procedure)")
    ap.add_argument("--sample-k", type=int, default=10,
                    help="sampling interval over the full benign corpus (1 in every k packets)")
    args = ap.parse_args()
    if args.cmd == "real":
        run_real(args.theta0)
    elif args.cmd == "calibrate":
        run_calibrate(args.theta0, args.all_benign, args.sample_k)
    elif args.cmd == "exp1":
        run_e1(args.theta0, [512], "EXP1_static", args.dump)
    elif args.cmd == "exp3":
        run_e4(args.theta0, args.budgets)
    elif args.cmd == "exp4":
        run_e7(args.theta0)
    elif args.cmd == "exp2":
        run_e2(args.theta0)
    elif args.cmd == "compare":
        run_compare()
    elif args.cmd == "exp9":
        run_p8(args.theta0, tuple(int(x) for x in args.budgets.split(",")))
    elif args.cmd == "exp8":
        run_adv(args.theta0)
    elif args.cmd == "exp6":
        run_abl(args.theta0)
    elif args.cmd == "exp5":
        run_matrix()
    elif args.cmd == "exp7":
        run_mech(args.theta0)
    elif args.cmd == "iot":
        from s6_3_exp1_exp4_cic_iot2023 import run_iot
        run_iot(args.theta0)
