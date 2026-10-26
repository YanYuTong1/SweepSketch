#!/bin/bash
set -u
cd "$(dirname "$0")/../../.." || exit 1
PY=${PYTHON:-python3}
export SWEEPSKETCH_WORKERS=2
OUT=results/e3_seeds
mkdir -p "$OUT/logs"
run_one() {
  local seed=$1 fold=$2
  echo "[$(date +%H:%M:%S)] start seed=$seed fold=$fold"
  $PY -u code/1_reference_implementation/experiments/e3_netradar.py --protocol p2 --fold "$fold" \
      --seed "$seed" --epochs 2 --full-epoch --no-save \
      --outdir "$OUT" --tag "p2_s${seed}_f${fold}" \
      > "$OUT/logs/train_s${seed}_f${fold}.log" 2>&1
  echo "[$(date +%H:%M:%S)] done  seed=$seed fold=$fold rc=$?"
}
n=0
for seed in 0 1 2 3 4; do
  for fold in 0 1 2 3 4; do
    run_one "$seed" "$fold" &
    n=$((n + 1))
    if [ $((n % 2)) -eq 0 ]; then wait; fi
  done
done
wait
echo "[$(date +%H:%M:%S)] all 25 runs done"
