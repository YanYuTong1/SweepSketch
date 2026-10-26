#!/bin/bash
set -u
cd "$(dirname "$0")/../../.." || exit 1
PY=${PYTHON:-python3}
export SWEEPSKETCH_WORKERS=2
echo "[$(date +%H:%M:%S)] start p1 seeds"
for seed in 0 1 2; do
  echo "[$(date +%H:%M:%S)] p1 full seed=$seed"
  $PY -u code/1_reference_implementation/experiments/e3_netradar.py --protocol p1 --seed "$seed" \
      --epochs 2 --full-epoch --tag "p1_full_seed${seed}" \
      >> "logs/e3/train_p1_seed${seed}.log" 2>&1
  echo "[$(date +%H:%M:%S)] p1 seed=$seed done rc=$?"
done
echo "[$(date +%H:%M:%S)] start p2 folds"
for fold in 0 1 2 3 4; do
  echo "[$(date +%H:%M:%S)] p2 full fold=$fold"
  $PY -u code/1_reference_implementation/experiments/e3_netradar.py --protocol p2 --fold "$fold" --seed 0 \
      --epochs 2 --full-epoch --tag "p2_full_fold${fold}_seed0" \
      >> "logs/e3/train_p2_fold${fold}.log" 2>&1
  echo "[$(date +%H:%M:%S)] p2 fold=$fold done rc=$?"
done
echo "[$(date +%H:%M:%S)] all done"
