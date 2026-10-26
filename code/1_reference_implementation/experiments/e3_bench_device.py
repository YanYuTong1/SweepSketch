import json
import os
import sys
import time
REV = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
NETRADAR = os.environ.get('NETRADAR_DIR', '')
if NETRADAR:
    sys.path.insert(0, os.path.join(NETRADAR, 'detectors'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
import torch
from nn_models.loss_sort import pointnet, pointnetloss
OUT = os.path.join(REV, 'results', 'e3')
B, F, N = (32, 11, 256)
STEPS = int(os.environ.get('E3_BENCH_STEPS', '20'))
WARM = 3

def bench(dev, seed=0):
    torch.manual_seed(seed)
    torch.set_num_threads(int(os.environ.get('SWEEPSKETCH_WORKERS', '2')))
    np.random.seed(seed)
    model = pointnet(2, F, N).to(dev)
    crit = pointnetloss().to(dev)
    opt = torch.optim.Adam(model.parameters(), lr=0.001, betas=(0.9, 0.999), eps=1e-08, weight_decay=0.0001)
    x = torch.randn(B, N, F, device=dev)
    drop_mask = torch.tensor([1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0], dtype=x.dtype, device=dev)
    nondrop = torch.ones(F, dtype=x.dtype, device=dev)
    y = torch.randint(0, 2, (B, N), device=dev)

    def step():
        opt.zero_grad()
        p = x.clone()
        mask = torch.stack([torch.stack([drop_mask if np.random.rand() < 0.5 else nondrop for _ in range(N)]) for _ in range(B)])
        p = p * mask
        p = p.transpose(2, 1)
        seg_pred, trans_feat = model(p)
        seg_pred = seg_pred.contiguous().view(-1, 2)
        target = y.view(-1, 1)[:, 0]
        loss = crit(seg_pred, target, trans_feat)
        loss.backward()
        opt.step()
        return float(loss.detach().cpu())
    for _ in range(WARM):
        step()
    if dev == 'mps':
        torch.mps.synchronize()
    t0 = time.time()
    for _ in range(STEPS):
        step()
    if dev == 'mps':
        torch.mps.synchronize()
    wall = time.time() - t0
    nparam = sum((p.numel() for p in model.parameters()))
    return {'device': dev, 'batch': B, 'points': N, 'features': F, 'steps': STEPS, 'param_M': round(nparam / 1000000.0, 2), 'ms_per_step': round(wall / STEPS * 1000, 2), 'steps_per_s': round(STEPS / wall, 2), 'samples_per_s': round(STEPS * B / wall, 1), 'wall_s': round(wall, 2)}

def main():
    os.makedirs(OUT, exist_ok=True)
    rows = []
    has_mps = torch.backends.mps.is_available()
    print('torch', torch.__version__, 'mps_available', has_mps)
    for dev in ['cpu', 'mps'] if has_mps else ['cpu']:
        try:
            r = bench(dev)
            rows.append(r)
            print(r)
        except Exception as e:
            print('device', dev, 'failed:', repr(e))
            rows.append({'device': dev, 'error': repr(e)})
    with open(os.path.join(OUT, 'device_bench.csv'), 'w') as f:
        cols = ['device', 'param_M', 'ms_per_step', 'steps_per_s', 'samples_per_s', 'wall_s', 'batch', 'points', 'features']
        f.write(','.join(cols) + '\n')
        for r in rows:
            f.write(','.join((str(r.get(c, '')) for c in cols)) + '\n')
    meta = {'script': os.path.abspath(__file__), 'torch': torch.__version__, 'mps_available': has_mps, 'model': 'official detectors/nn_models/loss_sort.py pointnet(2,11,256)', 'input': [B, N, F], 'threads': os.environ.get('SWEEPSKETCH_WORKERS', '2'), 'started': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'host': os.uname().nodename, 'rows': rows}
    with open(os.path.join(OUT, 'device_bench.meta.json'), 'w') as f:
        json.dump(meta, f, indent=1)
if __name__ == '__main__':
    main()
