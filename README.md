# SweepSketch Artifact

Code accompanying the SweepSketch paper.

## Layout

| Path | Contents |
|---|---|
| `1_reference_implementation/` | Python reference implementation and experiment drivers |
| `2_baselines_p4/` | P4 implementations of the nine comparison baselines |
| `3_throughput_cpp/` | C++ throughput benchmark |
| `4_dataplane_deployed_p4/` | Deployed Tofino-2 data plane |
| `5_dataplane_full_p4/` | Full Tofino-2 data plane, plus its equivalence check against the reference |

## Data

`database/attack/` holds the packet records used by the real-traffic
experiments. They are stored gzipped, one line per packet:

```
ts,src,dst,proto,sport,dport
1780286476.261322,45.142.193.150,1.182.230.94,17,65333,26009
```

| Directory | Files | Contents |
|---|---|---|
| `normal_single24/` | 71 | Real captures, one destination /24 each |
| `natural_multi24/` | 2 | Real captures, multiple destination /24s |
| `synthetic_multi24_by_timestamp/` | 13 | Multi-prefix holdout samples, interleaved by timestamp |
| `synthetic_multi24_shuffled/` | 15 | Multi-prefix holdout samples, shuffled |

The loaders in `sweepsketch/pcapio.py` read `.csv.gz` and plain `.csv`
interchangeably, so nothing downstream changes if you decompress in place.

The benign corpora are not redistributed. Obtain CIC-IDS-2017 and CIC-IoT-2023
from the UNB Canadian Institute for Cybersecurity, and place the benign pcaps
under `database/benign/` (the file names expected there are listed in
`common.py` and `s6_3_table6_real_holdout.py`).

## Reference implementation

Requires Python 3 and `tqdm`.

```
cd code/1_reference_implementation
python run_experiments.py <cmd>
```

`<cmd>` is one of `calibrate`, `compare`, `iot`, `real`, or `exp1` … `exp9`.
Results are written to `results/csv/`.

## Throughput benchmark

```
cd code/3_throughput_cpp
make          # builds build/bench
make verify   # replays verify/trace.csv against verify/expected_*
```

## Tofino-2 data planes

Requires Intel SDE 9.7.1 and a Tofino-2 switch; set `SDE` if it is not at the
default path.

```
cd code/5_dataplane_full_p4 && ./deploy_sweep.sh deploy
cd code/2_baselines_p4/<baseline> && ./deploy_<baseline>.sh deploy
```

Both scripts also accept `build`, `run`, and `clean`. `4_dataplane_deployed_p4/`
has no wrapper script: build `sweepsketch.p4` with `p4_build.sh`, then load
`setup_ports.py` and `setup_tables.py` through `run_bfshell.sh`.
