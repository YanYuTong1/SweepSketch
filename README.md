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

Traffic traces are not stored in this repository. Download the artifact archive
from the release page and extract it so that `database/` sits next to `code/`:

```
sweepsketch-artifact/
├── code/
└── database/
    └── attack/normal_single24/*.csv
```

The benign corpora are not redistributed. Obtain CIC-IDS-2017 and CIC-IoT-2023
from the UNB Canadian Institute for Cybersecurity, and place the benign pcaps
under `database/benign/`.

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
