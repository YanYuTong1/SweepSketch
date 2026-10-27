# SweepSketch

Code and packet-record data for the paper *SweepSketch: Detecting Carpet-Bombing
Attacks Before They End*.

SweepSketch detects carpet-bombing DDoS from the destination side, one packet at
a time, without source-side state or training; it raises its first alarm while
the attack is still in progress. The detector state occupies 512 KB. A bit-exact
C++ implementation reaches 13.21 Mpps per core, and the Tofino2 data plane is a
two-pass, 90-table, 12-stage program that reports a 28-B snapshot per packet.

## Layout

```
code/
  1_reference_implementation/   Python reference detector and experiment drivers
    experiments/                Drivers for the paper's dynamic experiments (E1-E13)
  2_baselines_p4/               P4 ports of the comparison baselines
  3_throughput_cpp/             C++ per-packet insertion-path throughput harness
  4_dataplane_deployed_p4/      Tofino2 P4 program (two forms) and compile evidence
  5_cpp_detector/               C++20 bit-exact detector and benchmark harness
  6_dpu_data_plane/             Portable C model of the DPU data plane
database/
  attack/                       101 gzipped CSV packet records and SHA256SUMS.txt
```

## Requirements

- Python 3.10+; the reference implementation uses only the standard library.
  The drivers in `experiments/` additionally use `numpy` and `matplotlib`, and
  E3 uses `torch` plus the NetRadar repository (set `NETRADAR_DIR`).
- A C++20 compiler for `code/3_throughput_cpp` and `code/5_cpp_detector`.
- A C11 compiler for `code/6_dpu_data_plane`.
- Intel Tofino2 and BF-SDE 9.7.1 (`bf-p4c` 9.7.1) for `code/4`.

## Experiment environment

| Environment | Used for | Configuration |
|---|---|---|
| Workstation | Python detector, C++ detector and throughput harness, E1-E13 drivers, DPU host replay | Apple M5 Pro, 15 cores, 24 GB RAM, macOS 27.0.1 |
| BF-SDE 9.7.1 container | `bf-p4c` 9.7.1 compilation and resource reports | Ubuntu 22.04 x86_64 (`sde971-amd64`) on Docker Desktop 29.5.2 with Rosetta; 15 vCPU, 19.8 GB |
| Tofino2 testbed | Hardware compile and resource report | Tofino2, T2NA, BF-SDE 9.7.1 |
| DPU hardware | Micro-engine deployment | DPU with 240 KB on-chip SRAM, 5,120 slots |
| DPU toolchain container | Micro-engine build and device image | arm64 Linux (AlmaLinux 8) on Docker Desktop; vendor RISC-V toolchain |

## Quick start

```bash
cd code/1_reference_implementation
python3 run_sweep.py selfcheck
```

`selfcheck` runs a synthetic end-to-end check and needs no data.

## Experiment drivers

Run from `code/1_reference_implementation`; attack files are read from
`database/attack/` and benign corpora from `database/benign/`.

| Command | Paper item |
|---|---|
| `python3 run_sweep.py calibrate --all-benign --sample-k 1` | calibration corpus |
| `python3 run_sweep.py exp1` | static detection |
| `python3 run_sweep.py exp2` | source-spoofing immunity |
| `python3 run_sweep.py exp3 --budgets 512,1024` | memory grid |
| `python3 run_sweep.py exp4` | dynamic timeline |
| `python3 run_sweep.py exp5` | attack-type matrix |
| `python3 run_sweep.py exp6` | ablation grid |
| `python3 run_sweep.py exp7` | component mechanisms |
| `python3 run_sweep.py exp8` | adversarial grid |
| `python3 run_sweep.py exp9` | backbone scale stress test |
| `python3 run_sweep.py real` | holdout validation |
| `python3 run_sweep.py iot` | five-dataset static |
| `python3 run_sweep.py compare` | baseline comparison |

The dynamic results of the paper come from `code/1_reference_implementation/experiments/`:

| Driver | Result in the paper | Command |
|---|---|---|
| E1 | mixed traffic, F1 0.991 | `python3 e1_mixed.py --all-seeds --aggregate` |
| E2 | adaptive grid, damage checkpoints | `python3 e2_adaptive.py all --seeds 5` |
| E3 | NetRadar comparison and leave-one-type-out | `python3 e3_netradar.py --protocol p2 --fold 0 --seed 0 --full-epoch` |
| E4 | benign false alarms | `python3 e4_benign.py --dataset cic --configs 512:on --seeds 0,1,2,3,4` |
| E5 | deployment scale limits | `python3 e5_scale.py --budgets 512,1024` |
| E7 | deployment and throughput | `python3 e7_deploy.py all` |
| E8 | strategy-grid oracle | `python3 e8_oracle.py` |
| E9 | T-HLL collision bias | `python3 e9_thll.py` |
| E10 | sweep-distance diagnostics | `python3 e10_sweep_dist.py --help` |
| E11 | deadline recall and damage | `python3 e11_deadline.py` |
| E12/E12b/E13 | benign and deadline curves | `python3 e12.py`; `python3 e12b_sk.py`; `python3 e13.py` |

E3 needs the NetRadar code and its trained models; E11-E13 reuse those models.
E1, E2, E4, and E5 take hours on a many-core machine. Results are written to
`results/` at the repository root.

## C++

```bash
cd code/3_throughput_cpp
make
make verify

cd code/5_cpp_detector
make
./build/detector --gen-synth /tmp/synth.bin --n 200000 --prefixes 1000 --seed 1
./build/detector --bin /tmp/synth.bin --alarms alarms.csv --max-pkts 200000
./build/detector --bin /tmp/synth.bin --bench --repeats 3 --max-pkts 200000
```

`--pcap FILE` reads a packet capture directly; `--alarms OUT.csv` writes the
alarm stream.

## DPU data plane

`code/6_dpu_data_plane` implements 48-B T-HLL buckets, per-packet CUSUM,
dual EWMA gates, and an alarm ring. It runs 1,000,000 synthetic packets and
prints raw alarm counts and a state checksum. The model runs on the host;
device-specific build files and management interfaces are not included in this
release.

```bash
cd code/6_dpu_data_plane
./run.sh
```

## Tofino2 data plane

Two forms of the two-pass program are provided:

| Form | Directory | TCAM cells | MAU SRAM words | SRAM units |
|---|---|---|---|---|
| SRAM lookup | `code/4_dataplane_deployed_p4/src/sram` | 8 (1.67%) | 11,264 | 73 |
| TCAM lookup | `code/4_dataplane_deployed_p4/src/tcam` | 29 (6.04%) | 2,048 | 76 |

Both compile to 90 physical tables (89 algorithmic plus the shared IPv4 LPM
table), 12 stages, and 13 stateful registers, each confined to a single MAU
stage; the register state is 500 KB (42 B per /24 entry at depth 8,192 and 41 B
per /16 entry at depth 4,096). Pass 1 reads the bucket state, decides per
packet, and emits a 28-B snapshot; pass 2 writes the new state. The final gates,
confirmation, and cross-prefix correlation run on the control plane.

```bash
cd code/4_dataplane_deployed_p4
SDE=/path/to/bf-sde-9.7.1 VARIANT=sram ./control/deploy_sweep_2pass.sh check
SDE=/path/to/bf-sde-9.7.1 VARIANT=sram ./control/deploy_sweep_2pass.sh build
SDE=/path/to/bf-sde-9.7.1 VARIANT=tcam ./control/deploy_sweep_2pass.sh build
```

Compile evidence is archived in `code/4_dataplane_deployed_p4/evidence/`
(`sram/` and `tcam/`, each with `summary.json`, `compiler.log`,
`resources.json`, and `mau.resources.log`). With `bf-p4c` 9.7.1 the SRAM form
compiles and places in 38.5 s and the TCAM form in 36.9 s, with zero placement
errors.

## Baseline P4 ports

`code/2_baselines_p4/` holds P4 ports of SegSketch, SpreadSketch, Couper, RHHH,
ElasticSketch, HeavyKeeper, MRB, and the two entropy baselines. The paper's
reported F1 numbers come from the Python implementations; the P4 ports cover
switch-resource accounting.

The SpreadSketch port uses the full 511.9-KB configuration (four rows,
W = 1820 buckets per row, 72 B per bucket). Load `setup_fold.py` after
`setup_tables.py`, and run `query_spreadsketch.py` with `W=1820`, which is the
default. The Couper port is a direct port that does not fit placement on Tofino2; it is
kept to document that finding.

## Data

`database/attack/` contains 101 gzipped CSV files (25,860,949 packets), one row
per packet:

```
ts,src,dst,proto,sport,dport
1780286476.261322,45.142.193.150,1.182.230.94,17,65333,26009
```

| Directory | Files | Packets | Contents |
|---|---:|---:|---|
| `normal_single24/` | 71 | 6,618,743 | Real captures, one destination /24 each, 10 attack types |
| `natural_multi24/` | 2 | 962,959 | Real captures spanning several /24s |
| `synthetic_multi24_by_timestamp/` | 13 | 8,658,144 | Multi-prefix samples interleaved by timestamp |
| `synthetic_multi24_shuffled/` | 15 | 9,621,103 | Multi-prefix samples with shuffled timestamps |

The files carry packet metadata only: no payloads, link-layer headers, or
capture metadata. `database/attack/SHA256SUMS.txt` lists the checksum of every
file.

The benign corpora are public. Download them and place them under
`database/benign/`:

| File | Source |
|---|---|
| `CIC-IDS-2017-Benign.pcap` | CIC-IDS-2017, University of New Brunswick |
| `CIC-IoT-2023-Benign.pcap`, `-Benign1.pcap`, `-Benign2.pcap`, `-Benign3.pcap` | CIC-IoT-2023, University of New Brunswick |

The optional backbone stress test (`exp9`) expects
`database/benign/202607051400.pcap`.

## Reference detector constants

The reference implementation uses the paper's frozen constants: `AGE_WIN = 4`,
`COOLDOWN_WIN = 20`, D2 confirmation on 2 of the last 3 windows, cross-prefix
`W = 4` and `K = 2` with a 12-destination signal, a quiet floor of 12, and
`Q_MAX_K = 16`.

## Provenance

The md5 of each P4 source is `11c0ee5171142f14b7f82f13c053adb7` (`headers.p4`),
`082bb52531a4c374290031f32c553d38` (`parser.p4`),
`20f1a4681b9fb3852a0cbd196d041004` (`src/sram/sweepsketch.p4`), and
`7dda6d7edcee01dcc86c26e7a1bc35c0` (`src/tcam/sweepsketch.p4`). The per-stage
resource tables produced by `bf-p4c` 9.7.1 are archived under
`code/4_dataplane_deployed_p4/evidence/`: 90 tables, 12 stages, 13 single-stage
registers, TCAM 8 or 29 cells, and SRAM 73 or 76 units.

## Citation

The paper is under review; cite it as:

```
SweepSketch: Detecting Carpet-Bombing Attacks Before They End.
Manuscript under review, 2026.
```
