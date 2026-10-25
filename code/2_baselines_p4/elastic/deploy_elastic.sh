#!/bin/bash
set -e

P4=${P4:-elastic_rs}
P4_DIR="$(cd "$(dirname "$0")" && pwd)"
SDE=${SDE:-/sde/bf-sde-9.7.1}

build() {
    . $SDE/set_sde.bash
    export P4FLAGS="--Wdisable=duplicate"
    $SDE/p4_build.sh "$P4_DIR/$P4.p4" --with-tofino2
    echo "build DONE ($P4)"
}

run() {
    . $SDE/set_sde.bash
    ( until $SDE/run_bfshell.sh -c "exit" >/dev/null 2>&1; do sleep 3; done
      $SDE/run_bfshell.sh -c "ucli; pm; port-add 1/0 100G RS; port-add 2/0 100G RS; port-enb 1/0; port-enb 2/0; show; ..; ..; exit"
      $SDE/run_bfshell.sh -b "$P4_DIR/setup_tables.py"
      echo "ports+tables ready ($P4)"
    ) &
    $SDE/run_switchd.sh -p $P4 --arch tf2
}

deploy() {
    build
    run
}

clean() {
    rm -rf $SDE/build/p4-build/tofino2/$P4
    rm -rf $SDE/logs/p4-build/tofino2/$P4
    echo "clean DONE ($P4)"
}

case "${1:-deploy}" in
    build)  build ;;
    run)    run ;;
    deploy) deploy ;;
    clean)  clean ;;
    *) echo "  : $0 {build|run|deploy|clean}   [P4=elastic_rs|elastic]"; exit 1 ;;
esac
