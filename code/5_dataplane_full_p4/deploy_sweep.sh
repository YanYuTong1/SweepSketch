#!/bin/bash



set -e

P4_NAME=sweepsketch
P4_DIR="$(cd "$(dirname "$0")" && pwd)"
SDE=${SDE:-/sde/bf-sde-9.7.1}

build() {
    . $SDE/set_sde.bash
    export P4FLAGS="--Wdisable=duplicate"      
    $SDE/p4_build.sh "$P4_DIR/sweepsketch.p4" --with-tofino2
    echo "build DONE"
}

run() {
    . $SDE/set_sde.bash
    
    ( until $SDE/run_bfshell.sh -c "exit" >/dev/null 2>&1; do sleep 3; done
      $SDE/run_bfshell.sh -b "$P4_DIR/setup_ports.py"   
      $SDE/run_bfshell.sh -b "$P4_DIR/setup_tables.py"
      echo "ports+tables ready"
    ) &
    $SDE/run_switchd.sh -p $P4_NAME --arch tf2     
}

deploy() {
    build
    run
}

clean() {
    rm -rf $SDE/build/p4-build/tofino2/$P4_NAME
    rm -rf $SDE/logs/p4-build/tofino2/$P4_NAME
    echo "clean DONE"
}

case "${1:-deploy}" in
    build)  build ;;
    run)    run ;;
    deploy) deploy ;;
    clean)  clean ;;
    *) echo "Usage: $0 {build|run|deploy|clean}"; exit 1 ;;
esac
