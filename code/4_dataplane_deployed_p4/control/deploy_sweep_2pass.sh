#!/bin/bash
set -euo pipefail

P4_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SDE="${SDE:-/sde/bf-sde-9.7.1}"
VARIANT="${VARIANT:-sram}"
P4_NAME=sweepsketch

case "$VARIANT" in
    sram) SRC="$P4_ROOT/src" ;;
    tcam) SRC="$P4_ROOT/src-tcam" ;;
    *) echo "unknown VARIANT=$VARIANT (use sram or tcam)" >&2; exit 2 ;;
esac

MD5_HEADERS=11c0ee5171142f14b7f82f13c053adb7
MD5_PARSER=082bb52531a4c374290031f32c553d38
MD5_SRAM=20f1a4681b9fb3852a0cbd196d041004
MD5_TCAM=7dda6d7edcee01dcc86c26e7a1bc35c0

md5_of() { md5sum "$1" 2>/dev/null | awk '{print $1}' || md5 -q "$1"; }

check() {
    local ok=1
    local want_main=$MD5_SRAM
    [ "$VARIANT" = tcam ] && want_main=$MD5_TCAM
    for pair in "headers.p4:$MD5_HEADERS" "parser.p4:$MD5_PARSER" "sweepsketch.p4:$want_main"; do
        f="${pair%%:*}"; want="${pair##*:}"
        got=$(md5_of "$SRC/$f")
        if [ "$got" != "$want" ]; then
            echo "md5 mismatch: $f got=$got want=$want"
            ok=0
        else
            echo "md5 ok: $f ($got)"
        fi
    done
    [ $ok -eq 1 ] || { echo "source does not match the shipped ${VARIANT} program" >&2; exit 2; }
}

build() {
    check
    . "$SDE/set_sde.bash"
    export P4FLAGS="--Wdisable=duplicate"
    "$SDE/p4_build.sh" "$SRC/sweepsketch.p4" --with-tofino2
    local bd="$SDE/build/p4-build/tofino2/$P4_NAME"
    for f in pipe/tofino2.bin pipe/context.json bfrt.json "$P4_NAME.conf"; do
        [ -f "$bd/$f" ] && echo "built: $f" || echo "missing: $bd/$f"
    done
}

run() {
    . "$SDE/set_sde.bash"
    ( until "$SDE/run_bfshell.sh" -c "exit" >/dev/null 2>&1; do sleep 3; done
      "$SDE/run_bfshell.sh" -b "$P4_ROOT/control/setup_ports.py"
      "$SDE/run_bfshell.sh" -b "$P4_ROOT/control/setup_p4_2pass.py"
      echo "ports and tables ready"
    ) &
    "$SDE/run_switchd.sh" -p "$P4_NAME" --arch tf2
}

clean() {
    rm -rf "$SDE/build/p4-build/tofino2/$P4_NAME"
    echo "build output removed"
}

case "${1:-}" in
    check) check ;;
    build) build ;;
    run)   run ;;
    deploy) build; run ;;
    clean) clean ;;
    *) echo "usage: $0 {check|build|run|deploy|clean}  (VARIANT=sram|tcam)" ; exit 2 ;;
esac
