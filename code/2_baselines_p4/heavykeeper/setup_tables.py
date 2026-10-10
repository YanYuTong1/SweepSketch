
import math
import sys

try:
    p4 = bfrt.heavykeeper.pipe.Ingress
except NameError:
    print("must run inside bfshell: $SDE_DIR/run_bfshell.sh -b setup_tables.py")
    sys.exit(1)


ROWS = 3
W = 16384                       
DECAY = 1.0 / 1.08              


DEV_PORT_MAP = {
    392: 400,
    400: 392,
}


print("[1/4] forward_ipv4 (392↔400)...")
for ingress_port, egress_port in DEV_PORT_MAP.items():
    added = False
    
    
    for key_name in ("ingress_port", "ig_intr_md.ingress_port",
                     "ig_intr_md_ingress_port"):
        if added:
            break
        try:
            p4.forward_ipv4.add_with_set_egr(
                **{key_name: ingress_port}, egr_port=egress_port
            )
            print(f"  ✓ ingress {ingress_port} → egress {egress_port} (key={key_name})")
            added = True
        except Exception as e:
            if "exists" in str(e).lower():
                
                print(f"  ✓ ingress {ingress_port} → egress {egress_port} (already exists)")
                added = True
                break
            
    if not added:
        print(f"  ✗ ingress {ingress_port} → egress {egress_port} all key names failed")


print("[2/4] decay threshold tables thr_tbl0/1/2 (256 entries each)...")
for r in range(ROWS):
    tbl = getattr(p4, "thr_tbl%d" % r)
    try:
        tbl.clear()
    except Exception as e:
        print(f"  ⚠ thr_tbl{r} clear failed: {e}")
    key_name = "c8_r%d" % r
    act_name = "act_thr%d" % r
    for c in range(256):
        
        thr = min(int(math.floor((2 ** 32) * (DECAY ** c))), 0xFFFFFFFF)
        add_fn = getattr(tbl, "add_with_%s" % act_name)
        add_fn(**{key_name: c}, t=thr)
    print(f"  ✓ thr_tbl{r}: 256 entries written (c=0→0x{min(0xFFFFFFFF, 2**32):08X}, "
          f"c=1→{int(math.floor((2**32)*DECAY))}, c=255→"
          f"{int(math.floor((2**32)*(DECAY**255)))})")


print("[3/4] clear heap_keys + reset hmin_reg to 0 (unsynced = empty Python heap)...")
try:
    p4.heap_keys.clear()
    print("  ✓ heap_keys cleared")
except Exception as e:
    print(f"  ⚠ heap_keys clear failed: {e}")
try:
    
    p4.hmin_reg.mod(REGISTER_INDEX=0, f1=0)
    print("  ✓ hmin_reg = 0")
except Exception as e:
    print(f"  ⚠ hmin_reg reset failed: {e}")


if "--reset" in sys.argv:
    print("[4/4] --reset: zero all fp/cnt (slow; please be patient)...")
    for r in range(ROWS):
        for kind in ("fp", "cnt"):
            reg = getattr(p4, "%s_r%d" % (kind, r))
            for i in range(W):
                try:
                    reg.mod(REGISTER_INDEX=i, f1=0)
                except Exception:
                    pass
                if i % 4096 == 0:
                    print(f"    {kind}_r{r}: {i}/{W}")
        print(f"  ✓ {r} rows zeroed")
else:
    print("[4/4] skipping register zeroing (registers start at 0 on a cold switchd start; add --reset if needed)")

print("setup_tables done: forward 2 + thr_tbl×3 768 + heap reset")
