

import sys



DEV_PORT_MAP = {
    392: 400,
    400: 392,
}


def _find_ingress():
    
    for name in ("elastic_rs", "elastic"):
        try:
            return getattr(bfrt, name).pipe.Ingress  # noqa: F821(bfshell  environment)
        except (NameError, AttributeError):
            continue
    return None


def main():
    p4 = _find_ingress()
    if p4 is None:
        print("Error: bfrt unavailable. This script must run inside bfshell.")
        print("Usage: $SDE_DIR/run_bfshell.sh -b setup_tables.py")
        sys.exit(1)

    
    print("[1/2] clearing existing entries ...")
    for tname in ("forward_ipv4",):
        try:
            getattr(p4, tname).clear()
            print(f"  ✓ {tname} cleared")
        except Exception as e:
            print(f"  ⚠ {tname} clear failed: {e}")

    
    
    
    print("[2/2] forward_ipv4 (port forwarding) ...")
    KEY_NAMES = ("ingress_port", "ig_intr_md.ingress_port",
                 "ig_intr_md_ingress_port")
    for ingress_port, egress_port in DEV_PORT_MAP.items():
        added = False
        for key_name in KEY_NAMES:
            if added:
                break
            try:
                p4.forward_ipv4.add_with_set_egr(
                    **{key_name: ingress_port}, egr_port=egress_port
                )
                print(f"  ✓ ingress {ingress_port} → egress {egress_port} "
                      f"(key={key_name})")
                added = True
            except Exception as e:
                if "exists" in str(e).lower():
                    
                    print(f"  ✓ ingress {ingress_port} → egress {egress_port} "
                          f"(already exists)")
                    added = True
                    break
                
        if not added:
            print(f"  ✗ ingress {ingress_port} → egress {egress_port} "
                  f"all key names failed")

    
    print("\n[verify] forward_ipv4 read back:")
    for ingress_port in DEV_PORT_MAP.keys():
        found = False
        for key_name in KEY_NAMES:
            try:
                p4.forward_ipv4.get(**{key_name: ingress_port},
                                    print_ents=False)
                found = True
                print(f"  ✓ ingress {ingress_port} confirmed present (use {key_name})")
                break
            except Exception:
                continue
        if not found:
            print(f"  ✗ ingress {ingress_port} not readable! (add may have failed)")

        print("[3/3] tb_evx (256 entries: ev_val=k&0x7F, ev_flag=k>>7, decision 103)...")
    for k in range(256):
        p4.tb_evx.add_with_act_evx(wmin=k, v=k & 0x7F, f=k >> 7)

print("\n[done] ElasticSketch control plane initialized.")


if __name__ == "__main__":
    main()
