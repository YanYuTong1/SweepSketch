import sys
DEV_PORT_MAP = {392: 400, 400: 392}

def _find_ingress():
    for name in ('elastic_rs', 'elastic'):
        try:
            return getattr(bfrt, name).pipe.Ingress
        except (NameError, AttributeError):
            continue
    return None

def main():
    p4 = _find_ingress()
    if p4 is None:
        pass
        pass
        sys.exit(1)
    pass
    for tname in ('forward_ipv4',):
        try:
            getattr(p4, tname).clear()
            pass
        except Exception as e:
            pass
    pass
    KEY_NAMES = ('ingress_port', 'ig_intr_md.ingress_port', 'ig_intr_md_ingress_port')
    for ingress_port, egress_port in DEV_PORT_MAP.items():
        added = False
        for key_name in KEY_NAMES:
            if added:
                break
            try:
                p4.forward_ipv4.add_with_set_egr(**{key_name: ingress_port}, egr_port=egress_port)
                pass
                added = True
            except Exception as e:
                if 'exists' in str(e).lower():
                    pass
                    added = True
                    break
        if not added:
            pass
    pass
    for ingress_port in DEV_PORT_MAP.keys():
        found = False
        for key_name in KEY_NAMES:
            try:
                p4.forward_ipv4.get(**{key_name: ingress_port}, print_ents=False)
                found = True
                pass
                break
            except Exception:
                continue
        if not found:
            pass
        pass
    for k in range(256):
        p4.tb_evx.add_with_act_evx(wmin=k, v=k & 127, f=k >> 7)
pass
if __name__ == '__main__':
    main()
