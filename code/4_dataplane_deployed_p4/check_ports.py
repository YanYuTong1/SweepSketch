import sys
try:
    bfrt.port
except NameError:
    pass
    sys.exit(1)
for dp in (392, 400):
    print('=' * 60)
    pass
    try:
        pst = bfrt.port.port_stat
        pst.get(DEV_PORT=dp, from_hw=True, print_ents=True)
    except Exception as e1:
        pass
        try:
            info = bfrt.port.info()
            pass
            print(info)
        except Exception as e2:
            pass
print('=' * 60)
