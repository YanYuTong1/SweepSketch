import sys
PORTS = [(392, 'BF_SPEED_100G', 'BF_FEC_TYP_REED_SOLOMON'), (400, 'BF_SPEED_100G', 'BF_FEC_TYP_REED_SOLOMON')]
try:
    pt = bfrt.port.port
except (NameError, AttributeError) as e:
    print('error: bfrt.port.port unavailable ({})'.format(e))
    sys.exit(1)
print('[ports] adding ports via bfrt.port.port ...')
for dp, speed, fec in PORTS:
    try:
        pt.add(DEV_PORT=dp, SPEED=speed, FEC=fec, PORT_ENABLE=True, AUTO_NEGOTIATION='PM_AN_DEFAULT')
        print('  ✓ dev_port {:>4}  ({}, {})  ENABLED'.format(dp, speed, fec))
    except Exception as e:
        try:
            pt.mod(DEV_PORT=dp, PORT_ENABLE=True)
            print('  ok dev_port {:>4}  exists, re-enabling'.format(dp))
        except Exception as e2:
            print('  !  dev_port {:>4}  failed: add={}  mod={}'.format(dp, e, e2))
print('[ports] done; wait ~5 s and check pm show for OPR UP')
