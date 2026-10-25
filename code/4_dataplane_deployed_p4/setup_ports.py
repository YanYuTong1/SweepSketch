import sys
PORTS = [(392, 'BF_SPEED_100G', 'BF_FEC_TYP_REED_SOLOMON'), (400, 'BF_SPEED_100G', 'BF_FEC_TYP_REED_SOLOMON')]
try:
    pt = bfrt.port.port
except (NameError, AttributeError) as e:
    pass
    sys.exit(1)
pass
for dp, speed, fec in PORTS:
    try:
        pt.add(DEV_PORT=dp, SPEED=speed, FEC=fec, PORT_ENABLE=True, AUTO_NEGOTIATION='PM_AN_DEFAULT')
        pass
    except Exception as e:
        try:
            pt.mod(DEV_PORT=dp, PORT_ENABLE=True)
            pass
        except Exception as e2:
            pass
pass
