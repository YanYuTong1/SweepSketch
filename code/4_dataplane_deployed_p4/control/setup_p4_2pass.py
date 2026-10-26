import math
import sys
try:
    p4 = bfrt.sweepsketch.pipe.Ingress
except NameError:
    print('must run inside bfshell: $SDE_DIR/run_bfshell.sh -b setup_p4_2pass.py')
    sys.exit(1)
WIN_MAX = 7
assert WIN_MAX == 7
for c in range(1, 256):
    rho = 0 + (8 - 1 - int(math.floor(math.log2(c))))
    p4.clz0.add_with_act_clz(r_hi=c, rho_v=rho, done_v=1)
for c in range(1, 256):
    rho = 8 + (8 - 1 - int(math.floor(math.log2(c))))
    p4.clz1.add_with_act_clz(r_mid=c, rho_v=rho, done_v=1)
for c in range(1, 256):
    rho = 16 + (8 - 1 - int(math.floor(math.log2(c))))
    p4.clz2.add_with_act_clz(r_lo=c, rho_v=rho, done_v=1)
for c in range(1, 8):
    rho = 24 + (3 - 1 - int(math.floor(math.log2(c))))
    p4.clz3.add_with_act_clz(r_tail=c, rho_v=rho, done_v=1)
p4.t1_delta.add_with_act_delta(event=1, claim=0, rollover=0, d=38)
p4.t1_delta.add_with_act_dD(event=1, claim=0, rollover=1, dc=38)
p4.t1_delta.add_with_act_dD(event=1, claim=1, rollover=0, dc=38)
p4.t1_delta.add_with_act_dD(event=1, claim=1, rollover=1, dc=38)
p4.t1_delta.add_with_act_delta(event=0, claim=0, rollover=0, d=65498)
p4.t1_delta.add_with_act_dnegC(event=0, claim=0, rollover=1)
p4.t1_delta.add_with_act_dnegC(event=0, claim=1, rollover=0)
p4.t1_delta.add_with_act_dnegC(event=0, claim=1, rollover=1)
p4.t2_delta.add_with_act_delta2(event2=1, claim2=0, rollover2=0, d=38)
p4.t2_delta.add_with_act_dD2(event2=1, claim2=0, rollover2=1, dc=38)
p4.t2_delta.add_with_act_dD2(event2=1, claim2=1, rollover2=0, dc=38)
p4.t2_delta.add_with_act_dD2(event2=1, claim2=1, rollover2=1, dc=38)
p4.t2_delta.add_with_act_delta2(event2=0, claim2=0, rollover2=0, d=65498)
p4.t2_delta.add_with_act_dnegC2(event2=0, claim2=0, rollover2=1)
p4.t2_delta.add_with_act_dnegC2(event2=0, claim2=1, rollover2=0)
p4.t2_delta.add_with_act_dnegC2(event2=0, claim2=1, rollover2=1)
_n_wn = 0
for k in range(256):
    w = k & WIN_MAX
    assert 0 <= w <= WIN_MAX
    w1 = w + 1 & WIN_MAX
    assert 0 <= w1 <= WIN_MAX
    p4.tb1_wn0.add_with_act_wn(ep_old=k, v=w)
    p4.tb1_wn1.add_with_act_wn(ep_old=k, v=w1)
    p4.tb2_wn0.add_with_act_wn2(ep2_old=k, v=w)
    p4.tb2_wn1.add_with_act_wn2(ep2_old=k, v=w1)
    _n_wn += 4
assert _n_wn == 1024, _n_wn
_N_TAG = 0
for tag in range(8):
    for win in range(8):
        assert 0 <= win <= WIN_MAX
        if tag != win:
            p4.t1_tag.add_with_set_evt1(hll_rv=tag, win_new=win)
            p4.t2_tag.add_with_set_evt2(hll2_rv=tag, win2_new=win)
            _N_TAG += 2
assert _N_TAG == 112, _N_TAG
_N_RHO = 0
for rv in range(32):
    for rho in range(32):
        if rv < rho:
            p4.t1_rho.add_with_set_evt1(hll_rv=rv, rho=rho)
            p4.t2_rho.add_with_set_evt2(hll2_rv=rv, rho=rho)
            _N_RHO += 2
assert _N_RHO == 992, _N_RHO
_N_HN = 0
for win in range(8):
    for rho in range(32):
        v = (win & 7) << 5 | rho & 31
        p4.t1_hllnew.add_with_act_hllnew1(win_new=win, rho=rho, v=v)
        p4.t2_hllnew.add_with_act_hllnew2(win2_new=win, rho=rho, v=v)
        _N_HN += 2
assert _N_HN == 512, _N_HN
_N_EN = 0
for epoch in range(32):
    for win in range(8):
        v = (epoch & 31) << 3 | win & 7
        p4.t1_epnew.add_with_act_epnew1(global_epoch=epoch, win_new=win, v=v)
        p4.t2_epnew.add_with_act_epnew2(global_epoch=epoch, win2_new=win, v=v)
        _N_EN += 2
assert _N_EN == 512, _N_EN
p4.forward_ipv4.add_with_set_egr(ingress_port=392, port=400)
p4.forward_ipv4.add_with_set_egr(ingress_port=400, port=392)

def _key_names(tbl, defaults):
    try:
        keys = tbl.info.key
        names = list(keys.keys()) if isinstance(keys, dict) else list(keys)
        if len(names) == len(defaults):
            return names
    except Exception:
        pass
    return defaults
_N_FL = 0
for claim in (0, 1):
    for roll in (0, 1):
        for skip in (0, 1):
            for ev in (0, 1):
                f = claim & 1 | (roll & 1) << 1 | (skip & 1) << 2 | (ev & 1) << 3
                p4.tb_rs_flags1.add_with_do_rs_flags1(claim=claim, rollover=roll, skip=skip, event=ev, f=f)
                p4.tb_rs_flags2.add_with_do_rs_flags2(claim2=claim, rollover2=roll, skip2=skip, event2=ev, f=f)
                _N_FL += 2
assert _N_FL == 32, _N_FL
_KN = _key_names(p4.tb_rs_dec1, ['l1_flags'])
_KN2 = _key_names(p4.tb_rs_dec2, ['l2_flags'])
_N_DEC = 0
for b in range(256):
    p4.tb_rs_dec1.add_with_do_rs_dec1(**{_KN[0]: b}, c=b >> 0 & 1, r=b >> 1 & 1, sk=b >> 2 & 1, ev=b >> 3 & 1)
    p4.tb_rs_dec2.add_with_do_rs_dec2(**{_KN2[0]: b}, c=b >> 0 & 1, r=b >> 1 & 1, sk=b >> 2 & 1, ev=b >> 3 & 1)
    _N_DEC += 2
assert _N_DEC == 512, _N_DEC
print('setup_p4_2pass done: P0b 3942 + rs flags 32 + rs dec 512 = 4486')
