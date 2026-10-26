import sys

try:
    p4 = bfrt.spreadsketch.pipe.Ingress
except NameError:
    print('must run inside bfshell')
    sys.exit(1)

W = 1820
N = 2048
for i in range(4):
    tbl = getattr(p4, 'fold_r%d' % i)
    add = getattr(tbl, 'add_with_act_fold%d' % i)
    for x in range(N):
        add(v=(x - W if x >= W else x))
print('fold tables filled: 4 x %d entries, W=%d' % (N, W))
