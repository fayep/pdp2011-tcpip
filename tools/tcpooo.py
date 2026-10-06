#!/usr/bin/env python3
# Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
# free for non-commercial use with attribution (see LICENSE).
"""tcpooo.py <port>: out-of-order and SACK test against TCPIPD over the SIMH
UDP Ethernet link (as ethpeer.py; ETHPEER_IP = the PDP-11's address).
Connects to <port> (NC -L there), offers SACK, sends three segments in the
order 2, 3, 1 and checks the ACKs: after 2 and 3 the cumulative ACK stays at
the gap and a SACK block covers 2..3; after 1 it covers everything."""
import os, struct, sys, time
sys.argv, port = sys.argv[:1], int(sys.argv[1])
exec(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ethpeer.py')).read().split("\nif __name__")[0])
assert resolve(), 'no ARP reply'
SP = 40000 + os.getpid() % 20000
ISN = 1000000

def seg(seq, ack, flags, data=b'', opts=b''):
    hl = 20 + len(opts)
    th = struct.pack('!HHIIBBHHH', SP, port, seq, ack, (hl // 4) << 4, flags, 8192, 0, 0) + opts
    ph = MY_IP + PDP_IP + struct.pack('!BBH', 0, 6, hl + len(data))
    c = cksum(ph + th + data)
    th = th[:16] + struct.pack('!H', c) + th[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + hl + len(data), 1, 0x4000, 64, 6, 0, MY_IP, PDP_IP)
    ip = ip[:10] + struct.pack('!H', cksum(ip)) + ip[12:]
    send(PDP_MAC + MY_MAC + b'\x08\x00' + ip + th + data)

def wait_seg(t=5):
    for f in frames(t):
        if f[12:14] != b'\x08\x00' or f[23] != 6: continue
        h = f[14:]; hl = (h[0] & 15) * 4; th = h[hl:]
        if struct.unpack('!H', th[2:4])[0] != SP: continue
        doff = (th[12] >> 4) * 4
        sq, ak = struct.unpack('!II', th[4:12]); fl = th[13]
        opts = th[20:doff]; sack = []; sackp = False; o = 0
        while o < len(opts):
            k = opts[o]
            if k == 0: break
            if k == 1: o += 1; continue
            l = opts[o + 1]
            if k == 4: sackp = True
            if k == 5: sack = [struct.unpack('!II', opts[o + 2 + 8 * i:o + 10 + 8 * i]) for i in range((l - 2) // 8)]
            o += l
        return sq, ak, fl, sack, sackp, th[doff:struct.unpack('!H', h[2:4])[0] - hl]
    return None

ok = True
def check(what, cond):
    global ok
    print('%-55s %s' % (what, 'ok' if cond else 'FAILED')); ok &= bool(cond)

seg(ISN, 0, 0x02, opts=bytes([2, 4, 5, 180, 1, 1, 4, 2]))          # SYN, MSS 1460, SACK-permitted
r = wait_seg()
check('SYN-ACK received', r and r[2] & 0x12 == 0x12)
srv_isn, _, _, _, sackp, _ = r
check('the SYN-ACK allows SACK', sackp)
seg(ISN + 1, srv_isn + 1, 0x10)                                     # ACK
time.sleep(1)
d = [b'(segment one: the first hundred bytes of the stream)'.ljust(100, b'.'),
     b'(segment two: the second hundred bytes)'.ljust(100, b'.'),
     b'(segment three: the third hundred bytes)'.ljust(98, b'.') + b'\r\n']
base = ISN + 1
seg(base + 100, srv_isn + 1, 0x18, d[1])                           # 2 before 1
r = wait_seg()
check('after segment 2: cumulative ACK stays at the gap', r and r[1] == base)
check('after segment 2: SACK block = segment 2', r and (base + 100, base + 200) in r[3])
seg(base + 200, srv_isn + 1, 0x18, d[2])                           # then 3
r = wait_seg()
check('after segment 3: cumulative ACK still at the gap', r and r[1] == base)
check('after segment 3: SACK block covers 2..3', r and (base + 100, base + 300) in r[3])
seg(base, srv_isn + 1, 0x18, d[0])                                 # the hole
r = wait_seg()
check('after segment 1: cumulative ACK covers all three', r and r[1] == base + 300)
check('after segment 1: no SACK blocks left', r and not r[3])
seg(base + 300, srv_isn + 1, 0x11)                                 # FIN
fin = False
for i in range(6):
    r = wait_seg(5)
    if not r: break
    if r[2] & 0x01:
        fin = True
        seg(base + 301, r[0] + 1, 0x10)                             # ACK their FIN
        break
check('the other side closed too (FIN)', fin)
print('RESULT', 'PASS' if ok else 'FAIL')
