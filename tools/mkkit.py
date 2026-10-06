#!/usr/bin/env python3
# Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
# free for non-commercial use with attribution (see LICENSE).
"""mkkit.py <rsts-written.tap> <c-kit.tap> <out.tap>

Assemble the RSTS/E TCP/IP Auto-Install kit tape: the ANSI volume RSTS's
BACKUP wrote (VOL1 + TCPTCP.BCK, TCPREL.BCK, TCP010.A), with Auto-Install's
own savesets (AUTVER.BCK, AUT101.A) copied in front from a DEC kit, as DEC's
layered-product kits carry them. Every HDR1/EOF1/EOV1 is given the volume's
file-set identifier and the files are renumbered 1..n in tape order, so the
labels are consistent; saveset data is copied unchanged.
"""
import struct, sys

def records(path):
    d = open(path, 'rb').read(); p = 0; out = []
    while p + 4 <= len(d):
        n = struct.unpack('<I', d[p:p + 4])[0]
        if n == 0:
            out.append(None); p += 4; continue           # tape mark
        if n == 0xFFFFFFFF:
            break
        l = n & 0x7FFFFFFF
        out.append(d[p + 4:p + 4 + l]); p += 4 + l + (l & 1) + 4
    return out

def files(recs):
    """split after VOL1 into ANSI file sections: HDR..TM data TM EOF..TM"""
    secs = []; i = 1 if recs and recs[0] and recs[0][:4] == b'VOL1' else 0
    while i < len(recs):
        if recs[i] is None:
            i += 1; continue
        assert recs[i][:4] == b'HDR1', recs[i][:20]
        j = i; tms = 0
        while j < len(recs) and tms < 3:
            if recs[j] is None: tms += 1
            j += 1
        secs.append(recs[i:j]); i = j
    return secs

def name(sec):
    return sec[0][4:21].decode().strip()

def relabel(sec, fsid, seq):
    out = []
    for r in sec:
        if r is not None and r[:4] in (b'HDR1', b'EOF1', b'EOV1'):
            r = r[:21] + fsid + r[27:31] + b'%04d' % seq + r[35:]
        out.append(r)
    return out

def rec(b):
    return struct.pack('<I', len(b)) + b + (b'\0' if len(b) & 1 else b'') + struct.pack('<I', len(b))

ours, dec, dst = sys.argv[1:4]
r1 = records(ours); r2 = records(dec)
vol1 = r1[0]; assert vol1[:4] == b'VOL1', 'no VOL1 on ' + ours
fsid = vol1[4:10]
dsec = {name(s): s for s in files(r2)}
osecs = files(r1)
order = [dsec['AUTVER.BCK'], dsec['AUT101.A']] + osecs
out = rec(vol1)
for k, s in enumerate(order, 1):
    for r in relabel(s, fsid, k):
        out += struct.pack('<I', 0) if r is None else rec(r)
out += struct.pack('<I', 0) + b'\xff\xff\xff\xff'     # extra tape mark (end of volume), EOM
open(dst, 'wb').write(out)
print('volume %s: ' % vol1[4:10].decode().strip() + ', '.join('%d %s' % (k, name(s)) for k, s in enumerate(order, 1)))
