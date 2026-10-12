#!/usr/bin/env python3
# Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
# free for non-commercial use with attribution (see LICENSE).
"""tlibpeer.py <library folder> [udp-port-in udp-port-out]

The MiSTer tape library (MiSTer_pdp2011 support/pdp2011/tapelib.cpp) for
TLOAD/TDIR tests in SIMH: answers the guest's 88-B5 "TLIB" frames on SIMH's
UDP Ethernet, serving a local folder as the library. Attach the XU with
    attach xu udp:7101:localhost:7102
(the defaults: SIMH sends to 7102, we send to 7101). Loads are only
recorded (there is no tape drive to mount on); STATUS reports the last.
Same rules as tapelib.cpp: '/'-separated paths, case-insensitive per
component; '.'/'_' folders and folders with no tapes below them are not
listed; a bare name is looked for in every listed folder.
"""
import os, socket, struct, sys

LIB_MAC = bytes.fromhex('02504450544C')
OK, NOFILE, BADNAME, FAILED, BADOP, EMPTY, NODIR, AMBIG = range(8)
DEPTH, DATAMAX, PATHMAX = 4, 1400, 128
PLAIN = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-$+')

root = os.path.abspath(sys.argv[1])
pin, pout = (int(sys.argv[2]), int(sys.argv[3])) if len(sys.argv) > 3 else (7102, 7101)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('127.0.0.1', pin))
loaded = None

def plain(n):
    return 0 < len(n) <= 64 and n[0] != '.' and all(c in PLAIN for c in n)

def tape(n):
    return len(n) >= 5 and plain(n) and n[-4:].lower() in ('.tap', '.tpc')

def shown(n):
    return n[0] != '_' and plain(n)

def has_tapes(p, depth):
    for e in os.listdir(p):
        q = os.path.join(p, e)
        if tape(e) and os.path.isfile(q): return True
        if depth < DEPTH and shown(e) and os.path.isdir(q) and has_tapes(q, depth + 1): return True
    return False

def resolve(rel, want_dir):
    """-> the real path relative to root, or None"""
    parts = [c for c in rel.split('/') if c]
    if not parts: return '' if want_dir else None
    cur = ''
    for i, c in enumerate(parts):
        if not plain(c) or i > DEPTH: return None
        hit = [e for e in os.listdir(os.path.join(root, cur)) if e.lower() == c.lower()]
        if not hit: return None
        cur = os.path.join(cur, hit[0]) if cur else hit[0]
        isdir = os.path.isdir(os.path.join(root, cur))
        if i < len(parts) - 1 or want_dir:
            if not isdir: return None
        elif isdir or not tape(hit[0]): return None
    return cur

def scan(rel):
    p = os.path.join(root, rel)
    tapes = sorted([e for e in os.listdir(p) if tape(e) and os.path.isfile(os.path.join(p, e))], key=str.lower)
    dirs = sorted([e + '/' for e in os.listdir(p) if shown(e) and os.path.isdir(os.path.join(p, e))
                   and has_tapes(os.path.join(p, e), 1)], key=str.lower)
    return dirs + tapes

def find(rel, want, depth, out):
    p = os.path.join(root, rel)
    for e in os.listdir(p):
        q = os.path.join(rel, e) if rel else e
        if tape(e) and e.lower() == want.lower() and os.path.isfile(os.path.join(root, q)): out.append(q)
        elif depth < DEPTH and shown(e) and os.path.isdir(os.path.join(root, q)): find(q, want, depth + 1, out)
    return out

def answer(f):
    global loaded
    q = f[14:]
    op, dlen = q[4], struct.unpack('>H', q[8:10])[0]
    data = q[10:10 + dlen]
    st, d = OK, b''
    if op == 1:
        want = data.decode('latin-1')
        base = want.rsplit('/', 1)[-1]
        if not (1 <= dlen <= PATHMAX) or not tape(base): st = BADNAME
        else:
            path = resolve(want, False)
            if path is None and '/' not in want:
                hits = sorted(find('', want, 0, []), key=str.lower)
                if len(hits) == 1: path = hits[0]
                elif hits: st, d = AMBIG, b''.join(h.encode() + b'\0' for h in hits)[:DATAMAX]
            if st == OK:
                if path is None: st = NOFILE
                else:
                    loaded = path
                    print('  load', path, flush=True)
                    d = path.encode() + b'\0SIMH'
    elif op == 2:
        loaded = None
        print('  unload', flush=True)
    elif op == 3:
        first = struct.unpack('>H', data[:2])[0] if dlen >= 2 else 0
        rel = resolve(data[2:].decode('latin-1'), True)
        if rel is None: st = NODIR
        else:
            names = scan(rel)
            d, here = b'', 0
            for n in names[first:]:
                b = n.encode() + b'\0'
                if 4 + len(d) + len(b) > DATAMAX: break
                d += b; here += 1
            d = struct.pack('>HH', len(names), here) + d
    elif op == 4:
        if loaded: d = loaded.encode() + b'\0SIMH'
        else: st = EMPTY
    else:
        st = BADOP
    r = f[6:12] + LIB_MAC + b'\x88\xb5' + b'TLIB' + bytes([op | 0x80, st]) + q[6:8] + struct.pack('>H', len(d)) + d
    return r + b'\0' * max(0, 60 - len(r))

print('tlibpeer: library %s, udp %d -> %d' % (root, pin, pout), flush=True)
while True:
    f, _ = sock.recvfrom(2048)
    if len(f) >= 24 and f[12:14] == b'\x88\xb5' and f[14:18] == b'TLIB':
        print('op %d seq %d from %s' % (f[18], struct.unpack('>H', f[20:22])[0], f[6:12].hex('-')), flush=True)
        sock.sendto(answer(f), ('127.0.0.1', pout))
