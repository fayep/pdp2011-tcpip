#!/usr/bin/env python3
# Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
# free for non-commercial use with attribution (see LICENSE).
"""ethpeer.py - a raw-Ethernet test peer for the RSTS/E IP programs in SIMH.

SIMH's XU is attached with  attach xu udp:7101:localhost:7102 , so every
Ethernet frame it sends arrives here as one UDP datagram on port 7102, and
datagrams sent to port 7101 appear on its wire. This plays a host on that
wire: it sends ARP requests, pings and (later) TFTP, and checks the replies.

usage: ethpeer.py arp | ping [count] | sniff [seconds]
       ethpeer.py get <remote> <local> | put <local> <remote>
       ethpeer.py dhcpd <ip> <lease-seconds> <run-seconds>   (DHCP server, then ping+get)
"""
import socket, struct, sys, time, os

PDP_IP = bytes(int(x) for x in os.environ.get('ETHPEER_IP', '192.168.51.240').split('.'))
PDP_MAC = bytes.fromhex('AA0004000A04')     # DECnet node 1.10 on the dev system
MY_MAC = bytes.fromhex('020000000001')      # locally administered
MY_IP = bytes([192, 168, 51, 10])
BCAST = b'\xff' * 6

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('127.0.0.1', 7102))
SIMH = ('127.0.0.1', 7101)

def send(frame):
    if os.environ.get('ETHPEER_DEBUG') and frame[12:14] == b'\x08\x00' and frame[23] == 17:
        u = frame[14 + (frame[14] & 15) * 4:]
        print('    tx %.3f udp %d->%d op %d blk %d' % ((time.time() % 100,) + struct.unpack('!HH', u[:4]) + struct.unpack('!HH', u[8:12])))
    if len(frame) < 60:
        frame += b'\0' * (60 - len(frame))
    sock.sendto(frame, SIMH)

def frames(seconds):
    end = time.time() + seconds
    while True:
        left = end - time.time()
        if left <= 0:
            return
        sock.settimeout(left)
        try:
            data, _ = sock.recvfrom(2048)
        except socket.timeout:
            return
        yield data

def cksum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def ip(b):
    return '.'.join(str(x) for x in b)

def mac(b):
    return '-'.join('%02X' % x for x in b)

def describe(f):
    t = struct.unpack('!H', f[12:14])[0]
    return '%s -> %s type %04X len %d' % (mac(f[6:12]), mac(f[0:6]), t, len(f))

def resolve():
    """find the PDP-11's MAC by ARP, as a real client would"""
    global PDP_MAC
    req = (BCAST + MY_MAC + b'\x08\x06' +
           struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) + MY_MAC + MY_IP + b'\0' * 6 + PDP_IP)
    for attempt in range(3):
        send(req)
        for f in frames(2):
            if f[12:14] == b'\x08\x06' and struct.unpack('!H', f[20:22])[0] == 2 and f[28:32] == PDP_IP:
                PDP_MAC = bytes(f[22:28])
                return True
    print('no ARP reply from %s' % ip(PDP_IP))
    return False

def arp():
    req = (BCAST + MY_MAC + b'\x08\x06' +
           struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) + MY_MAC + MY_IP + b'\0' * 6 + PDP_IP)
    send(req)
    for f in frames(5):
        if f[12:14] == b'\x08\x06' and struct.unpack('!H', f[20:22])[0] == 2 and f[28:32] == PDP_IP:
            print('ARP reply: %s is at %s (frame from %s, to %s)' % (ip(f[28:32]), mac(f[22:28]), mac(f[6:12]), mac(f[0:6])))
            return f[22:28] == PDP_MAC
        print('  (other frame: %s)' % describe(f))
    print('no ARP reply')
    return False

def ping(count=4):
    ok = 0
    for seq in range(count):
        payload = b'rsts-ping %02d ' % seq + bytes(range(32))
        icmp = struct.pack('!BBHHH', 8, 0, 0, 0x1234, seq) + payload
        icmp = icmp[:2] + struct.pack('!H', cksum(icmp)) + icmp[4:]
        hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(icmp), seq, 0, 64, 1, 0, MY_IP, PDP_IP)
        hdr = hdr[:10] + struct.pack('!H', cksum(hdr)) + hdr[12:]
        t0 = time.time()
        send(PDP_MAC + MY_MAC + b'\x08\x00' + hdr + icmp)
        got = False
        for f in frames(3):
            if f[12:14] != b'\x08\x00' or f[23] != 1:
                print('  (other frame: %s)' % describe(f))
                continue
            h = f[14:]; hl = (h[0] & 15) * 4; ic = h[hl:struct.unpack('!H', h[2:4])[0]]
            good = (cksum(h[:hl]) == 0 and cksum(ic) == 0 and ic[0] == 0 and
                    struct.unpack('!HH', ic[4:8]) == (0x1234, seq) and ic[8:] == payload and h[12:16] == PDP_IP)
            print('reply seq %d from %s: %.0f ms, %s' % (seq, ip(h[12:16]), (time.time() - t0) * 1000,
                                                        'checksums and data OK' if good else 'BAD'))
            ok += good; got = True
            break
        if not got:
            print('seq %d: no reply' % seq)
    print('%d/%d replies OK' % (ok, count))
    return ok == count

def sniff(seconds=10):
    for f in frames(seconds):
        print(describe(f))

def udp_frame(sport, dport, payload):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = MY_IP + PDP_IP + struct.pack('!BBH', 0, 17, len(u))
    c = cksum(ph + u) or 0xffff
    u = u[:6] + struct.pack('!H', c) + u[8:]
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 0, 0, 64, 17, 0, MY_IP, PDP_IP)
    h = h[:10] + struct.pack('!H', cksum(h)) + h[12:]
    return PDP_MAC + MY_MAC + b'\x08\x00' + h + u

import os
DEBUG = os.environ.get('ETHPEER_DEBUG')

def udp_recv(port, seconds):
    """next UDP datagram to our port: (sport, payload), checksums verified"""
    for f in frames(seconds):
        if DEBUG:
            extra = ''
            if f[12:14] == b'\x08\x00' and f[23] == 17:
                u = f[14 + (f[14] & 15) * 4:]
                extra = ' udp %d->%d op %d blk %d' % (struct.unpack('!HH', u[:4]) + struct.unpack('!HH', u[8:12]))
            print('    rx %.3f %s%s' % (time.time() % 100, describe(f), extra))
        if f[12:14] != b'\x08\x00' or f[23] != 17:
            continue
        h = f[14:]; hl = (h[0] & 15) * 4; tot = struct.unpack('!H', h[2:4])[0]
        u = h[hl:tot]
        sp, dp, ul, uc = struct.unpack('!HHHH', u[:8])
        if dp != port:
            continue
        assert cksum(h[:hl]) == 0, 'bad IP checksum'
        if uc:
            if cksum(h[12:20] + struct.pack('!BBH', 0, 17, ul) + u[:ul]) != 0:
                print('BAD UDP checksum: stored %04X, IP total %d, UDP len %d, frame %d bytes' % (uc, tot, ul, len(f)))
                print('  ' + f[:min(len(f), 80)].hex())
                raise AssertionError('bad UDP checksum')
        return sp, u[8:ul]
    return None, None

# a fresh source port for every transfer, as real TFTP clients use: a fixed
# one would pick up resends from an earlier transfer the server still runs
MYPORT = 40000 + os.getpid() % 20000
def tftp_get(remote, local):
    if not resolve():
        return False
    send(udp_frame(MYPORT, 69, b'\0\1' + remote.encode() + b'\0octet\0'))
    data = b''; expect = 1; t0 = time.time(); server = None
    while True:
        sp, p = udp_recv(MYPORT, 5)
        if p is None:
            print('timeout waiting for block %d' % expect); return False
        op, blk = struct.unpack('!HH', p[:4])
        if op == 5:
            print('server error %d: %s' % (blk, p[4:].split(b'\0')[0].decode())); return False
        if op != 3 or blk != expect:
            continue
        server = sp
        data += p[4:]
        send(udp_frame(MYPORT, server, struct.pack('!HH', 4, blk)))
        expect += 1
        if len(p) - 4 < 512:
            break
    open(local, 'wb').write(data)
    dt = time.time() - t0
    print('got %s: %d bytes in %d blocks, %.1f s (%.0f bytes/s)' % (remote, len(data), expect - 1, dt, len(data) / dt))
    return True

def tftp_put(local, remote):
    if not resolve():
        return False
    data = open(local, 'rb').read()
    send(udp_frame(MYPORT, 69, b'\0\2' + remote.encode() + b'\0octet\0'))
    sp, p = udp_recv(MYPORT, 5)
    if p is None or struct.unpack('!HH', p[:4]) != (4, 0):
        print('no ACK 0: %r' % (p,)); return False
    server = sp; blk = 1; t0 = time.time()
    while True:
        chunk = data[(blk - 1) * 512: blk * 512]
        for attempt in range(5):
            send(udp_frame(MYPORT, server, struct.pack('!HH', 3, blk) + chunk))
            sp, p = udp_recv(MYPORT, 3)
            if p is not None and struct.unpack('!HH', p[:4]) == (4, blk):
                break
        else:
            print('no ACK for block %d' % blk); return False
        if len(chunk) < 512:
            break
        blk += 1
    dt = time.time() - t0
    print('put %s as %s: %d bytes in %d blocks, %.1f s' % (local, remote, len(data), blk, dt))
    return True

def dhcp_reply(req, mtype, yiaddr, lease):
    xid = req[4:8]; chaddr = req[28:44]
    b = bytearray(240)
    b[0] = 2; b[1] = 1; b[2] = 6
    b[4:8] = xid; b[10:12] = req[10:12]
    b[16:20] = yiaddr; b[20:24] = MY_IP; b[28:44] = chaddr
    b[236:240] = bytes([99, 130, 83, 99])
    opts = bytes([53, 1, mtype, 54, 4]) + MY_IP + bytes([1, 4, 255, 255, 254, 0, 3, 4, 192, 168, 50, 1])
    opts += bytes([51, 4]) + struct.pack('!I', lease) + bytes([58, 4]) + struct.pack('!I', lease // 2) + b'\xff'
    payload = bytes(b) + opts
    payload += b'\0' * max(0, 300 - len(payload))
    u = struct.pack('!HHHH', 67, 68, 8 + len(payload), 0) + payload
    dst = b'\xff' * 4
    c = cksum(MY_IP + dst + struct.pack('!BBH', 0, 17, len(u))) 
    c = cksum(MY_IP + dst + struct.pack('!BBH', 0, 17, len(u)) + u) or 0xffff
    u = u[:6] + struct.pack('!H', c) + u[8:]
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 0, 0, 64, 17, 0, MY_IP, dst)
    h = h[:10] + struct.pack('!H', cksum(h)) + h[12:]
    send(b'\xff' * 6 + MY_MAC + b'\x08\x00' + h + u)

def dhcpd(ip_s, lease, run):
    global PDP_IP, PDP_MAC
    yiaddr = bytes(int(x) for x in ip_s.split('.'))
    end = time.time() + run; bound = 0; renewals = 0; tested = False
    names = {1: 'DISCOVER', 3: 'REQUEST', 4: 'DECLINE', 7: 'RELEASE', 8: 'INFORM'}
    while time.time() < end:
        for f in frames(min(2, max(0.1, end - time.time()))):
            if f[12:14] != b'\x08\x00' or f[23] != 17:
                continue
            h = f[14:]; hl = (h[0] & 15) * 4; u = h[hl:]
            sp, dp = struct.unpack('!HH', u[:4])
            if (sp, dp) != (68, 67):
                continue
            b = u[8:]; o = 240; mt = 0; opts = {}
            while o < len(b) and b[o] != 255:
                if b[o] == 0: o += 1; continue
                opts[b[o]] = b[o + 2:o + 2 + b[o + 1]]; o += 2 + b[o + 1]
            mt = opts.get(53, b'\0')[0]
            t = time.strftime('%H:%M:%S')
            print('%s %s from %s, xid %s, ciaddr %s, src IP %s, host name %r' % (t, names.get(mt, mt), mac(b[28:34]), b[4:8].hex(),
                  ip(b[12:16]), ip(h[12:16]), opts.get(12, b'').decode('latin-1')))
            if mt == 1:
                dhcp_reply(b, 2, yiaddr, lease); print('         -> OFFER %s, lease %d s' % (ip(yiaddr), lease))
            elif mt == 3:
                dhcp_reply(b, 5, yiaddr, lease); print('         -> ACK')
                if b[12:16] == yiaddr: renewals += 1
                else: bound += 1
                PDP_MAC = bytes(b[28:34])
        if bound and not tested:
            tested = True
            PDP_IP = yiaddr
            time.sleep(1)
            print('--- bound: ping and TFTP to %s' % ip(yiaddr))
            ping(2); tftp_get('HELLO.C', os.path.join(os.environ.get('TMPDIR', '/tmp'), 'ethpeer_dhcp_hello.c'))
    print('DHCP: %d bound, %d renewals' % (bound, renewals))
    return bound >= 1

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'dhcpd':
        sys.exit(0 if dhcpd(sys.argv[2], int(sys.argv[3]), float(sys.argv[4])) else 1)
    if len(sys.argv) > 1 and sys.argv[1] == 'get':
        sys.exit(0 if tftp_get(sys.argv[2], sys.argv[3]) else 1)
    if len(sys.argv) > 1 and sys.argv[1] == 'put':
        sys.exit(0 if tftp_put(sys.argv[2], sys.argv[3]) else 1)
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'sniff'
    if cmd == 'arp':
        sys.exit(0 if arp() else 1)
    if cmd == 'ping':
        sys.exit(0 if ping(int(sys.argv[2]) if len(sys.argv) > 2 else 4) else 1)
    sniff(float(sys.argv[2]) if len(sys.argv) > 2 else 10)
