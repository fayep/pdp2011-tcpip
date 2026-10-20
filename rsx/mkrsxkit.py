#!/usr/bin/env python3
# Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
# free for non-commercial use with attribution (see LICENSE).
"""mkrsxkit.py --rsts DISK --rsx DISK [--version 100] [--work DIR]

Build the PDP2011 RSX-11M-PLUS tools kit tape, dist/pdp2011_rsx_tools_vNNN.tap
(ANSI volume TLOAD: TLOAD.TSK, INSTALL.CMD, README.TXT and the sources), in
two SIMH runs on copies of the given disks (the originals are not touched):

 1. RSTS/E with PDP-11 C (the C kit's RSX libraries in [1,1]): compile
    TLORSX.C, write TLORSX.OBJ and [1,1]CFPURS.OLB to an ANSI transfer tape.
 2. RSX-11M-PLUS with MAC, TKB, DEUNA.MLB and RMS-11 (SYSGEN'd with XE:):
    read the transfer tape, assemble RSXIO.MAC, TKB @TLOBLD, write the kit.

Neither disk ships: they hold DEC software. The defaults match the dev
systems this was written on (RSTS account 1,20 / INSTALL, RSX SYSTEM /
SYSTEM); override with --rsts-user/--rsts-pass/--rsx-user/--rsx-pass.
SIMH: $SIMH, else ~/Source/simh-ekbee1/BIN/pdp11. Every SIMH process this
starts is stopped before it exits, also on errors.
"""
import argparse, os, pty, re, select, shutil, signal, struct, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SIMH = os.environ.get('SIMH', os.path.expanduser('~/Source/simh-ekbee1/BIN/pdp11'))
BASE = os.path.join(REPO, 'sim', 'base.ini')
RP06 = 174419968                    # an RP06 image without SIMH's footer

class Sim:
    """SIMH on a pty: send lines, wait for regexes in what it printed"""
    def __init__(self, ini, log):
        self.log = open(log, 'wb')
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execv(SIMH, ['pdp11', ini])
        self.buf = b''
        self.mark = 0

    def pump(self, t=0.2):
        r, _, _ = select.select([self.fd], [], [], t)
        if r:
            try:
                d = os.read(self.fd, 65536)
            except OSError:
                d = b''
            if not d:
                raise RuntimeError('SIMH exited; last output:\n' + self.text(max(0, len(self.buf) - 600)))
            self.buf += d
            self.log.write(d); self.log.flush()

    def text(self, frm=None):
        b = self.buf[self.mark if frm is None else frm:]
        return b.replace(b'\0', b'').replace(b'\r', b'').decode('latin-1')

    def expect(self, rx, tmo=60):
        """wait for rx in the output since the last send; returns the match text"""
        t0 = time.time()
        while time.time() - t0 < tmo:
            m = re.search(rx, self.text())
            if m:
                return self.text()
            self.pump()
        raise RuntimeError('timeout waiting for %r; last output:\n%s' % (rx, self.text()[-600:]))

    def send(self, line, cr=True):
        self.mark = len(self.buf)
        os.write(self.fd, line.encode('latin-1') + (b'\r' if cr else b''))

    def cmd(self, line, rx, tmo=60):
        self.send(line)
        return self.expect(rx, tmo)

    def ctl(self, ch):
        self.mark = len(self.buf)
        os.write(self.fd, bytes([ord(ch) & 0x1f]))

    def type_file(self, path, start, end_rx):
        """type a text file line by line (each echo awaited), then ^Z"""
        self.cmd(start, r'\S', 10)
        time.sleep(0.5)
        for line in open(path).read().replace('\r', '').rstrip('\n').split('\n'):
            self.send(line)
            key = line.strip()[-8:]
            if key:
                self.expect(re.escape(key), 20)
            else:
                time.sleep(0.15)
        self.ctl('Z')
        self.expect(end_rx, 30)

    def sim(self, *lines, tmo=10):
        """SIMH commands: ^E, each command, continue"""
        self.ctl('E')
        self.expect(r'sim> $', tmo)
        for line in lines:
            self.cmd(line, r'sim> $', tmo)
        self.send('cont')
        time.sleep(2)

    def stop(self):
        """^E quit; keep reading the pty meanwhile (SIMH blocks on exit while
        its last output is unread), then close it; SIGKILL if still there"""
        try:
            self.ctl('E'); time.sleep(0.5)
            self.send('quit')
        except OSError:
            pass
        for _ in range(40):
            try:
                self.pump(0.25)
            except RuntimeError:
                pass
            if os.waitpid(self.pid, os.WNOHANG) != (0, 0):
                break
        else:
            os.kill(self.pid, signal.SIGKILL)
            os.close(self.fd)
            os.waitpid(self.pid, 0)
            return
        os.close(self.fd)

def ini(path, lines):
    open(path, 'w').write('\n'.join(['do ' + BASE] + lines + ['']))

def rsts_phase(a, w):
    """compile TLORSX.C on RSTS; write TLORSX.OBJ + CFPURS.OLB to xfer.tap"""
    disk = os.path.join(w, 'rsts.dsk')
    shutil.copyfile(a.rsts, disk)
    xfer = os.path.join(w, 'xfer.tap')
    if os.path.exists(xfer):
        os.remove(xfer)
    ini(os.path.join(w, 'rsts.ini'), ['set tm enabled', 'attach tm0 ' + xfer,
        'set rp0 rp06', 'attach rp0 ' + disk, 'set xu enabled', 'set xu type=delua', 'attach xu nat:', 'boot rp0'])
    s = Sim(os.path.join(w, 'rsts.ini'), os.path.join(w, 'rsts.log'))
    try:
        s.expect(r"date\? *$", 120)
        d = time.strftime('%d-%b-%y').upper()
        s.cmd(d, r'time\? *$')
        s.cmd(time.strftime('%H:%M'), r'Start timesharing\? <Yes> *$')
        s.cmd('', r'startup is complete', 600)
        time.sleep(5)
        s.cmd('', r'User: *$', 30)
        s.cmd(a.rsts_user, r'Password: *$')
        out = s.cmd(a.rsts_pass, r'\$ $|attach to\? *$', 60)
        if 'attach to' in out:
            s.cmd('', r'\$ $')
        for f, n in (('tload.c', 'TLOAD.C'), ('rsxio.h', 'RSXIO.H'), ('tlorsx.c', 'TLORSX.C'),
                     ('hlpidx.c', 'HLPIDX.C')):
            s.cmd('DELETE/NOLOG/NOCONFIRM %s' % n, r'\$ $')
            s.type_file(os.path.join(REPO, 'src', f), 'CREATE %s' % n, r'\$ $')
        for c in ('TLORSX.C', 'HLPIDX.C'):
            out = s.cmd('CCC ' + c, r'\$ $', 600)
            if re.search(r'%CC-[EF]-|\?[A-Z]', out):
                raise RuntimeError('CCC %s failed:\n%s' % (c, out))
        s.cmd('INITIALIZE MT0: XFER/FORMAT=ANSI', r'Proceed.*\? *$')
        s.cmd('Y', r'\$ $', 60)
        s.cmd('MOUNT MT0: XFER', r'\$ $', 60)
        for c in ('COPY/BLOCK_SIZE=2048 TLORSX.OBJ MT0:TLORSX.OBJ', 'COPY/BLOCK_SIZE=2048 HLPIDX.OBJ MT0:HLPIDX.OBJ',
                  'COPY [1,1]CFPURS.OLB MT0:CFPURS.OLB'):
            out = s.cmd(c, r'\$ $', 600)
            if 'copied' not in out:
                raise RuntimeError(c + ' failed:\n' + out)
        s.cmd('DISMOUNT MT0:', r'\$ $', 60)
        s.cmd('RUN $SHUTUP', r'<YES>\? *$')
        s.cmd('NO', r'<5>\? *$')
        s.cmd('0', r'RESTART <NO>\? *$')
        s.cmd('', r'Start timesharing\? <Yes> *$', 600)
    finally:
        s.stop()
    return xfer

def rsx_boot(a, w, tape, ro, log):
    """boot the RSX copy with tape on MS0:, log in, set up [200,1]"""
    ini(os.path.join(w, 'rsx.ini'), ['set xu enabled', 'set xu address=17774510', 'set xu vector=120',
        'set ts enabled', 'attach %sts0 %s' % ('-r ' if ro else '', tape), 'set rp0 rp06',
        'attach rp0 ' + os.path.join(w, 'rsx.dsk'), 'boot rp0'])
    s = Sim(os.path.join(w, 'rsx.ini'), os.path.join(w, log))
    s.expect(r'Time and date : *$', 300)
    s.cmd(time.strftime('%H:%M %d-%b-%Y').upper(), r'logged off', 600)
    time.sleep(3)
    s.cmd('HELLO ' + a.rsx_user, r'Password: *$')
    s.cmd(a.rsx_pass, r'Logged on')
    s.expect(r'\n>\s*$', 30)
    for c in ('SET /BUF=TI:132.', 'SET /NOWRAP=TI:', 'UFD SY:[200,1]', 'SET /UIC=[200,1]'):
        s.cmd(c, r'\n>\s*$', 60)
    return s

def rsx_shutup(s):
    s.cmd('RUN $SHUTUP', r'shutdown: *$')
    s.cmd('0', r'none\): *$')
    s.cmd('', r'\[Y/N\]: *$')
    s.cmd('Y', r'SHUTUP operation complete', 300)

def rsx_phase(a, w, xfer, kit):
    """link TLOAD.TSK on RSX from the transfer tape, then write the kit"""
    shutil.copyfile(a.rsx, os.path.join(w, 'rsx.dsk'))
    s = rsx_boot(a, w, xfer, True, 'rsx.log')
    try:
        for c in ('INS $MAC', 'INS $TKB', 'PIP *.*;*/DE/NM'):
            s.cmd(c, r'\n>\s*$', 60)
        for f, n in (('src/rsxio.mac', 'RSXIO.MAC'), ('rsx/TLOBLD.CMD', 'TLOBLD.CMD'),
                     ('rsx/TLOAD.ODL', 'TLOAD.ODL'), ('rsx/INSTALL.CMD', 'INSTALL.CMD'),
                     ('rsx/README.TXT', 'README.TXT'), ('src/tload.c', 'TLOAD.C'),
                     ('src/tlorsx.c', 'TLORSX.C'), ('src/rsxio.h', 'RSXIO.H'),
                     ('rsx/help/TLOAD.HLP', 'TLOAD.HLP'), ('rsx/help/TDIR.HLP', 'TDIR.HLP'),
                     ('rsx/help/TLOIDX.HLP', 'TLOIDX.HLP'), ('src/hlpidx.c', 'HLPIDX.C'),
                     ('rsx/HLPBLD.CMD', 'HLPBLD.CMD'), ('rsx/HLPIDX.ODL', 'HLPIDX.ODL')):
            s.type_file(os.path.join(REPO, f), 'PIP %s=TI:' % n, r'\n>\s*$')
        s.cmd('MOU MS0:XFER', r'\n>\s*$', 60)
        for c in ('PIP SY:[200,1]/NV=MS0:TLORSX.OBJ', 'PIP SY:[200,1]/NV=MS0:HLPIDX.OBJ',
                  'PIP SY:[200,1]/NV/CO=MS0:CFPURS.OLB'):
            out = s.cmd(c, r'\n>\s*$', 300)
            if '--' in out:
                raise RuntimeError(c + ' failed:\n' + out)
        s.cmd('DMO MS0:', r'dismounted|Dismount complete', 60)
        s.expect(r'\n>\s*$', 30)
        out = s.cmd('MAC RSXIO,RSXIO=LB:[1,1]DEUNA/ML,SY:[200,1]RSXIO', r'\n>\s*$', 300)
        if 'Errors detected' in out or '--' in out:
            raise RuntimeError('MAC failed:\n' + out)
        for b, t in (('TLOBLD', 'TLOAD.TSK'), ('HLPBLD', 'HLPIDX.TSK')):
            out = s.cmd('TKB @' + b, r'\n>\s*$', 600)
            if '--' in out:
                raise RuntimeError('TKB @%s failed:\n%s' % (b, out))
            out = s.cmd('PIP %s/LI' % t, r'\n>\s*$')
            if t not in out:
                raise RuntimeError('no %s:\n%s' % (t, out))
        rsx_shutup(s)
    finally:
        s.stop()
    # the kit: a second boot with a new tape on the drive (swapping tapes
    # under a running RSX from the sim> prompt left its console dead)
    if os.path.exists(kit):
        os.remove(kit)
    s = rsx_boot(a, w, kit, False, 'rsxkit.log')
    try:
        # INI wants the tape mounted foreign; then the new ANSI volume
        s.cmd('MOU MS0:/FOR', r'\n>\s*$', 60)
        out = s.cmd('INI MS0:TLOAD', r'\n>\s*$', 120)
        if '--' in out:
            raise RuntimeError('INI failed:\n' + out)
        s.cmd('DMO MS0:', r'dismounted|Dismount complete', 60)
        s.expect(r'\n>\s*$', 30)
        out = s.cmd('MOU MS0:TLOAD', r'\n>\s*$', 60)
        if '--' in out:
            raise RuntimeError('MOU failed:\n' + out)
        for f in ('TLOAD.TSK', 'HLPIDX.TSK', 'INSTALL.CMD', 'README.TXT', 'TLOAD.HLP', 'TDIR.HLP',
                  'TLOIDX.HLP', 'TLOAD.C', 'TLORSX.C', 'RSXIO.H', 'RSXIO.MAC', 'TLOBLD.CMD',
                  'TLOAD.ODL', 'HLPIDX.C', 'HLPBLD.CMD', 'HLPIDX.ODL'):  # one per line: MCR takes 80
            out = s.cmd('PIP MS0:/NV=' + f, r'\n>\s*$', 300)
            if '--' in out:
                raise RuntimeError('writing %s to the kit failed:\n%s' % (f, out))
        out = s.cmd('PIP MS0:*.*/LI', r'\n>\s*$', 120)
        print(out.strip())
        s.cmd('DMO MS0:', r'dismounted|Dismount complete', 60)
        s.expect(r'\n>\s*$', 30)
        rsx_shutup(s)
    finally:
        s.stop()

def main():
    p = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    p.add_argument('--rsts', required=True, help='RSTS/E disk with PDP-11 C (RP06 image)')
    p.add_argument('--rsx', required=True, help='RSX-11M-PLUS disk with XE: (RP06 image)')
    p.add_argument('--version', default='100', help='kit version, e.g. 100 for V1.00')
    p.add_argument('--work', default=os.path.join(REPO, 'rsx', 'work'))
    p.add_argument('--rsts-user', default='1,20')
    p.add_argument('--rsts-pass', default='INSTALL')
    p.add_argument('--rsx-user', default='SYSTEM')
    p.add_argument('--rsx-pass', default='SYSTEM')
    a = p.parse_args()
    os.makedirs(a.work, exist_ok=True)
    kit = os.path.join(REPO, 'dist', 'pdp2011_rsx_tools_v%s.tap' % a.version)
    xfer = rsts_phase(a, a.work)
    rsx_phase(a, a.work, xfer, kit)
    print('kit:', kit)

if __name__ == '__main__':
    main()
