#!/usr/bin/env python3
# Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
# free for non-commercial use with attribution (see LICENSE).
"""simdrv.py <ini>: run SIMH on a pty; all output -> term.log; lines written to
in.fifo are typed followed by CR; a line '^E' sends Ctrl-E (SIMH's sim> prompt)."""
import os, pty, select, sys
pid, fd = pty.fork()
if pid == 0:
    os.execv(os.environ.get('SIMH', os.path.expanduser('~/Source/simh-ekbee1/BIN/pdp11')), ['pdp11', sys.argv[1]])
log = open('term.log', 'ab', 0)
fifo = os.open('in.fifo', os.O_RDWR | os.O_NONBLOCK); pend = b''
while True:
    r, _, _ = select.select([fd, fifo], [], [], 1.0)
    if fd in r:
        try: d = os.read(fd, 65536)
        except OSError: break
        if not d: break
        log.write(d)
    if fifo in r:
        pend += os.read(fifo, 4096)
        while b'\n' in pend:
            line, pend = pend.split(b'\n', 1)
            os.write(fd, bytes([line[1] & 0x1f]) if len(line) == 2 and line[:1] == b'^' else line + b'\r')   # '^X' = Ctrl-X
