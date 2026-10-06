#!/usr/bin/env python3
# Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
# free for non-commercial use with attribution (see LICENSE).
# say.py "<line>" "<regex to wait for>" [timeout]: type a line into the running
# SIMH (via in.fifo) and print what follows until the regex appears.
import re, sys, time
line, rx, tmo = sys.argv[1], sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 120
start = len(open('term.log', 'rb').read())
if line != '-':
    open('in.fifo', 'w').write(line + '\n')
t0 = time.time()
while time.time() - t0 < tmo:
    time.sleep(1)
    out = open('term.log', 'rb').read()[start:].decode('latin-1').replace('\r', '')
    out = re.sub(r'Sockets: _eth_reader.*\n|^\w{3} \w{3} +\d+ [\d:]+ \d{4}\n', '', out, flags=re.M)
    if re.search(rx, out[-300:]):
        print(out.rstrip()); sys.exit(0)
print(out.rstrip()); print('[say.py: TIMEOUT waiting for %r]' % rx); sys.exit(1)
