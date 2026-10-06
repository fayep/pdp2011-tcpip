#!/usr/bin/env python3
# Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
# free for non-commercial use with attribution (see LICENSE).
# put.py <local file> <RSTS name>: type a text file into RSTS with CREATE on
# the console (the job must be at a "$ " prompt), one line at a time, then ^Z.
# Waits for each line's echo so nothing is typed ahead of RSTS.
import sys, time
src, dst = sys.argv[1], sys.argv[2]
lines = open(src).read().replace('\r', '').split('\n')
if lines and lines[-1] == '':
    lines.pop()
def tail():
    return open('term.log', 'rb').read().decode('latin-1')
def send(s):
    open('in.fifo', 'w').write(s + '\n')
import re
NOISE = re.compile(r'\w{3} \w{3} +\d+ \d\d:\d\d:\d\d \d{4}\r?\n|Sockets: _eth_reader\(udp\):[^\n]*\n')
def squash(s):
    """drop SIMH's own interjections, then all whitespace"""
    return ''.join(NOISE.sub('', s).split())
def wait_for(text, start, tmo=30):
    """wait until text (whitespace ignored) has been echoed since start"""
    want = squash(text)
    t0 = time.time()
    while time.time() - t0 < tmo:
        got = tail()[start:]
        if (want in squash(got)) if want else ('\n' in got):
            return True
        time.sleep(0.05)
    return False
# only ever type at a DCL prompt: anywhere else (User:, a question) the
# lines would be taken as answers or commands
start = len(tail()); send(''); time.sleep(1.5)
last = [l for l in NOISE.sub('', tail()[start:]).replace('\r', '').split('\n') if l.strip()]
if not last or last[-1].strip() != '$':
    sys.exit('not at a DCL $ prompt (last line %r); nothing sent' % (last[-1] if last else ''))
start = len(tail()); send('CREATE ' + dst); time.sleep(1.5)
said = NOISE.sub('', tail()[start:])
if 'OK to replace' in said:
    # the file exists: without a YES here the first line is taken as the
    # answer (no) and the rest is typed at the $ prompt
    start = len(tail()); send('YES'); time.sleep(1.5)
    said = NOISE.sub('', tail()[start:])
if re.search(r'^\s*\?|\?\s*$', said.strip(), re.M):
    # CREATE refused (bad device, no access): typing on would run each
    # line as a command at the $ prompt
    sys.exit('CREATE %s failed:\n%s' % (dst, said.strip()))
for i, l in enumerate(lines):
    if len(l) > 250:
        sys.exit('line %d longer than 250 characters' % (i + 1))
    start = len(tail()); send(l)
    if not wait_for(l[-40:], start):
        sys.exit('no echo for line %d: %r' % (i + 1, l))
start = len(tail()); send('^Z'); wait_for('$ ', start)
print('%s -> %s: %d lines' % (src, dst, len(lines)))
