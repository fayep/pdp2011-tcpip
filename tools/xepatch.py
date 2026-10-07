#!/usr/bin/env python3
# Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
# free for non-commercial use with attribution (see LICENSE).
"""xepatch.py <una.bin> > XEPAT.CMD - ONLPAT command file that fixes the RSTS/E
10.1 XE (DEUNA/DELUA) driver crash on received frames of 629-632 bytes.

The bug: receive buffers hold 632 bytes; a frame whose CRC spills alone into
the last chained buffer gets a length of 0..-3 for it (GETPKT), and XEREAD
passes that to MOVMEM (which needs >= 1) -> runaway copy -> monitor crash.

The fix, in XEREAD (module UNA): skip MOVMEM when the count is <= 0. The
count has already been added to XRBC, so the program sees the true length.
Room: BIC #170000,R1 / BIS #120000,R1 (APR6 -> APR5 virtual) becomes
SUB #20000,R1 (the pointer is always in the APR6 window); the code below it
moves up two words and TST R2 / BLE go in front of JSR PC,@#MOVMEM.
Every moved word is copied from this system's own module, and ONLPAT checks
each old value before it writes, so a different monitor is refused, never
corrupted."""
import struct, sys

LOAD = 0o120000
w = struct.unpack('<%dH' % (len(open(sys.argv[1], 'rb').read()) // 2), open(sys.argv[1], 'rb').read())
at = lambda a: w[(a - LOAD) // 2]

# find: BIC #170000,R1 / BIS #120000,R1 / MOV (SP)+,@#x / CMP (R3),R2 / BGE .+12
#       ... JSR PC,@#movmem
hits = [i for i in range(len(w) - 24)
        if w[i:i+4] == (0o042701, 0o170000, 0o052701, 0o120000)
        and w[i+4] == 0o012677 and w[i+6] == 0o021302 and w[i+7] == 0o002005
        and w[i+8] == 0o112777 and w[i+11] == 0o011302 and (w[i+12] & 0o177400) == 0o001400
        and w[i+13] == 0o160213 and w[i+16] == 0o060263 and w[i+20] == 0o010503
        and w[i+21] == 0o060205 and w[i+22] == 0o004737]
if len(hits) != 1:
    sys.exit('xepatch: XEREAD not found as expected (%d matches): not patching' % len(hits))
s = LOAD + 2 * hits[0]                  # address of BIC #170000,R1
old = [at(s + 2 * k) for k in range(22)]   # s .. JSR (exclusive)
beq = old[12]                            # BEQ 40$ at s+30 (old)
target = s + 30 + 2 + 2 * (beq & 0o377 if beq & 0o200 == 0 else (beq & 0o377) - 0o400)
# moved up 4 bytes: PC-relative operands (mode 6/7 on R7: MAP POP's @DPAR6,
# SETERR's @IOSTS) must reach 4 further
moved = list(old[4:12])                  # MOV (SP)+,@x(PC) ; CMP ; BGE ; MOVB #..,@y(PC) ; MOV (R3),R2
assert moved[0] == 0o012677 and moved[4] == 0o112777
moved[1] = (moved[1] + 4) & 0o177777
moved[6] = (moved[6] + 4) & 0o177777
new = [0o162701, 0o020000] + moved      # SUB #20000,R1 ; ...
off = (target - (s + 26 + 2)) // 2      # BEQ 40$ now at s+26
assert 0 < off < 0o200
new += [0o001400 | off] + old[13:22] + [0o005702, 0o003402]   # ... ADD R2,R5 ; TST R2 ; BLE .+6
assert len(new) == 22
print('File to patch? ' + (sys.argv[2] if len(sys.argv) > 2 else ''))
print('Module name? UNA')
print('Base address? %o' % LOAD)
print('Offset address? %o' % (s - LOAD))
print(' Base\tOffset  Old     New?')
for k in range(22):
    print('%06o\t%06o\t%06o\t? %06o' % (LOAD, s - LOAD + 2 * k, old[k], new[k]))
print('%06o\t%06o\t%06o\t? ^Z' % (LOAD, s - LOAD + 44, at(s + 44)))
print('Offset address? ^Z')
print('Base address? ^Z')
print('Module name? ^Z')
print('File to patch? ^Z')
