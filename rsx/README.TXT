PDP2011 RSX-11M-PLUS tools V1.00

TLOAD and TDIR: the MiSTer tape library from RSX-11M-PLUS. The library is
the PDP2011 core's folder on the MiSTer's SD card (games/PDP2011) and the
folders below it; TLOAD puts a .TAP or .TPC image from it on the tape
drive, as if you had chosen it in the OSD.

    >TDIR                        the top: folders (NAME/) and tapes
    >TDIR RSX                    a folder
    >TDIR RSTS/V9.6/*RAW*        matching names (* is a wildcard)
    >TLOAD RSTS_V9_6_INSTALL.TAP a name alone is found in any folder
    >TLOAD RSTS/V9.6/RSTS_V9_6_INSTALL.TAP
    >MOU MS0:/FOR                (or BRU, FLX, ... as usual)
    >TLOAD                       what is on the drive
    >TLOAD/UNLOAD                empty the drive

The drive is MS0: (the core's Tape controller option set to TS11) or MT0:
(TM11). TLOAD will not change a tape that is mounted with a file
structure (MOU MS0:label) or attached by a task (BRU, FLX, ...), but it
cannot see MOU/FOR or ALL: DMO or DEA the tape first.

Needs: RSX-11M-PLUS V4.x with the XE: (DEUNA/DELUA) driver loaded
(SYSGEN: one DEUNA, CSR 174510, vector 120; DRIVER=XE: in SYSPARAM.DAT);
no DECnet is needed. On the MiSTer: the PDP2011 core with the XU, Host
network not Off, and MiSTer_pdp2011 with tape library folder support.

Install (privileged account):
    >MOU MS0:TLOAD
    >PIP SY:/NV=MS0:INSTALL.CMD
    >@INSTALL
    >DMO MS0:

Files on this tape: TLOAD.TSK, INSTALL.CMD, README.TXT, and the sources:
TLOAD.C TLORSX.C RSXIO.H RSXIO.MAC TLOBLD.CMD TLOAD.ODL. To rebuild:
compile TLORSX.C with PDP-11 C (RSX target), assemble
    MAC RSXIO,RSXIO=LB:[1,1]DEUNA/ML,SY:RSXIO
and TKB @TLOBLD with the PDP-11 C library CFPURSX.OLB (as CFPURS.OLB).

Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0: free for
non-commercial use with attribution
(https://creativecommons.org/licenses/by-nc/4.0/). TLOAD.TSK contains
PDP-11 C and RMS-11 run-time code from Digital Equipment Corporation.
