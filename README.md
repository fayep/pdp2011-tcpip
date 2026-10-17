# TCP/IP for RSTS/E 10.1 (user mode)

A small IP stack for RSTS/E that runs as ordinary privileged jobs on the
documented Ethernet portal interface (RSTS/E V10 Programming Manual ch. 7,
System Directives Manual 3.27.2; driver source 170070/xedvr.mac). No monitor
changes. Written in PDP-11 C with a thin MACRO-11 layer.

- `src/ethio.mac`  MACRO-11 portal access for C: ethopn, ethcls, ethmul, ethget, ethput
- `src/netcfg.h`   address settings and helpers (the controller's MAC must be given)
- `src/arpd.c`     answers ARP for our address (own job, stalled on the ARP portal)
- `src/pingd.c`    answers ICMP echo (stalled on the IP portal)
- `src/netd.c`     ARP + ping in one job: poll every portal without stalling, then
                   .SLEEP; a frame for any of the job's portals ends the sleep at once
- `src/tftpd.c`    TFTP server (RFC 1350) + ARP + ping in one job; files only in FTP$:
- `src/netcfg.c`   settings (TCPIP$:TCPIP.INI) and the controller address: hardware
                   address read as SHOW DEVICE XE does (UU.TB1/UU.TB2 + .PEEK of the
                   DDB), or AA-00-04-00+node when DECnet is running (detected: its
                   portal 60-03 is open)
- `src/mactst.c`   prints the hardware address (matches SHOW DEVICE XE)
- `tools/ethpeer.py` raw-Ethernet test peer over SIMH's UDP Ethernet transport
                   (arp, ping, sniff, get, put)
- `kit/help/`      HELP topics (HELP TCPIP, PING, ..., TLOAD, TDIR): installed into
                   HELP$: by TCPINS.COM, with their entries merged into HELP$:HELP.HLP
                   by kit/TCPHLP.COM; `rsx/help/` the same for RSX (LB:[1,2], MCR.HLP and
                   HELP.HLP)
- `kit/`           Auto-Install kit sources: TCPTCP.CFG, TCPINS.COM, TCPIVP.COM,
                   TCPIP.INI (default), TCP010.DAT, TCPREL.DOC, AUTVER.DAT; src/tcpip.ins
- `dist/tcpip_v010.tap` the kit (SIMH .tap, ANSI volume TCPIP), written entirely by
                   RSTS BACKUP; it carries no DEC software
- `tools/tapeconv` (not in git) converts TPC tapes to SIMH .tap; build it from
                   Main_MiSTer_pdp2011's support/pdp2011/tapeconv.cpp
- `sim/`           SIMH development system (dev.ini, simdrv.py, say.py, put.py)

Build on RSTS (account with PDP-11 C, COMMON.MAC copied from [1,2]):

    RUN $MAC
    MAC> ETHIO,ETHIO=COMMON,ETHIO
    CCC TFTPD.C
    CCC NETCFG.C
    LINK/CC/STACK=1024 TFTPD,NETCFG,ETHIO     (the default stack overflows)

PDP-11 C keeps only 6 characters of global names: keep globals unique in 6.

PDP-11 C does not word-align char arrays. Frame buffers handed to the XE
driver must be even: the driver uses .READ/.WRITE buffers as given and an odd
one crashes RSTS (odd-address trap in kernel mode, in the APR6 mapping of the
user buffer; seen as R5=140057 at MOV 12(R1),14(R5), CPUERR 100). Frame
buffers are word arrays, and ETHIO refuses odd buffers (error 255).

PUT16 must evaluate its value once: PUT16(u+6, udp_cksum(...)) with a
two-use macro summed again after storing the high byte, and 1 frame in 256
(right checksum ending in 00) went out as xxFF.

RSTS CREATE asks "OK to replace existing file ...?" when the file exists;
sim/put.py answers YES, and refuses to type anything unless it sees a DCL $
prompt (otherwise the file's lines run as commands).

Driver facts this relies on (xedvr.mac): the protocol type is FIRQB+FQNENT,
compared as the PDP-11 word of the frame's type field (08-00 -> 0x0008);
multicasts, broadcast included, reach a portal only if enabled on it (.SPEC -3).

Status (2026-10-05, SIMH): ARP, ping and TFTP read/write work.
- TFTP: RRQ and WRQ, 512-byte blocks, retransmit after 2 s (5 tries), one
  transfer at a time ("busy" to others), lingers 4 s after a write to re-ACK
  a lost final block. Verified byte-for-byte both ways (random 3001 bytes,
  exactly 1024, empty). Reads return whole RSTS blocks: files without record
  attributes are NUL-padded to 512 bytes, as on disk.
- FTP$: on the dev system is SY:[0,90] (CREATE/ACCOUNT/NOUSER, ASSIGN/SYSTEM).

Settings and the controller address work (dev system: DECnet detected, MAC
AA-00-04-00-0A-04 from node 1.10; hardware read = SHOW DEVICE XE).

DHCP (default, IP DHCP): DISCOVER/OFFER/REQUEST/ACK, mask/router/lease from the
server, renewal at T1 (unicast, ciaddr), restart if the lease runs out; host
name = HOSTNAME, else the DECnet node name (DECNET 1.10 RSTS1), else RSTS.
Tested in SIMH against ethpeer.py dhcpd: bound, ping + TFTP on the leased
address, renewals every T1.

Lessons: ethslp must not be void (PDP-11 C reserves the result word only for
non-void calls, and the MACRO layer expects it); the default task stack
overflows (link /STACK=1024).

Auto-Install kit (product TCP, V010), tested in SIMH on a clean RSTS/E 10.1:
installer account [1,20]; CREATE/ACCOUNT/NOUSER AUTOIN$:; RESTORE MT0:[1,2]AUT101.A
AUTOIN$:*.*; @AUTOIN$:AUTOIN, product TCP, MT0: -> TCP has passed; then
@SY:[0,91]TCPIP.INS starts TFTPD detached: hardware MAC found, DHCP bound,
ping and TFTP read/write OK.

Installing: the system needs Auto-Install, which comes with DEC's V10
layered-product kits (C, COBOL, ...). If AUTOIN$: is empty, restore it from
one of those (RESTORE MT0:[1,2]AUT101.A AUTOIN$:*.*), then mount this kit and
@AUTOIN$:AUTOIN, product TCP.

Kit layout (from Auto-Install's own AUTOIN.COM/PRODIN.COM, studied locally):
  AUTVER.BCK  our own AUTVER.DAT ("101"): Auto-Install reads it to see whether
              the tape carries a newer Auto-Install; 101 is the one installed
  TCPTCP.BCK  <prod><prod>.BCK: only TCPTCP.CFG, restored into the installer's
              account (no account data)
  TCPREL.BCK  release notes, restored into AUTWRK$
  TCP010.A    <prod><ver>.A: everything else (procedures, TFTPD.TSK, sources,
              TCPIP.INI, TCPIP.INS), restored into AUTWRK$; PRODIN runs
              TCPINS.COM, then TCPIVP.COM, then copies AUTWRK$ to FINAL
The four savesets are written in this order with RSTS BACKUP (/NOACCOUNT_DATA,
the first with /INITIALIZE/OUT_LABEL=TCPIP). DEC's AUTVER.BCK/AUT101.A are not
on the tape (tools/mkkit.py, which added them, is kept for reference only).
docs/AUTO-INSTALL.md describes what Auto-Install expects of a kit.

Tested on the user's MiSTer (2026-10-05): installed and worked first time.

Next: the MiSTer (with the user's OK). Known: a detached TFTPD keeps devices
its parent job had assigned (deassign them before detaching).

## RSX-11M-PLUS tools (rsx/)

TLOAD and TDIR for RSX-11M-PLUS, from the same `src/tload.c` (built with
`RSX` defined by `src/tlorsx.c`). `src/rsxio.mac` is the RSX side of
ETHIO: the XE: (DEUNA/DELUA) driver's DECnet Direct Line Access interface
(IO.XOP line UNA-0, IO.XSC CC.DST to enable the protocol, IO.XTM/IO.XRC with
CC.ADR/CC.PRO/CC.DAD characteristics; LB:[11,10]XEDRV.MAC, LB:[1,1]DEUNA.MLB),
which needs no DECnet. The kit tape is `dist/pdp2011_rsx_tools_vNNN.tap`
(ANSI volume TLOAD: TLOAD.TSK, INSTALL.CMD, README.TXT and the sources);
`rsx/README.TXT` is the user's guide.

    rsx/mkrsxkit.py --rsts sim/tcp_dev.dsk --rsx <RSX-11M-PLUS RP06 disk with XE:>

builds it in two SIMH runs on copies of the disks: RSTS/E compiles TLORSX.C
with PDP-11 C and writes TLORSX.OBJ and the C kit's RSX library [1,1]CFPURS.OLB
(CFPURSX.OLB) to an ANSI transfer tape (COPY/BLOCK_SIZE=2048: RSX rejects
records spanning blocks); RSX reads it, assembles RSXIO, links (`TLOBLD.CMD`,
`TLOAD.ODL`: RMS-11 from LB:[1,1]RMS11S.ODL) and writes the kit. Neither disk
ships (DEC software). The RSX system needs one DEUNA in SYSGEN (CSR 174510,
vector 120) and DRIVER=XE: in SYSPARAM.DAT; XEDRV is loaded into GEN.

Testing in SIMH without a MiSTer: `tools/tlibpeer.py <folder>` answers the
library's frames (tapelib.cpp's rules) over `attach xu udp:7101:127.0.0.1:7102`
(127.0.0.1, not localhost: SIMH may pick IPv6). Attach the XU before booting:
detaching it stops the XU's receive polling.

Limits on RSX: TLOAD tests the drive with IO.ATT, which a file-structured
mount (MTAACP holds it) or another task's attach refuses; MOU/FOR and ALL do
not stop an attach, and an unprivileged task cannot see them otherwise
(GLUN$ reports the same either way; this exec has no EMT-form $SWSTK).

## License

Copyright (c) 2026 Faye Salwin. Free for non-commercial use with attribution:
[CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/); see LICENSE.
Auto-Install itself is DEC software and is not in this repository. The task
images on the kit tapes are linked with DEC's PDP-11 C (and, for RSX, RMS-11)
run-time libraries, which stay DEC's.
