# RSTS/E TCP/IP V1.01 — User's Guide

Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0: free for
non-commercial use with attribution
(<https://creativecommons.org/licenses/by-nc/4.0/>).

A small IP stack for RSTS/E V10.1. It runs as ordinary jobs on the RSTS/E
Ethernet portal interface (XE:, a DEUNA or DELUA), with no changes to the
monitor beyond two small fixes for bugs in RSTS itself (see
[Monitor fixes](#monitor-fixes)). It runs on a real PDP-11, in SIMH, and on
the PDP2011 core for the MiSTer.

## Contents

1. [What you get](#what-you-get)
2. [Requirements](#requirements)
3. [Installing](#installing)
4. [Settings: TCPIP.INI](#settings-tcpipini)
5. [Commands](#commands)
6. [Web pages and HTTPS: CURL and sslproxy](#web-pages-and-https-curl-and-sslproxy)
7. [The date and time: NETDATE](#the-date-and-time-netdate)
8. [File transfer: TFTP and NC](#file-transfer-tftp-and-nc)
9. [MiSTer notes](#mister-notes)
10. [Monitor fixes](#monitor-fixes)
11. [Writing programs: the socket library](#writing-programs-the-socket-library)
12. [Troubleshooting](#troubleshooting)
13. [Limits](#limits)
14. [Credits](#credits)

## What you get

- **TCPIPD**, the TCP/IP job: ARP, IPv4 with routing, ICMP echo, DHCP
  client, UDP and TCP. TCP has a 4 KB receive window, keeps out-of-order
  segments and reports them with SACK, and retransmits quickly on
  duplicate acknowledgements.
- **Commands**: PING, HOST, IFCONFIG, CURL, NC, NETDATE, and on the
  MiSTer TLOAD and TDIR.
- **TFTPD**, a TFTP server for moving files to and from the system.
- **A socket library** for PDP-11 C programs, in the BSD style.
- **sslproxy.py**, a small proxy that runs on a nearby modern machine and
  does HTTPS for CURL.

## Requirements

- RSTS/E V10.1 with an Ethernet controller (DEUNA or DELUA, `XE0:`).
- The RSTS/E Auto-Install procedure (`AUTOIN$:AUTOIN`), part of V10.1.
- Privileges for installing: log in as `[1,2]`.
- PDP-11 C is **not** needed to install or use the kit, only to build your
  own programs with the socket library.
- The kit is a SIMH-format tape image, `tcpip_v101.tap`.

## Installing

1. **Mount the tape.**
   - MiSTer (PDP2011 core): copy `tcpip_v101.tap` to
     `games/PDP2011/RSTS/Products/` on the SD card and choose it in the
     OSD as the tape, or load it from RSTS with
     `TLOAD RSTS/Products/tcpip_v101.tap` if you already run a version
     with TLOAD.
   - SIMH: `attach -r tm0 tcpip_v101.tap`.
2. **Run Auto-Install** as `[1,2]`:

       $ @AUTOIN$:AUTOIN
       Which product(s) do you want to install? TCP
       Where are the update files located <PATCH$:>? <RETURN>
       Which device are the distribution files ... located on? MT0:
       Do you want to customize TCP (TCP) (Y/N) <N>? <RETURN>

   Customizing lets you answer **XEPATCH** (default YES): whether to apply
   the [monitor fixes](#monitor-fixes). Leave it YES.
3. **Reboot if told to.** If the installer says the DEUNA receive fix is in
   the monitor file, TCP/IP will not start until the next boot (the
   running monitor still has the bug). Other installs need no reboot.
4. **Start it at every boot.** Add this line to the system start-up file
   `[0,1]START.COM`, after DECnet/E if you run it:

       $ @SY:[0,91]TCPIP.INS

   To start it now without rebooting: `@SY:[0,91]TCPIP.INS`.
   `TCPIP.INS` also defines the commands (PING, HOST, IFCONFIG, CURL, NC,
   NETDATE, TLOAD, TDIR) for all users.

Reinstalling or upgrading is the same procedure. Your `TCPIP.INI` is kept;
new settings must be added to it by hand (the installer says so).

Everything lives in `TCPIP$:`, which is `SY:[0,91]`.

## Settings: TCPIP.INI

`TCPIP$:TCPIP.INI` is a plain text file, one setting per line, `!` starts a
comment. Edit it with EDT; the changes take effect when TCP/IP next starts
(`REMOVE` the TCPIPD and TFTPD jobs and run `@SY:[0,91]TCPIP.INS`, or
reboot).

| Setting | Example | Meaning |
|---|---|---|
| `IP` | `DHCP` or `192.168.1.240` | Get the address by DHCP (default), or use this fixed address |
| `MASK` | `255.255.255.0` | Network mask, with a fixed address |
| `GATEWAY` | `192.168.1.1` | Default gateway, with a fixed address |
| `DNS` | `192.168.1.1 8.8.8.8` | One or two name servers (DHCP supplies them otherwise) |
| `DOMAIN` | `lan` | Domain tried after short names (DHCP may supply it) |
| `HOSTNAME` | `RSTS1` | Name sent to DHCP (default: the DECnet node name) |
| `DECNET` | `1.10 RSTS1` | Needed while DECnet/E runs: its node address and name (DECnet sets the Ethernet address) |
| `MAC` | `08-00-2B-12-34-56` | Use this Ethernet address instead of reading the controller's |
| `UNIT` | `0` | Controller unit (XE0: is 0) |
| `DETACH` | `YES` | Run TCPIPD and TFTPD as detached jobs |
| `TFTP` | `YES` | Run the TFTP server (`NO` turns it off) |
| `PROXY` | `mister:3128` | HTTP proxy for CURL (needed for `https://`) |
| `NTP` | `pool.ntp.org` | Time server for NETDATE (default: the gateway) |
| `TIMEZONE` | `PST8PDT,M3.2.0,M11.1.0` | Local time zone (POSIX TZ string); NETDATE sets the clock at start-up only when this is given |

## Commands

Errors are reported in messages starting with `?` and the command's name.
See [Command lines](#command-lines) for how qualifiers and quotes work.

### PING host [count]

Sends ICMP echo requests (default 4) and shows each reply's round-trip
time, in line-clock ticks (16 or 20 ms resolution).

    $ PING 192.168.1.1 3
    PING 192.168.1.1
    reply from 192.168.1.1: seq=1 ttl=64 time=16 ms

### HOST [name ...]

Looks up names with DNS and prints their addresses. With no name, shows
the system's settings: host name, address, mask, gateway, name servers.

### IFCONFIG

Shows the interface: Ethernet address, IP address, mask, broadcast,
gateway, the DHCP lease time left, name servers, and counts of packets
and bytes received and sent, with errors.

    XE0: flags=UP,BROADCAST  mtu 1500
         ether 08:00:2b:05:06:07
         inet 192.168.50.53  netmask 255.255.254.0  broadcast 192.168.51.255
         gateway 192.168.50.1  (DHCP, lease 23:57:56 left)
         RX packets 235  bytes 76672  errors 0
         TX packets 2  bytes 684  errors 0

### CURL [options] url

Fetches a web page; see [Web pages and HTTPS](#web-pages-and-https-curl-and-sslproxy).

### NC [options] host port, NC [options] -L port

A TCP connection on your terminal; see [File transfer](#file-transfer-tftp-and-nc).

### NETDATE [/SET] [/QUICK] [server]

The date and time from a time server; see [NETDATE](#the-date-and-time-netdate).

### TLOAD and TDIR (MiSTer only)

See [MiSTer notes](#mister-notes).

### Command lines

Every command reads its whole command line, up to 127 characters (RSTS
hands programs only the first 80 otherwise). Qualifiers can be written
RSTS style, onto the command or each other (`TLOAD/UNLOAD`,
`NETDATE/SET/QUICK`), or after spaces. A `/` inside a parameter, such as
a URL, is left alone.

DCL upper-cases what you type outside quotes, so options cannot differ
only in case, and anything whose case matters, such as a URL path, goes in
double quotes:

    $ CURL -o page.htm "http://example.com/Some/Path"

## Web pages and HTTPS: CURL and sslproxy

    CURL[/qualifiers] url          or, as Unix curl:
    CURL [-i] [-h] [-L] [-s] [-v] [-k] [-t|-b] [-x proxy] [-o file] url

| Qualifier | Option | Meaning |
|---|---|---|
| `/OUTPUT=file` | `-o file` | Save the body to a file instead of showing it |
| `/TEXT`, `/BINARY` | `-t`, `-b` | With `/OUTPUT`: save as text / binary whatever the server says |
| `/HEADERS` | `-i` | Show the response headers too |
| `/HEAD` | `-h` | Ask for the headers only |
| `/FOLLOW` | `-L` | Follow redirects (up to 5) |
| `/QUIET` | `-s` | No progress or error chatter |
| `/VERBOSE` | `-v` | Show how the proxy's TLS went |
| `/INSECURE` | `-k` | Fetch even when the certificate does not check out |
| `/PROXY=host:port` | `-x host:port` | Use this proxy (`none`: no proxy); else `PROXY` in TCPIP.INI |

Qualifiers can be shortened to three letters (`/OUT=`, `/FOL`), two for
`/QU`, `/TE` and `/BI`; `/HEAD` and `/HEADERS` are written out to the
fifth letter (`/HEADE`). The URL is the parameter, in quotes when its case
matters:

    $ CURL/FOLLOW/OUTPUT=PAGE.HTM "http://example.com/Some/Path"

**Saved files.** A `text/...` response is saved as an ordinary RSTS text
file (CR LF lines, no attributes), which EDT and the compilers read.
Anything else is saved as binary with its exact length recorded in the
file's RMS attributes.

**HTTPS.** RSTS has no TLS, so `https://` goes through **sslproxy**, a
small program for any machine with Python 3 (the MiSTer's own Linux works,
see [MiSTer notes](#mister-notes)):

    python3 sslproxy.py [--port 3128] [--bind 0.0.0.0] [--allow 192.168.1.0/24]

CURL sends it the request in plain HTTP; the proxy fetches the page over
TLS, checks the certificate, and answers in plain HTTP with what it found
in `X-TLS-*` headers (`CURL -v` shows them). A certificate that does not
check out is refused unless you give `-k`. Only addresses in `--allow`
may use the proxy (default: private and loopback networks), so it is not
an open proxy. Set it once in TCPIP.INI:

    PROXY    192.168.1.10:3128

## The date and time: NETDATE

    NETDATE                  show the server's time and how far off the system is
    NETDATE /SET             set the system date and time from it
    NETDATE /QUICK           set it now, to the nearest minute
    NETDATE /SET server      the same, from this server

NETDATE asks a time server (SNTP, UDP port 123): the one named, else `NTP`
in TCPIP.INI, else the gateway (many home routers answer). It converts the
time to local time with `TIMEZONE` and, with `/SET`, sets the system clock
to within about half a second. RSTS sets the time in whole minutes and starts
the seconds again from zero, so `/SET` waits for the start of the next
minute (between 2 and 62 seconds). `/QUICK` sets it at once to the nearest
minute instead, leaving the clock up to 30 seconds off. Setting needs the DATES privilege (`[1,2]` has
it).

`TCPIP.INS` runs `NETDATE /SET` at every start, in the background, when
TCPIP.INI has a `TIMEZONE` line. Without one NETDATE shows UTC and does
not set the clock (write `TIMEZONE UTC0` if UTC is what you want).

**TIMEZONE** is a POSIX TZ string: the standard time's name and its hours
*west* of UTC, then the daylight time's name and when it starts and ends
(month, week 1-5 with 5 = last, weekday 0 = Sunday, and an optional time,
default 02:00):

| Where | TIMEZONE |
|---|---|
| US Pacific | `PST8PDT,M3.2.0,M11.1.0` |
| US Eastern | `EST5EDT,M3.2.0,M11.1.0` |
| UK | `GMT0BST,M3.5.0/1,M10.5.0` |
| Central Europe | `CET-1CEST,M3.5.0,M10.5.0/3` |
| Australia (Sydney) | `AEST-10AEDT,M10.1.0,M4.1.0/3` |
| No daylight time | `UTC0`, `JST-9`, ... |

**The line clock.** RSTS keeps time by counting line-clock ticks, and it
must be told the rate: INIT option `HARDWR`, then `HERTZ 50` or
`HERTZ 60`. If it does not match the clock (on the MiSTer, the OSD's
50/60 Hz setting), the time runs a sixth fast or slow, however often
NETDATE sets it.

**Dates end in 2035.** RSTS stores a date as (year − 1970) × 1000 + day,
which runs out after 31-Dec-2035; NETDATE refuses to set a later date.

## File transfer: TFTP and NC

### The TFTP server

TFTPD serves files in `FTP$:` only, a system logical you point at one
account, for example:

    $ ASSIGN/SYSTEM SY:[1,100] FTP$

Names are upper-cased; anything with a device, account or directory is
refused. One transfer at a time. From another machine:

    tftp 192.168.1.240
    tftp> ascii              (text files: hello.c, prog.bas)
    tftp> put hello.c
    tftp> binary             (anything else)
    tftp> get prog.tsk

Text sent in `ascii` (netascii) becomes an ordinary RSTS text file; a
binary file keeps its exact length in its RMS attributes, and is sent
back up to that length. macOS's `tftp` defaults to binary: say `ascii`
for text.

### NC: a TCP connection

    NC[/INPUT=file][/OUTPUT=file][/TEXT|/BINARY] host port    connect
    NC[/INPUT=file][/OUTPUT=file][/TEXT|/BINARY]/LISTEN=port  wait for one
    NC [-i file] [-o file] [-t|-b] host port      (the same, Unix style)
    NC [-i file] [-o file] [-t|-b] -L port

Lines you type are sent (ending CR LF); CTRL/Z sends end-of-file; NC ends
when the other side closes. RSTS has no pipes, so:

- `/INPUT=file` (`-i file`) sends a file, then end-of-file (like
  `nc < file`);
- `/OUTPUT=file` (`-o file`) saves what arrives (like `nc > file`), as
  text or binary as for CURL (`/TEXT` or `/BINARY` to choose).

Example, copying a file to a Mac (`nc -l 9000 > hello.c` on the Mac):

    $ NC/INPUT=HELLO.C 192.168.1.10 9000

## MiSTer notes

These apply to the PDP2011 core with its own Main, `MiSTer_pdp2011`
(release 20261007 or later for everything below).

**Networking.** The OSD option *Host network* passes the DEUNA's frames
to the MiSTer's Linux: `eth0` shares the MiSTer's port, `tap0` uses a tap
interface. With `eth0` the PDP-11 cannot reach the MiSTer itself (frames
leave the port and never come back). To reach it, for sslproxy or TFTP
from the MiSTer, bridge `tap0` with `eth0` using `start_bridge.sh` from
the PDP2011 release (`linux/`), and choose `tap0`; `start_bridge.sh` also
starts sslproxy on port 3128. Wired Ethernet only.

**Tape library: TLOAD and TDIR.** Load tapes from RSTS instead of the
OSD. The library is `games/PDP2011` on the SD card and its folders
(`RSTS/V9.6`, `RSX/...`); `.tap` and `.tpc` images can be loaded.

    $ TDIR                      the top: folders (NAME/) and tapes
    $ TDIR RSTS                 a folder
    $ TDIR RSTS/V9.6            a folder below it
    $ TDIR RSTS/V9.6/*RAW*      matching names (* is a wildcard)
    $ TLOAD RSTS/V9.6/rsts_v9_6_install.tap
    $ MOUNT MT0:
    $ TLOAD                     what is on MT0:
    $ DISMOUNT MT0:
    $ TLOAD /UNLOAD             empty the drive

Paths use `/` between folders; case does not matter. Folders whose names
start with `_` (and folders with no tapes in them) are not listed, but a
tape in one can still be loaded by its path. TDIR's folder listing needs
MiSTer_pdp2011 with folder support (later than 20261011); older ones list
only the top. TLOAD will not change a
tape that is mounted, allocated or assigned by any job, your own
included: `DISMOUNT`, `DEALLOCATE` or `DEASSIGN` it first. TLOAD needs *Host
network* to be something other than Off; the requests go to
MiSTer_pdp2011 as Ethernet frames and never reach the network.

**50/60 Hz.** Set INIT `HARDWR HERTZ` to match the OSD (see
[NETDATE](#the-date-and-time-netdate)).

## Monitor fixes

RSTS/E V10.1 has two bugs that matter here. The kit fixes both in the
installed monitor with ONLPAT, through a program, **XEPAT**, that reads
this system's own monitor, checks the exact code, and writes an ONLPAT
command file carrying every old value; ONLPAT verifies each before it
changes it, so a monitor that differs is left alone. `TCPIP.INS` repeats
the check at every start, so a monitor you build later gets the fixes too.

1. **DEUNA receive crash.** The DEUNA/DELUA driver crashes the system on
   a received frame of 629-632 bytes: the frame's CRC alone lands in the
   last of its 632-byte receive buffers and the driver copies a negative
   length. Real controllers and SIMH both produce such frames. The fix is
   in resident code, so it takes effect at the next boot; TCP/IP waits for
   that reboot.
2. **Setting the time.** The monitor's set-time call zeroed the clock's
   tick counter, so the first second after the time was set lasted over
   4 seconds. This is Paul Koning's `timfix`, found here by its code
   pattern because its offset differs between monitors. It is in an
   overlay and works at once. NETDATE needs it.

Customizing the installation with **XEPATCH NO** turns this off (it leaves
`TCPIP$:XEPAT.NO`).

## Writing programs: the socket library

For PDP-11 C programs: BSD-style sockets in `TCPIP$:SOCK.H` — `socket`,
`bind`, `listen`, `accept`, `connect`, `send`, `recv`, `sendto`,
`recvfrom`, `shutdown`, `closesocket`, `getsockname`, `getpeername`,
`gethostbyname`, `htons`, `inet_addr`, `inet_ntoa` and friends, with a few
extras (`sonblk` non-blocking, `sotmo` timeouts, `soinfo` the settings,
`linehz` the line-clock rate), and `cmdarg` (`CMDLIN.H`) for reading the
whole command line RSTS style. `PROGRAMMING.md` is the full guide. Build:

    $ COPY TCPIP$:SOCK.H,TCPIP$:CMDLIN.H *.*
    $ CCC PROG.C
    $ LINK/CC/STACK=1024 PROG,TCPIP$:CMDLIN,TCPIP$:RESOLV,TCPIP$:SOCK,TCPIP$:ETHIO

(The default stack is too small for the library: give `/STACK=1024`.)

PDP-11 C keeps only six characters of global names, and does not
word-align `char` arrays: Ethernet and message buffers must be declared
as `unsigned` arrays. The kit's sources (`TCPIP$:*.C`, `*.MAC`) are
examples of all of this.

## Troubleshooting

| Symptom | What to check |
|---|---|
| `?... TCP/IP is not running` | Start it: `@SY:[0,91]TCPIP.INS`; see the start-up messages |
| "will start after the reboot" at start-up | The DEUNA fix was just installed; reboot |
| `TCP/IP has no address yet` | DHCP has not answered: check the network setting (MiSTer *Host network*), or set `IP`, `MASK`, `GATEWAY` |
| PING works by address, not by name | No name server: `HOST` shows the settings; set `DNS` |
| `CURL https://...` fails | Set `PROXY` and run sslproxy; `CURL -v` shows what the proxy said |
| NETDATE: no answer from the time server | The gateway does not serve time: set `NTP pool.ntp.org` |
| The clock drifts by about 10 s a minute | INIT `HARDWR HERTZ` does not match the line clock |
| TLOAD: no answer from the tape library | Not on MiSTer_pdp2011 20261007 or later, or *Host network* is Off |
| A received text file has odd line ends | Send text as text: TFTP `ascii`, CURL `-t`, NC `-t` |

## Limits

- IPv4 only; no IP fragments.
- Up to 4 TCP connections at a time.
- No TLS on RSTS itself: HTTPS goes through sslproxy.
- RSTS dates end on 31-Dec-2035.
- SIMH's NAT ignores the TCP MSS the stack advertises; the monitor fix
  covers the frame sizes that causes.

## Credits

- Paul Koning, for the RSTS patches this kit's time fix follows
  (<https://github.com/pkoning2/decstuff>).
- Tony Nicholson, for the RSTS/E V10.1 updates and research collected at
  <https://github.com/agn453/RSTS-E>.
- The RSTS/E V10.1 sources on bitsavers, which made finding and fixing
  the monitor bugs possible.
