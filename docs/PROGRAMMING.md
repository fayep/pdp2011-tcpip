# RSTS/E TCP/IP V1.00 — Programmer's Guide

Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0: free for
non-commercial use with attribution
(<https://creativecommons.org/licenses/by-nc/4.0/>).

How to write PDP-11 C programs that use TCP/IP on RSTS/E. If you have
written sockets programs on Unix, most of this will be familiar: read
[How it works](#how-it-works) and [Differences from BSD](#differences-from-bsd),
then look at the [examples](#examples).

## Contents

1. [How it works](#how-it-works)
2. [Building a program](#building-a-program)
3. [Examples](#examples)
4. [Addresses and names](#addresses-and-names)
5. [TCP](#tcp)
6. [UDP](#udp)
7. [Waiting: blocking, timeouts, non-blocking](#waiting-blocking-timeouts-non-blocking)
8. [Errors](#errors)
9. [Settings and the interface: soinfo](#settings-and-the-interface-soinfo)
10. [Command lines](#command-lines)
11. [Function reference](#function-reference)
12. [Differences from BSD](#differences-from-bsd)
13. [Limits](#limits)
14. [PDP-11 C notes](#pdp-11-c-notes)
15. [Below the sockets: Ethernet portals](#below-the-sockets-ethernet-portals)

## How it works

The IP stack is one RSTS/E job, **TCPIPD**, started by
`[0,91]TCPIP.INS`. Your program does not talk to the network itself; the
socket library (`SOCK.OBJ`) talks to TCPIPD:

- **Control** — opening, binding, connecting, listening, closing — goes to
  TCPIPD as RSTS/E local messages (the message send/receive system
  calls). The library declares a message receiver for your job the first
  time you call `socket()`.
- **TCP data** flows through a **pseudo keyboard** (PK) that TCPIPD keeps
  for each connection. The library opens the matching `KBn:` and reads
  and writes it in binary mode, so a TCP connection costs no message
  traffic for its data, and RSTS buffers it for you.
- **UDP datagrams** travel as one message each way.

So a program needs TCPIPD to be running, and nothing else. Any number of
programs can use TCP/IP at once, within the [limits](#limits).

## Building a program

The kit installs everything you need in `TCPIP$:` (`SY:[0,91]`):

| File | What it is |
|---|---|
| `SOCK.H` | The declarations: include it |
| `SOCK.OBJ` | The socket library |
| `RESOLV.OBJ` | `gethostbyname` (DNS) |
| `CMDLIN.H`, `CMDLIN.OBJ` | `cmdarg`: the whole command line, split RSTS style (see [Command lines](#command-lines)) |
| `ETHIO.OBJ` | The RSTS/E system-call layer the library uses (MACRO-11) |
| `NETCFG.H`, `TCPMSG.H` | Lower-level declarations (see [Below the sockets](#below-the-sockets-ethernet-portals)) |
| `*.C`, `ETHIO.MAC` | The sources of the library and every command: more examples |

Copy the headers into your account, compile, and link with the three
object files:

    $ COPY TCPIP$:SOCK.H,TCPIP$:CMDLIN.H *.*
    $ CCC PROG.C
    $ LINK/CC/STACK=1024 PROG,TCPIP$:CMDLIN,TCPIP$:RESOLV,TCPIP$:SOCK,TCPIP$:ETHIO

**Give `/STACK=1024`**: the default stack is too small for the library.
Leave out `TCPIP$:RESOLV` if you never call `gethostbyname`, and
`TCPIP$:CMDLIN` if you never call `cmdarg`.

To run a program with arguments, define it as a command:

    $ DEFINE/COMMAND/SYSTEM/REPLACE PROG SY:[1,100]PROG.TSK
    $ PROG host 80

(`RUN PROG` works too, but passes no arguments; the examples ask instead.)

## Examples

Three short programs, in `examples/`, each showing one pattern. They are
tested on RSTS/E V10.1 (in SIMH, built exactly as above).

| Program | Shows |
|---|---|
| [`httpgt.c`](examples/httpgt.c) | A TCP client: look up a name, connect, send a request, read until the server closes |
| [`echod.c`](examples/echod.c) | A TCP server: listen, accept, echo, serve the next client |
| [`udpech.c`](examples/udpech.c) | UDP: send a datagram, wait for the reply with a timeout, retry |

The kit's own commands are larger examples: `NC.C` (a connection and the
terminal at once, without blocking), `CURL.C` (HTTP, files), `NETDAT.C`
(UDP, SNTP), `HOST.C` (DNS).

The heart of a TCP client:

```c
#include <stdio.h>
#include <string.h>
#include "sock.h"

struct sockaddr_in sa;
struct hostent *hp;
int s, n;
static unsigned bw[256];                /* even buffer: see PDP-11 C notes */
#define buf ((char *)bw)

hp = gethostbyname("example.com");
memset(&sa, 0, sizeof sa);
sa.sin_family = AF_INET;
sa.sin_port = htons(80);
memcpy(&sa.sin_addr, hp->h_addr, 4);
s = socket(AF_INET, SOCK_STREAM, 0);
connect(s, (struct sockaddr *)&sa, sizeof sa);
send(s, "GET / HTTP/1.0\r\n\r\n", 18, 0);
while ((n = recv(s, buf, sizeof bw, 0)) > 0)
	fwrite(buf, 1, n, stdout);
closesocket(s);
```

and of a TCP server:

```c
sa.sin_port = htons(7777);
sa.sin_addr.s_addr = INADDR_ANY;
ls = socket(AF_INET, SOCK_STREAM, 0);
bind(ls, (struct sockaddr *)&sa, sizeof sa);
listen(ls, 1);
for (;;) {
	alen = sizeof peer;
	s = accept(ls, (struct sockaddr *)&peer, &alen);
	while ((n = recv(s, buf, sizeof bw, 0)) > 0)
		send(s, buf, n, 0);
	closesocket(s);
}
```

(The real programs check every call; see [Errors](#errors).)

## Addresses and names

Addresses are `struct sockaddr_in`, as on BSD: `sin_family = AF_INET`,
`sin_port` a port in **network byte order** (use `htons`), `sin_addr` the
four address bytes in network order. Clear the structure first with
`memset`.

- `inet_addr("192.168.1.10")` turns dotted text into an address
  (`INADDR_NONE` if it is not one); `inet_ntoa(addr)` turns one back into
  text (a static buffer, overwritten by the next call).
- `gethostbyname(name)` looks a name up with DNS, using the name servers
  from DHCP or `DNS` in `TCPIP.INI`; a short name is also tried with the
  `DOMAIN`. It accepts dotted addresses too, so a program can take either.
  It returns `0` on failure, with the reason in `h_errno` (`hstrerror`
  describes it): `HOST_NOT_FOUND`, `TRY_AGAIN` (no answer from the name
  servers), `NO_RECOVERY` (no name server set), `NO_DATA` (no address for
  that name). Copy the address out of `hp->h_addr` before the next call.

## TCP

**A client** calls `socket(AF_INET, SOCK_STREAM, 0)`, then
`connect()`. `connect` waits until the connection is made or refused, or
for 60 seconds.

**A server** calls `socket`, `bind` with the port (any address), and
`listen`. `listen` claims the port in TCPIPD; it fails with
`SE_ADDRINUSE` if another program has it. Each `accept()` waits for a
connection and returns a new socket for it, with the client's address in
the `sockaddr`. A program that ends without closing its listening socket
gives the port back automatically when the next program asks for it.

**Data.** `send(s, buf, len, 0)` sends all `len` bytes (it waits while
TCPIPD's buffers are full) and returns `len`. `recv(s, buf, len, 0)`
waits until some data has arrived and returns what there is, 1 to `len`
bytes: TCP is a byte stream, so one `send` at the other end may arrive in
several `recv`s or several in one. `recv` returns `0` when the other side
has closed and everything it sent has been read.

**Closing.** `shutdown(s, 1)` sends end-of-file (the other side's `recv`
gets 0) but keeps receiving. `closesocket(s)` closes the connection and
waits (up to 30 seconds) until it is closed at both ends, so data you sent
is delivered first.

`sokb(s)` gives the number of the pseudo keyboard a connection uses
(`KBn:`), for programs that want to know.

## UDP

`socket(AF_INET, SOCK_DGRAM, 0)` makes a datagram socket.

- `sendto(s, buf, len, 0, to, sizeof to)` sends one datagram of up to
  **521 bytes** (`UDP_MAX`). A socket that has not been bound gets a free
  local port the first time it sends.
- `recvfrom(s, buf, len, 0, from, &alen)` waits for the next datagram to
  that socket and gives its sender. A datagram longer than `len` is cut
  short, as on BSD.
- `bind` with a port to receive on a known port (a server).
- `connect` on a datagram socket only sets the default destination, so
  `send` and `recv` can be used instead of `sendto` and `recvfrom`.

UDP does not retry: a datagram, or its reply, may be lost. Use a timeout
(`sotmo`) and try again, as `udpech.c` does. Up to two datagrams wait for
a program between `recvfrom` calls; more are dropped, so read them
promptly.

## Waiting: blocking, timeouts, non-blocking

By default every call waits for its answer, as on BSD. While it waits,
the program sleeps; a message from TCPIPD wakes it at once, so waiting
costs no CPU time.

- `sotmo(s, seconds)` puts a time limit on `accept`, `recv` and
  `recvfrom` for that socket: after it they return `-1` with
  `soerr == SE_TIMEDOUT`. `sotmo(s, 0)` waits for ever again.
- `sonblk(s, 1)` makes a socket non-blocking: `accept`, `recv` and
  `recvfrom` return `-1` with `soerr == SE_AGAIN` at once when there is
  nothing yet. `sonblk(s, 0)` turns it off.

There is no `select()`. To watch several things — two connections, or a
connection and the terminal — make the sockets non-blocking, poll each in
turn, and sleep a second when nothing happened. `ethslp(1)` (from
`NETCFG.H`) is that sleep: it ends early when a message arrives from
TCPIPD (new data, a connection) or a key is typed, so the program still
responds at once. `NC.C` works this way:

```c
sonblk(s, 1);
for (;;) {
	idle = 1;
	if ((n = recv(s, buf, sizeof bw, 0)) > 0) {
		/* ... use the data ... */
		idle = 0;
	} else if (n == 0)
		break;                  /* the other side closed */
	else if (soerr != SE_AGAIN)
		break;                  /* an error */
	/* ... check the terminal, other sockets ... */
	if (idle)
		ethslp(1);
}
```

## Errors

Calls that fail return `-1` (or `0` for `gethostbyname`) and set
**`soerr`**; `sostr(soerr)` describes it. (`errno` is the C library's own
and is not used.)

| soerr | Meaning |
|---|---|
| `SE_NOTRUN` | TCPIPD is not running |
| `SE_NETDOWN` | TCP/IP has no address yet (DHCP has not answered) |
| `SE_NETUNREACH` | No route to that network |
| `SE_HOSTUNREACH` | The host did not answer ARP |
| `SE_CONNREFUSED` | Nothing listens on that port |
| `SE_CONNRESET` | The other side reset the connection |
| `SE_TIMEDOUT` | The time limit (`sotmo`, or `connect`'s 60 s) ran out |
| `SE_AGAIN` | Non-blocking: nothing yet |
| `SE_ADDRINUSE` | The port is already in use |
| `SE_NOBUFS` | TCPIPD has no free connection or socket |
| `SE_MFILE` | This program already has 8 sockets |
| `SE_MSGSIZE` | A datagram over 521 bytes |
| `SE_BADF` | Not an open socket |
| `SE_INVAL` | Not valid now (e.g. `recv` on an unconnected socket) |
| `SE_IO` | A RSTS/E error on the connection's keyboard |

The usual pattern:

```c
if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0
    || connect(s, (struct sockaddr *)&sa, sizeof sa) < 0) {
	printf("?PROG: %s\n", sostr(soerr));
	return 1;
}
```

## Settings and the interface: soinfo

`soinfo(&inf)` fills a `struct soinf` with TCPIPD's settings and
counters: our address, mask, gateway, name servers, domain, host name,
Ethernet address, whether the address came from DHCP and the lease time
left, and packets and bytes in and out. `HOST` (with no arguments) and
`IFCONFIG` are built on it. It returns `-1` with `SE_NOTRUN` when TCPIPD
is not running, so it is also the way to ask "is TCP/IP up?":
`inf.up` is non-zero once TCP/IP has an address.

`linehz()` returns the line clock's rate, 50 or 60: useful for turning
RSTS/E's clock ticks into time.

## Command lines

A program run as a command gets only the first 80 characters of its
line through `argv`, split by the C run-time library. RSTS/E keeps the
whole line, up to 127 characters, in core common; `cmdarg` (in
`CMDLIN.H`, `CMDLIN.OBJ`) reads it and replaces `argc` and `argv` with
its words, split the way RSTS/E commands are:

```c
#include "cmdlin.h"

int main(int argc, char **argv)
{
	cmdarg("MYPROG", 0, &argc, &argv);
	/* argv[0] is the command word, argv[1].. the rest */
```

- Words are separated by spaces and tabs.
- A `/` starts a new word in the command word and in qualifiers:
  `MYPROG/LIST/BRIEF x` gives `MYPROG`, `/LIST`, `/BRIEF`, `x`. A `/`
  inside a parameter (a URL, say) does not.
- `"quoted text"` is one word, without the quotes, with its case and any
  `/` kept.
- The first argument names the command, or several separated by spaces
  (`"TLOAD TDIR"`, for one program with two command names). The line is
  used only when its first word is one of them (at least two letters), so
  a program started with `RUN` keeps the run-time library's `argv`.
- The second argument, if non-zero, lower-cases the unquoted words after
  the command (DCL upper-cases everything typed outside quotes). It
  follows that options cannot differ only in case.

It returns 1 when it used the line, 0 when it left `argv` alone. The
kit's commands all use it.

`cmdqal(word, name, min, &value)` recognises a qualifier: it returns 1
when `word` is `/name` shortened to at least `min` letters (any case),
and sets `value` to what follows an `=`, or 0. `CURL.C` and `NC.C` use it:

```c
for (i = 1; i < argc; i++) {
	char *v;
	if (cmdqal(argv[i], "OUTPUT", 3, &v) && v)
		ofile = v;                      /* /OUTPUT=file, /OUT=file */
	else if (cmdqal(argv[i], "QUIET", 2, &v))
		quiet = 1;                      /* /QUIET, /QU */
	else if (argv[i][0] == '/')
		printf("?MYPROG: unknown qualifier %s\n", argv[i]);
	else
		file = argv[i];                 /* the parameter */
}
```

## Function reference

| Function | Returns | Notes |
|---|---|---|
| `socket(AF_INET, type, 0)` | socket, or -1 | `SOCK_STREAM` (TCP) or `SOCK_DGRAM` (UDP) |
| `bind(s, addr, len)` | 0 / -1 | Only the port is used |
| `listen(s, backlog)` | 0 / -1 | TCP; `backlog` is ignored |
| `accept(s, addr, &len)` | new socket / -1 | Waits for a connection |
| `connect(s, addr, len)` | 0 / -1 | TCP: waits up to 60 s. UDP: sets the default destination |
| `send(s, buf, len, 0)` | `len` / -1 | TCP: all of it; UDP: to the default destination |
| `recv(s, buf, len, 0)` | 1..`len`, 0 at the end, -1 | |
| `sendto(s, buf, len, 0, to, tolen)` | `len` / -1 | UDP, up to 521 bytes |
| `recvfrom(s, buf, len, 0, from, &fromlen)` | length / -1 | UDP |
| `shutdown(s, how)` | 0 | `how` 1 or 2: send end-of-file |
| `closesocket(s)` | 0 / -1 | TCP: waits up to 30 s for the close |
| `getsockname(s, addr, &len)` | 0 / -1 | Our address and port |
| `getpeername(s, addr, &len)` | 0 / -1 | The other side's |
| `sotmo(s, seconds)` | 0 / -1 | Time limit for waits; 0 = none |
| `sonblk(s, on)` | 0 / -1 | Non-blocking on or off |
| `sokb(s)` | KB number / -1 | The connection's pseudo keyboard |
| `gethostbyname(name)` | `struct hostent *` / 0 | `h_errno`, `hstrerror()` |
| `soinfo(&inf)` | 0 / -1 | Settings and counters |
| `linehz()` | 50 or 60 | |
| `htons`, `ntohs`, `htonl`, `ntohl` | | Byte order |
| `inet_addr(text)`, `inet_ntoa(addr)` | | Dotted addresses |
| `sostr(e)`, `soerr` | | Errors |
| `cmdarg(names, lower, &argc, &argv)` | 1 / 0 | The whole command line (`CMDLIN.H`) |
| `cmdqal(word, name, min, &value)` | 1 / 0 | Is `word` the qualifier `/name`? (`CMDLIN.H`) |

The `flags` arguments of `send`, `recv`, `sendto` and `recvfrom` are
ignored; pass 0.

## Differences from BSD

- **`closesocket()`**, not `close()`, closes a socket (`close` is C's
  own).
- **`soerr`** and **`sostr()`**, not `errno` and `strerror()`.
- **No `select()`** or `poll()`: use non-blocking sockets and `ethslp(1)`
  (see [Waiting](#waiting-blocking-timeouts-non-blocking)).
- **`sotmo()`** and **`sonblk()`** in place of `setsockopt` /
  `fcntl`; there are no other socket options.
- **Datagrams** are at most 521 bytes.
- `listen`'s backlog and the `flags` arguments are ignored. A TCP socket
  is bound to a port only by `listen`.

## Limits

- 8 sockets per program (`SO_MAX`).
- 4 TCP connections at a time for the whole system (TCPIPD's).
- Datagrams of up to 521 bytes; 2 waiting per program.
- TCP: a 4 KB receive window and 2 KB send buffer per connection.
- IPv4 only; no IP fragments.
- The library uses I/O **channels 12 to 15** for connections, and the
  job's **message receiver**. Do not use those channels for anything else,
  and do not declare a receiver of your own.

## PDP-11 C notes

- **Even buffers.** PDP-11 C does not word-align `char` arrays, and
  RSTS/E's I/O wants even addresses. The library copies odd buffers for
  you, but declaring buffers as `unsigned` arrays is faster and is what
  the examples do:

      static unsigned bw[256];
      #define buf ((char *)bw)

- **Six characters.** Global names are significant to six characters
  only: keep your own globals distinct in their first six.
- **`int` is 16 bits**, `long` 32. Ports fit an `unsigned`; byte counts
  over 32767 need a `long`.
- **The stack**: link with `/STACK=1024` (or more).
- **Command lines.** A program run as a command gets at most 80
  characters of arguments through `argv`, upper-cased by DCL unless
  quoted: use `cmdarg` (see [Command lines](#command-lines)).

## Below the sockets: Ethernet portals

TCP/IP is built on RSTS/E's Ethernet **portal** interface, which any
privileged program can use for its own protocols: open the controller for
one Ethernet protocol type and send and receive whole frames. `ETHIO.MAC`
wraps it for C (declared in `NETCFG.H`):

| Function | Does |
|---|---|
| `ethopn(chan, unit, ptype, nbuf)` | Open `XEunit:` on channel `chan` for protocol type `ptype` (written as the PDP-11 word of the type field: 08-00 is `0x0008`) with `nbuf` receive buffers |
| `ethput(chan, frame, len)` | Send a frame (60 to 1514 bytes; destination filled in, source and type added by the driver) |
| `ethget(chan, buf, size, wait)` | Receive a frame; `wait` 0 returns at once (`-5`: nothing) |
| `ethmul(chan, addrs, n)` | Receive these multicast addresses too |
| `ethcls(chan)` | Close |
| `ethslp(seconds)` | Sleep; a frame, a message or typed input ends it |

Frame buffers must be even (word arrays). `TLOAD.C` is a complete small
example: it uses its own protocol type (88-B5) to talk to the MiSTer's
tape library. TCPIPD keeps the IP (08-00) and ARP (08-06) types, so a
program using portals must choose another type.
