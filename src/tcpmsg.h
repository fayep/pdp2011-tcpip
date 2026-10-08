/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* tcpmsg.h - messages between RSTS/E TCP/IP clients and the TCPIPD job.
 *
 * TCPIPD declares the local receiver "TCPIP ". A client declares a receiver
 * with a blank name (no privilege needed), sends requests to "TCPIP " and
 * gets replies on its job number. Requests and replies carry their fields in
 * the 20-byte parameter area of a local message; byte 0 is the operation.
 */
#define TM_NAME   "TCPIP "     /* the daemon's receiver name */

#define TM_PING   1             /* p[2..5] address, p[6..7] sequence,
				   p[8..9] data bytes (0..256) */
#define TM_PINGR  0x81          /* p[1] status, p[2..5] from, p[6..7] seq,
				   p[8] ttl */

/* status in replies */
#define TS_OK      0
#define TS_NOARP   1            /* no ARP reply from the next hop */
#define TS_NOROUTE 2            /* off our network and no gateway */
#define TS_DOWN    3            /* no address yet (DHCP) */
#define TS_BUSY    4            /* too many requests outstanding */

/* ---- TCP (V0.3) -------------------------------------------------------
 * A connection's data flows through a pseudo keyboard: TCPIPD holds PKn:,
 * the program opens the matching KBn: in binary mode (MODE 1), reads with
 * RECORD 8192 (no wait) and writes with RECORD 4096 (binary). Control and
 * events travel as messages. h = connection handle from TM_TCONR.
 */
#define TM_TCON   2             /* connect: p[2..5] address, p[6..7] port */
#define TM_TLSN   3             /* listen: p[6..7] local port (one connection) */
#define TM_TGO    4             /* p[2] h: KBn: is open, deliver data */
#define TM_TCLS   5             /* p[2] h: send FIN once all data is sent */
#define TM_TABT   6             /* p[2] h: abort (RST) */
#define TM_TCONR  0x82          /* p[1] status, p[2] h, p[3] KB number,
				   p[4..7] remote address, p[8..9] remote port */
#define TM_TEVT   0x86          /* p[1] event, p[2] h */

#define TE_EOF    1             /* the peer sent FIN: no more data after what is in KBn: */
#define TE_RESET  2             /* connection reset or timed out */
#define TE_CLOSED 3             /* both sides done: close KBn: */

#define TS_REFUSED 5            /* RST in answer to our SYN */
#define TS_TIMEOUT 6            /* no answer */

/* ---- UDP sockets -------------------------------------------------------
 * A datagram travels as one message: its first p[10] (0..9) bytes in
 * p[11..19], the rest (up to 512) as message data, so 521 bytes fit: a TFTP
 * data packet (4 + 512) included. u = socket handle from TM_UBNDR.
 */
#define TM_UBND   7             /* bind: p[6..7] local port, 0 = any */
#define TM_USND   8             /* p[1] u, p[2..5] to address, p[6..7] to port,
				   p[10..19] first bytes, data the rest */
#define TM_UCLS   9             /* p[1] u: unbind */
#define TM_UBNDR  0x87          /* p[1] status, p[2] u, p[6..7] the local port */
#define TM_URCV   0x88          /* p[1] u, p[2..5] from address, p[6..7] from
				   port, p[10..19] first bytes, data the rest */
#define UDP_MAX   521           /* the largest datagram a socket carries */
#define TM_TUNL   10            /* stop listening: p[6..7] local port */
/* TM_TCONR also carries p[10..11] = the local port (for accept) */
#define TM_INFO   11            /* our settings, please */
#define TM_ALIVE  0x8A          /* "are you still there?": programs ignore it */
#define TM_INFOR  0x89          /* p[1] status, p[2..5] address, p[6..9] mask,
				   p[10..13] gateway; data: name servers (2 x 4,
				   0.0.0.0 = none), domain (33), host name (33),
				   at 74 MAC (6), 80 flags (1 DHCP, 2 up), at 82
				   7 longs: lease seconds left, rx packets, rx bytes,
				   tx packets, tx bytes, rx errors, tx errors */
#define TM_TLSNR  0x83          /* p[1] status, p[6..7] the port */
/* TM_TCONR p[12] = 1 for a connection that arrived on a listening port */
