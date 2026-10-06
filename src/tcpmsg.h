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
