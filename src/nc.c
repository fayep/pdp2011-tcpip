/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* nc.c - netcat for RSTS/E: a TCP connection to the terminal.
 *
 *	NC address port         connect
 *	NC -L port              wait for one connection
 *
 * Lines typed are sent as typed (ending CR LF); what arrives is shown.
 * CTRL/Z sends end-of-file (FIN); the program ends when the other side
 * closes too.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "netcfg.h"
#include "tcpmsg.h"
#include "tcplib.h"

static unsigned bw[128], lw[64];
#define buf ((char *)bw)
#define line ((char *)lw)

static int parse_ip(char *s, unsigned char *ip)
{
	int a, b, c, d;

	if (sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d) != 4 ||
	    (a | b | c | d) < 0 || a > 255 || b > 255 || c > 255 || d > 255)
		return 0;
	ip[0] = a; ip[1] = b; ip[2] = c; ip[3] = d;
	return 1;
}

static char *why(int s)
{
	switch (s) {
	case TS_NOARP:   return "host unreachable";
	case TS_NOROUTE: return "network unreachable";
	case TS_DOWN:    return "TCP/IP has no address yet";
	case TS_BUSY:    return "no free connection";
	case TS_REFUSED: return "connection refused";
	case TS_TIMEOUT: return "no answer";
	}
	return s > 100 ? "TCP/IP is not running" : "error";
}

int main(int argc, char **argv)
{
	unsigned char ip[4];
	int h, n, listen = 0, sentfin = 0, idle;
	unsigned port;
	char in[80], *a1, *a2;

	if (argc > 2) {
		a1 = argv[1];
		a2 = argv[2];
	} else {
		printf("NC address port, or NC -L port? ");
		if (!fgets(in, sizeof in, stdin))
			return 1;
		a1 = strtok(in, " \t\n");
		a2 = strtok((char *)0, " \t\n");
	}
	if (!a1 || !a2) {
		printf("?NC: give an address and a port, or -L and a port\n");
		return 1;
	}
	listen = (a1[0] == '-' && (a1[1] == 'L' || a1[1] == 'l'));
	port = (unsigned)atol(a2);
	if (!listen && !parse_ip(a1, ip)) {
		printf("?NC: give the address as a.b.c.d (names need DNS, not yet)\n");
		return 1;
	}
	if (tcpopn() != 0) {
		printf("?NC: cannot declare a message receiver\n");
		return 1;
	}
	if (listen) {
		printf("Listening on port %u\n", port);
		h = tcplsn(port);
	} else
		h = tcpcon(ip, port);
	if (h < 0) {
		printf("?NC: %s\n", why(-h));
		return 1;
	}
	printf("Connected %s %d.%d.%d.%d port %u (KB%d:)\n", listen ? "from" : "to",
	       tcprip[0], tcprip[1], tcprip[2], tcprip[3], tcprpt, tcpkb(h));
	fflush(stdout);
	for (;;) {
		idle = 1;
		n = tcpred(h, buf, sizeof bw);
		if (n > 0) {
			fwrite(buf, 1, n, stdout);
			fflush(stdout);
			idle = 0;
		} else if (n == 0) {
			printf("\n[connection closed by the other side]\n");
			break;
		} else if (n == -2) {
			printf("\n[connection reset]\n");
			tcpabt(h);
			return 1;
		}
		if (!sentfin) {
			n = drd(0, line, sizeof lw - 2, 8192);  /* a typed line, if any */
			if (n > 0) {
				if (line[n - 1] == '\r')       /* the line ends CR: send CR LF */
					line[n++] = '\n';
				tcpwrt(h, line, n);
				idle = 0;
			} else if (n == -11) {                  /* CTRL/Z */
				tcpfin(h);
				sentfin = 1;
				idle = 0;
			}
		}
		if (idle)
			ethslp(1);      /* typing, data or a message ends the sleep */
	}
	tcpcls(h);
	return 0;
}
