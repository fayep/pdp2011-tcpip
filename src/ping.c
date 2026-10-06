/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* ping.c - send ICMP echo requests through the TCPIPD job.
 *
 *	PING address [count]
 *
 * The program declares a receiver with a blank name (no privilege needed),
 * asks TCPIPD for each echo with a local message and waits for its answer;
 * a message ends the sleep at once. Times come from the line clock
 * (.DATE ticks), so they are good to a tick (1/60 or 1/50 second).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "netcfg.h"
#include "tcpmsg.h"

#define WAIT_SEC 3              /* per echo */
#define HZ 60                   /* ticks per second */

static unsigned pw[10], dw[16];  /* word arrays: message buffers must be even */
#define p ((unsigned char *)pw)

static long now_ticks()         /* ticks since midnight */
{
	int w[3];

	tickd(w);
	return ((1440L - w[0]) * 60L + (60 - w[1])) * HZ + (HZ - w[2]);
}

static int parse_ip(char *s, unsigned char *ip)
{
	int a, b, c, d;

	if (sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d) != 4 ||
	    (a | b | c | d) < 0 || a > 255 || b > 255 || c > 255 || d > 255)
		return 0;
	ip[0] = a; ip[1] = b; ip[2] = c; ip[3] = d;
	return 1;
}

static char *why(int status)
{
	switch (status) {
	case TS_NOARP:   return "host unreachable (no ARP reply)";
	case TS_NOROUTE: return "network unreachable (no gateway)";
	case TS_DOWN:    return "TCP/IP has no address yet";
	case TS_BUSY:    return "TCPIPD is busy";
	}
	return "error";
}

int main(int argc, char **argv)
{
	char line[80], *host, *cnt;
	unsigned char ip[4];
	int count = 4, i, n, job2, e, sent = 0, got = 0;
	long t0, t, tmin = 0, tmax = 0, tsum = 0;

	if (argc > 1) {
		host = argv[1];
		cnt = argc > 2 ? argv[2] : 0;
	} else {
		printf("Ping which address? ");
		if (!fgets(line, sizeof line, stdin))
			return 1;
		host = strtok(line, " \t\n");
		cnt = strtok((char *)0, " \t\n");
		if (!host)
			return 1;
	}
	if (cnt && (count = atoi(cnt)) < 1)
		count = 1;
	if (!parse_ip(host, ip)) {
		printf("?PING: give an address as a.b.c.d (names need DNS, not yet)\n");
		return 1;
	}
	msgrem();
	if ((e = msgdcl("      ", 4)) != 0) {
		printf("?PING: cannot declare a message receiver, error %d\n", e);
		return 1;
	}
	printf("PING %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
	for (i = 1; i <= count; i++) {
		memset(p, 0, 20);
		p[0] = TM_PING;
		memcpy(p + 2, ip, 4);
		PUT16(p + 6, i);
		PUT16(p + 8, 32);
		t0 = now_ticks();
		if ((e = msgsnd(TM_NAME, 0, (char *)p, (char *)dw, 0)) != 0) {
			printf("?PING: TCP/IP is not running (error %d sending to %s)\n", e, TM_NAME);
			break;
		}
		sent++;
		for (;;) {
			n = msgrcv((char *)p, (char *)dw, sizeof dw, &job2);
			t = now_ticks() - t0;
			if (t < 0)
				t += 86400L * HZ;       /* past midnight */
			if (n >= 0 && p[0] == TM_PINGR && GET16(p + 6) == (unsigned)i) {
				if (p[1] != TS_OK) {
					printf("seq=%d: %s\n", i, why(p[1]));
					break;
				}
				t = t * 1000L / HZ;
				printf("reply from %d.%d.%d.%d: seq=%d ttl=%d time=%ld ms\n",
				       p[2], p[3], p[4], p[5], i, p[8], t);
				if (!got || t < tmin) tmin = t;
				if (t > tmax) tmax = t;
				tsum += t;
				got++;
				break;
			}
			if (n >= 0 || n == -1)
				continue;               /* someone else's message */
			if (t >= WAIT_SEC * HZ) {
				printf("seq=%d: no reply\n", i);
				break;
			}
			ethslp(1);                      /* a message wakes us at once */
		}
		if (i < count) {                        /* about a second between echoes */
			while ((t = now_ticks() - t0) >= 0 && t < HZ)
				ethslp(1);
		}
	}
	msgrem();
	printf("%d sent, %d received", sent, got);
	if (got)
		printf(", time min/avg/max = %ld/%ld/%ld ms", tmin, tsum / got, tmax);
	printf("\n");
	return got ? 0 : 1;
}
