/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* tcplib.c - TCP for RSTS/E programs, through the TCPIPD job.
 *
 * Control goes to TCPIPD as local messages (tcpmsg.h); a connection's data
 * flows through the pseudo keyboard TCPIPD holds for it: this side opens
 * the matching KBn: in binary mode (MODE 1), reads with RECORD 8192 (no
 * wait) and writes with RECORD 4096 (binary, no formatting).
 */
#include <stdio.h>
#include <string.h>
#include "netcfg.h"
#include "tcpmsg.h"
#include "tcplib.h"

#define CH0 3                           /* KB channels: CH0 .. CH0+TCP_MAXH-1 */

unsigned char tcprip[4];
unsigned tcprpt;
static struct {
	int open, kb, eof, reset, closed;
} hs[TCP_MAXH];
static unsigned pw[10], dw[16];
#define p ((unsigned char *)pw)

static long secs()
{
	int w[3];

	tickd(w);
	return (1440L - w[0]) * 60L + (60 - w[1]);
}

/* take pending messages; a TM_TCONR is copied to r[] (20 bytes), 1 if so */
static int poll(unsigned char *r)
{
	int n, job2, got = 0;

	while ((n = msgrcv((char *)p, (char *)dw, sizeof dw, &job2)) >= 0 || n == -1) {
		if (n < 0)
			continue;
		if (p[0] == TM_TCONR && r) {
			memcpy(r, p, 20);
			got = 1;
		} else if (p[0] == TM_TEVT && p[2] < TCP_MAXH) {
			if (p[1] == TE_EOF) hs[p[2]].eof = 1;
			if (p[1] == TE_RESET) hs[p[2]].reset = 1;
			if (p[1] == TE_CLOSED) hs[p[2]].closed = 1;
		}
	}
	return got;
}

static int request(int op, unsigned char *ip, unsigned port, int h)
{
	memset(p, 0, 20);
	p[0] = op;
	p[2] = h;
	if (ip)
		memcpy(p + 2, ip, 4);
	PUT16(p + 6, port);
	return msgsnd(TM_NAME, 0, (char *)p, (char *)dw, 0);
}

int tcpopn()
{
	msgrem();
	return msgdcl("      ", 16) ? -1 : 0;
}

/* wait for TCPIPD's answer (wait seconds, 0 = for ever), open the KB */
static int answer(long wait)
{
	unsigned char r[20];
	long t0 = secs();
	int h, e;
	char kbn[10];

	for (;;) {
		if (poll(r))
			break;
		if (wait && secs() - t0 > wait)
			return -TS_TIMEOUT;
		ethslp(5);                      /* a message ends the sleep */
	}
	if (r[1] != TS_OK)
		return -r[1];
	h = r[2];
	memset(&hs[h], 0, sizeof hs[h]);
	hs[h].kb = r[3];
	memcpy(tcprip, r + 4, 4);
	tcprpt = GET16(r + 8);
	sprintf(kbn, "KB%d:", hs[h].kb);
	if ((e = dopn(kbn, CH0 + h, 1)) < 0) {
		request(TM_TABT, (unsigned char *)0, 0, h);
		return e;
	}
	hs[h].open = 1;
	request(TM_TGO, (unsigned char *)0, 0, h);
	return h;
}

int tcpcon(unsigned char *ip, unsigned port)
{
	int e;

	poll((unsigned char *)0);
	if ((e = request(TM_TCON, ip, port, 0)) != 0)
		return -100 - e;                /* TCPIPD not running */
	return answer(60L);
}

int tcplsn(unsigned port)
{
	int e;

	poll((unsigned char *)0);
	if ((e = request(TM_TLSN, (unsigned char *)0, port, 0)) != 0)
		return -100 - e;
	return answer(0L);
}

int tcpred(int h, char *buf, int size)
{
	int n = drd(CH0 + h, buf, size, 8192);

	if (n > 0)
		return n;
	poll((unsigned char *)0);
	if (hs[h].reset)
		return -2;
	if (hs[h].eof || hs[h].closed) {        /* data written before the EOF event? */
		n = drd(CH0 + h, buf, size, 8192);
		return n > 0 ? n : 0;
	}
	return -1;
}

int tcpwrt(int h, char *buf, int len)
{
	int n;

	while (len > 0) {
		n = dwr(CH0 + h, buf, len, 4096);
		if (n < 0)
			return n;
		buf += n;
		len -= n;
	}
	return 0;
}

void tcpfin(int h)
{
	request(TM_TCLS, (unsigned char *)0, 0, h);
}

int tcpcls(int h)
{
	long t0 = secs();

	request(TM_TCLS, (unsigned char *)0, 0, h);
	while (!hs[h].closed && !hs[h].reset && secs() - t0 < 30) {
		poll((unsigned char *)0);
		if (!hs[h].closed)
			ethslp(2);
	}
	fcls(CH0 + h);
	hs[h].open = 0;
	return hs[h].closed ? 0 : -1;
}

void tcpabt(int h)
{
	request(TM_TABT, (unsigned char *)0, 0, h);
	fcls(CH0 + h);
	hs[h].open = 0;
}

int tcpkb(int h)
{
	return hs[h].kb;
}
