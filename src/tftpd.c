/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* tftpd.c - TFTP server (RFC 1350) for RSTS/E, a program on the socket
 * library: UDP port 69 through the TCPIPD job.
 *
 * Runs only when TCPIP$:TCPIP.INI says TFTP YES (the default); detaches
 * like TCPIPD when it says DETACH YES.
 *
 * Files live only in FTP$: (a system logical for one account). Names are
 * upper-cased; anything with a device, account or directory is refused.
 * One transfer at a time; a second client gets "busy". netascii is sent as
 * stored: RSTS text files already end their lines with CR LF.
 *
 * Writes: netascii becomes an ordinary RSTS text file (CR LF lines, no
 * attributes; netascii's CR NUL goes back to CR). octet gets RMS attributes
 * of undefined record format (a byte stream) with its end-of-file block and
 * first free byte, so RSTS knows the exact length.
 * Reads: a file is sent up to the end its attributes record; one without
 * attributes (text, C stdio and CREATE write none) is sent in whole blocks,
 * except that netascii drops the NUL padding of the last block.
 */
#include <stdio.h>
#include <string.h>
#include "netcfg.h"
#include "sock.h"

#define CH_RD     10            /* reads: RSTS block I/O on this channel */
#define SEG       512
#define RETRY_SEC 2
#define MAX_TRY   5

static char cpyrt[] = "RSTS/E TFTPD V1.00  Copyright (c) 2026 Faye Salwin\n"
	"Free for non-commercial use with attribution (CC BY-NC 4.0)\n";

static int s69, sx = -1;                /* the request socket; the transfer's */
static unsigned inw[(UDP_MAX + 1) / 2], outw[(UDP_MAX + 1) / 2];
#define in  ((unsigned char *)inw)
#define obuf ((unsigned char *)outw)
static int attached = 1;

static struct {
	int active, writing;            /* transfer in progress; WRQ */
	int done;                       /* WRQ complete: file closed, lingering to re-ACK */
	struct sockaddr_in peer;        /* the client */
	FILE *f;                        /* WRQ: written with stdio */
	int rd;                         /* RRQ: file open on CH_RD */
	unsigned nblk;                  /* RRQ: its size in blocks */
	unsigned block;                 /* last block sent (RRQ) or acked (WRQ) */
	int len;                        /* bytes in obuf for a retransmit */
	int text;                       /* netascii */
	int prevcr;                     /* netascii write: last byte was CR */
	long size;                      /* RRQ: exact length from attributes; -1 unknown */
	char name[24];                  /* FTP$:NAME, for the attributes */
	int last;                       /* RRQ: last block was short */
	int tries;
	long sent;                      /* time of the last send */
	long bytes;
} xf;

static long secs()
{
	int w[3];

	tickd(w);
	return (1440L - w[0]) * 60L + (60 - w[1]);
}

static long since(long t0)
{
	long t = secs() - t0;

	return t < 0 ? t + 86400L : t;
}

static void tftp_error(int s, struct sockaddr_in *to, int code, char *msg)
{
	static unsigned ew[60];
	unsigned char *e = (unsigned char *)ew;
	int n = 0;

	PUT16(e, 5);
	PUT16(e + 2, code);
	while (msg[n] && n < 100) {
		e[4 + n] = msg[n];
		n++;
	}
	e[4 + n] = 0;
	sendto(s, (char *)e, 4 + n + 1, 0, (struct sockaddr *)to, sizeof *to);
}

static void xf_send()                   /* (re)send what is in obuf */
{
	sendto(sx, (char *)obuf, xf.len, 0, (struct sockaddr *)&xf.peer, sizeof xf.peer);
	xf.sent = secs();
}

static void xf_end()
{
	if (xf.f)
		fclose(xf.f);
	if (xf.rd)
		fcls(CH_RD);
	xf.f = 0;
	xf.rd = 0;
	xf.active = 0;
	xf.done = 0;
	if (sx >= 0)
		closesocket(sx);
	sx = -1;
}

static void rrq_next()                  /* read and send the next data block */
{
	unsigned blk = xf.block + 1;
	int n = blk <= xf.nblk ? fblk(CH_RD, (char *)obuf + 4, blk) : 0;

	if (n < 0)
		n = 0;
	if (xf.size >= 0) {                     /* stop at the recorded end */
		if (xf.bytes + n > xf.size)
			n = xf.size > xf.bytes ? (int)(xf.size - xf.bytes) : 0;
	} else if (xf.text && blk >= xf.nblk) { /* last block of a text file: no NULs */
		while (n > 0 && obuf[4 + n - 1] == 0)
			n--;
	}
	xf.block++;
	PUT16(obuf, 3);
	PUT16(obuf + 2, xf.block);
	xf.len = 4 + n;
	xf.last = n < SEG;
	xf.bytes += n;
	xf.tries = 0;
	xf_send();
}

static void wrq_ack()                   /* acknowledge xf.block */
{
	PUT16(obuf, 4);
	PUT16(obuf + 2, xf.block);
	xf.len = 4;
	xf.tries = 0;
	xf_send();
}

/* "name" from a request -> FTP$:NAME, or 0 if it is not a plain file name */
static char *ftpname(unsigned char *p, int n, char *buf)
{
	int i;
	char c;

	strcpy(buf, "FTP$:");
	for (i = 0; i < n && p[i]; i++) {
		c = p[i];
		if (c >= 'a' && c <= 'z')
			c -= 'a' - 'A';
		if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '$'))
			return 0;
		if (i >= 10)
			return 0;
		buf[5 + i] = c;
	}
	if (i == 0 || i >= n)
		return 0;
	buf[5 + i] = 0;
	return buf;
}

/* RMS attributes for a binary file of len bytes: undefined record format
 * (a byte stream), highest block, end-of-file block and first free byte */
static void set_length(char *name, long len)
{
	int w[7];
	long blocks = (len + SEG - 1) / SEG, eof = len / SEG + 1;

	w[0] = 0;                               /* undefined record format */
	w[1] = 0;
	w[2] = (int)(blocks >> 16); w[3] = (int)blocks;
	w[4] = (int)(eof >> 16);    w[5] = (int)eof;
	w[6] = (int)(len % SEG);
	fatw(name, w, 7);
}

static long get_length(char *name)              /* -1: no recorded length */
{
	int w[11];
	long eof;

	if (fatr(name, w) != 0)
		return -1L;
	eof = (long)(unsigned)w[4] << 16 | (unsigned)w[5];
	if (eof == 0)
		return -1L;
	return (eof - 1) * SEG + (unsigned)w[6];
}

static void tftp_request(struct sockaddr_in *from, unsigned char *t, int tlen)
{
	unsigned char *m;
	unsigned op = GET16(t);
	char name[24], *fn;

	if (xf.active && xf.done)
		xf_end();               /* a finished write was only lingering */
	if (xf.active) {
		if (from->sin_port == xf.peer.sin_port &&
		    from->sin_addr.s_addr == xf.peer.sin_addr.s_addr)
			return;         /* the client resent its request */
		tftp_error(s69, from, 0, "busy, try again later");
		return;
	}
	if ((fn = ftpname(t + 2, tlen - 2, name)) == 0) {
		tftp_error(s69, from, 2, "only plain file names in FTP$:");
		return;
	}
	for (m = t + 2; m < t + tlen && *m; m++)
		;                               /* the mode follows the name */
	xf.text = m + 1 < t + tlen && (m[1] == 'n' || m[1] == 'N');
	xf.size = op == 1 ? get_length(fn) : -1L;
	strcpy(xf.name, fn);
	xf.f = 0;
	xf.rd = 0;
	if (op == 1)
		xf.rd = fopn(fn, CH_RD, &xf.nblk) == 0;
	else {
		fdel(fn);       /* TFTP replaces a file; stdio cannot open one with attributes */
		xf.f = fopen(fn, "wb");
	}
	if (!xf.f && !xf.rd) {
		tftp_error(s69, from, op == 1 ? 1 : 2,
			   op == 1 ? "file not found" : "cannot create file");
		return;
	}
	if ((sx = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {       /* the transfer's port */
		tftp_error(s69, from, 0, "no socket for the transfer");
		xf_end();
		return;
	}
	sonblk(sx, 1);
	xf.peer = *from;
	xf.active = 1;
	xf.writing = op == 2;
	xf.done = 0;
	xf.block = 0;
	xf.bytes = 0;
	xf.prevcr = 0;
	if (op == 1)
		rrq_next();
	else
		wrq_ack();
}

static void tftp_transfer(unsigned char *t, int tlen)
{
	unsigned op = GET16(t), blk = GET16(t + 2);

	if (op == 5) {                  /* client gave up */
		xf_end();
		return;
	}
	if (!xf.writing && op == 4) {   /* ACK */
		if (blk != xf.block)
			return;
		if (xf.last) {
			xf_end();
			return;
		}
		rrq_next();
	} else if (xf.writing && op == 3) {     /* DATA */
		if (xf.done) {                  /* our final ACK was lost */
			if (blk == xf.block)
				wrq_ack();
			return;
		}
		if (blk == xf.block) {          /* duplicate: our ACK was lost */
			wrq_ack();
			return;
		}
		if (blk != xf.block + 1)
			return;
		if (xf.text) {                  /* netascii: CR NUL -> CR */
			int i, bad = 0;
			for (i = 4; i < tlen; i++) {
				if (!(t[i] == 0 && xf.prevcr) && putc(t[i], xf.f) == EOF)
					bad = 1;
				xf.prevcr = t[i] == '\r';
			}
			if (bad) {
				tftp_error(sx, &xf.peer, 3, "disk full or write error");
				xf_end();
				return;
			}
		} else if (tlen > 4 && fwrite(t + 4, 1, tlen - 4, xf.f) != tlen - 4) {
			tftp_error(sx, &xf.peer, 3, "disk full or write error");
			xf_end();
			return;
		}
		xf.block = blk;
		xf.bytes += tlen - 4;
		wrq_ack();
		if (tlen - 4 < SEG) {           /* last block: close, linger to re-ACK */
			fclose(xf.f);
			xf.f = 0;
			xf.done = 1;
			if (!xf.text)
				set_length(xf.name, xf.bytes);
		}
	}
}

int main()
{
	struct sockaddr_in a;
	int n, alen, e, busy;
	long t0;

	printf("%s", cpyrt);
	cfgld();
	if (!cfgtft) {
		printf("tftpd: TFTP NO in TCPIP.INI; not started\n");
		return 0;
	}
	if ((s69 = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("tftpd: %s\n", sostr(soerr));
		return 1;
	}
	memset(&a, 0, sizeof a);
	a.sin_family = AF_INET;
	a.sin_port = htons(69);
	t0 = secs();
	while ((e = bind(s69, (struct sockaddr *)&a, sizeof a)) < 0 &&
	       soerr == SE_NOTRUN && since(t0) < 60)
		ethslp(2);                      /* TCPIPD still starting */
	if (e < 0) {
		printf("tftpd: cannot use port 69: %s\n", sostr(soerr));
		return 1;
	}
	sonblk(s69, 1);
	printf("tftpd: serving FTP$: on UDP port 69\n");
	if (cfgdet) {
		if ((e = ethdet()) != 0)
			printf("tftpd: cannot detach, error %d; running attached\n", e);
		else
			attached = 0;
	}
	for (;;) {
		busy = 0;
		alen = sizeof a;
		if ((n = recvfrom(s69, (char *)in, UDP_MAX, 0, (struct sockaddr *)&a, &alen)) >= 4) {
			unsigned op = GET16(in);
			if (op == 1 || op == 2)
				tftp_request(&a, in, n);
			busy = 1;
		}
		if (sx >= 0) {
			alen = sizeof a;
			if ((n = recvfrom(sx, (char *)in, UDP_MAX, 0, (struct sockaddr *)&a, &alen)) >= 4) {
				if (a.sin_port == xf.peer.sin_port &&
				    a.sin_addr.s_addr == xf.peer.sin_addr.s_addr)
					tftp_transfer(in, n);
				else if (GET16(in) != 5)
					tftp_error(sx, &a, 5, "unknown transfer ID");
				busy = 1;
			}
		}
		if (xf.active && xf.done && since(xf.sent) >= 2 * RETRY_SEC)
			xf_end();               /* finished lingering after a write */
		else if (xf.active && !xf.done && since(xf.sent) >= RETRY_SEC) {
			if (++xf.tries > MAX_TRY)
				xf_end();               /* client vanished */
			else
				xf_send();
		}
		if (!busy)
			ethslp(xf.active ? 1 : 30);     /* a datagram ends the sleep */
	}
}
