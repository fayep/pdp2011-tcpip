/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* sock.c - BSD-style sockets for RSTS/E programs, through the TCPIPD job.
 *
 * Control goes to TCPIPD as local messages (tcpmsg.h). A TCP connection's
 * data flows through the pseudo keyboard TCPIPD holds for it: this side
 * opens the matching KBn: in binary mode (MODE 1), reads with RECORD 8192
 * (no wait) and writes with RECORD 4096 (binary, no formatting). A UDP
 * datagram travels as one message each way.
 *
 * Everything TCPIPD sends lands in this job's one message queue, so poll()
 * sorts it: connection replies and datagrams wait in small queues until
 * the call that wants them comes along.
 */
#include <stdio.h>
#include <string.h>
#include "netcfg.h"
#include "tcpmsg.h"
#include "sock.h"

#define CH0   3                 /* KB channels: CH0 + TCP handle (0..3) */
#define TH_N  4                 /* TCP handles (TCPIPD's connections) */
#define CQ_N  4                 /* connection replies waiting */
#define DQ_N  2                 /* datagrams waiting */
#define S_NEW  0
#define S_LSN  1
#define S_CON  2
#define S_BND  3                /* UDP: bound */

int soerr;

static struct sk {
	int type;               /* 0 = free */
	int st;
	int h;                  /* TCP handle or UDP socket in TCPIPD */
	unsigned lport;         /* host order */
	unsigned char rip[4];
	unsigned rport;
	int nbio, tmo, finsent;
} sk[SO_MAX];
static struct {
	int open, eof, reset, closed, kb;
} hs[TH_N];
static unsigned char cq[CQ_N][14];
static int ncq;
static struct dq {
	int u, len;
	unsigned char ip[4];
	unsigned port;
	unsigned bw[(UDP_MAX + 1) / 2];
} dq[DQ_N];
static int ndq;
static int lsnst = -1, bndst = -1, bndu, infst = -1;
static struct soinf info;
static unsigned bndport;
static int declared;
static unsigned pw[10], dw[256], bw[256];       /* even buffers for RSTS */
#define p ((unsigned char *)pw)

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

static int request(int op, int b1, unsigned char *ip, unsigned port);
static void poll()                      /* sort what TCPIPD has sent */
{
	int n, job2;

	while ((n = msgrcv((char *)p, (char *)dw, sizeof dw, &job2)) >= 0 || n == -1) {
		if (n < 0)
			continue;
		switch (p[0]) {
		case TM_TCONR:
			if (ncq < CQ_N)
				memcpy(cq[ncq++], p, 14);
			else if (p[1] == TS_OK)         /* no room: refuse it */
				request(TM_TABT, p[2], (unsigned char *)0, 0);
			break;
		case TM_TLSNR:
			lsnst = p[1];
			break;
		case TM_INFOR:
			memcpy(info.ip, p + 2, 4);
			memcpy(info.mask, p + 6, 4);
			memcpy(info.gw, p + 10, 4);
			memcpy(info.dns, dw, 8);
			memcpy(info.domain, (char *)dw + 8, 33);
			memcpy(info.host, (char *)dw + 41, 33);
			info.domain[32] = info.host[32] = 0;
			infst = p[1];
			break;
		case TM_UBNDR:
			bndst = p[1];
			bndu = p[2];
			bndport = GET16(p + 6);
			break;
		case TM_TEVT:
			if (p[2] < TH_N) {
				if (p[1] == TE_EOF) hs[p[2]].eof = 1;
				if (p[1] == TE_RESET) hs[p[2]].reset = 1;
				if (p[1] == TE_CLOSED) hs[p[2]].closed = 1;
			}
			break;
		case TM_URCV:
			if (ndq < DQ_N && p[10] <= 9 && n + p[10] <= UDP_MAX) {
				struct dq *d = &dq[ndq++];
				d->u = p[1];
				memcpy(d->ip, p + 2, 4);
				d->port = GET16(p + 6);
				memcpy(d->bw, p + 11, p[10]);
				memcpy((char *)d->bw + p[10], dw, n);
				d->len = p[10] + n;
			}               /* else dropped, as UDP may */
			break;
		}
	}
}

static int request(int op, int b1, unsigned char *ip, unsigned port)
{
	memset(p, 0, 20);
	p[0] = op;
	p[1] = b1;
	p[2] = b1;
	if (ip)
		memcpy(p + 2, ip, 4);
	PUT16(p + 6, port);
	if (msgsnd(TM_NAME, 0, (char *)p, (char *)dw, 0) != 0) {
		soerr = SE_NOTRUN;
		return -1;
	}
	return 0;
}

static int fromts(int ts)               /* a TS_ status as an SE_ error */
{
	switch (ts) {
	case TS_NOARP:   return SE_HOSTUNREACH;
	case TS_NOROUTE: return SE_NETUNREACH;
	case TS_DOWN:    return SE_NETDOWN;
	case TS_BUSY:    return SE_NOBUFS;
	case TS_REFUSED: return SE_CONNREFUSED;
	case TS_TIMEOUT: return SE_TIMEDOUT;
	}
	return SE_IO;
}

static struct sk *getsk(int s)
{
	if (s < 0 || s >= SO_MAX || !sk[s].type) {
		soerr = SE_BADF;
		return 0;
	}
	return &sk[s];
}

/* wait for something: 1 when cond() holds, 0 on time-out or non-blocking */
static int await(struct sk *k, int (*cond)(), long limit)
{
	long t0 = secs();

	if (k && k->tmo && (!limit || k->tmo < limit))
		limit = k->tmo;
	for (;;) {
		poll();
		if ((*cond)())
			return 1;
		if (k && k->nbio) {
			soerr = SE_AGAIN;
			return 0;
		}
		if (limit && since(t0) >= limit) {
			soerr = SE_TIMEDOUT;
			return 0;
		}
		ethslp(1);              /* a message ends the sleep at once */
	}
}

static int want_lport, want_passive, want_u, got_i;
static int cq_ready()
{
	int i;

	for (i = 0; i < ncq; i++)
		if (cq[i][12] == want_passive &&
		    (!want_passive || GET16(cq[i] + 10) == (unsigned)want_lport)) {
			got_i = i;
			return 1;
		}
	return 0;
}
static int lsn_ready() { return lsnst >= 0; }
static int bnd_ready() { return bndst >= 0; }
static int inf_ready() { return infst >= 0; }
static int dq_ready()
{
	int i;

	for (i = 0; i < ndq; i++)
		if (dq[i].u == want_u) {
			got_i = i;
			return 1;
		}
	return 0;
}

static void setaddr(struct sockaddr *a, int *alen, unsigned char *ip, unsigned port)
{
	struct sockaddr_in *in = (struct sockaddr_in *)a;

	if (!a)
		return;
	memset(in, 0, sizeof *in);
	in->sin_family = AF_INET;
	in->sin_port = htons(port);
	memcpy(&in->sin_addr, ip, 4);
	if (alen)
		*alen = sizeof *in;
}

/* a TCP connection from TCPIPD's reply r: open its KB, onto socket k */
static int takecon(struct sk *k, unsigned char *r)
{
	int h = r[2], e;
	char kbn[10];

	if (r[1] != TS_OK) {
		soerr = fromts(r[1]);
		return -1;
	}
	if (h >= TH_N) {
		request(TM_TABT, h, (unsigned char *)0, 0);
		soerr = SE_NOBUFS;
		return -1;
	}
	memset(&hs[h], 0, sizeof hs[h]);
	hs[h].kb = r[3];
	sprintf(kbn, "KB%d:", r[3]);
	if ((e = dopn(kbn, CH0 + h, 1)) < 0) {
		request(TM_TABT, h, (unsigned char *)0, 0);
		soerr = SE_IO;
		return -1;
	}
	hs[h].open = 1;
	k->type = SOCK_STREAM;
	k->st = S_CON;
	k->h = h;
	memcpy(k->rip, r + 4, 4);
	k->rport = GET16(r + 8);
	k->lport = GET16(r + 10);
	k->finsent = 0;
	request(TM_TGO, h, (unsigned char *)0, 0);
	return 0;
}

static void cq_drop(int i)
{
	for (; i < ncq - 1; i++)
		memcpy(cq[i], cq[i + 1], 14);
	ncq--;
}

static int declare()
{
	if (!declared) {
		msgrem();
		if (msgdcl("      ", 16) != 0) {
			soerr = SE_IO;
			return -1;
		}
		declared = 1;
	}
	return 0;
}

int soinfo(struct soinf *inf)
{
	if (declare() < 0)
		return -1;
	poll();
	infst = -1;
	if (request(TM_INFO, 0, (unsigned char *)0, 0) < 0)
		return -1;
	if (!await((struct sk *)0, inf_ready, 10L))
		return -1;
	*inf = info;
	return 0;
}

int socket(int domain, int type, int protocol)
{
	int s;

	if (domain != AF_INET || (type != SOCK_STREAM && type != SOCK_DGRAM)) {
		soerr = SE_INVAL;
		return -1;
	}
	if (declare() < 0)
		return -1;
	for (s = 0; s < SO_MAX; s++)
		if (!sk[s].type)
			break;
	if (s == SO_MAX) {
		soerr = SE_MFILE;
		return -1;
	}
	memset(&sk[s], 0, sizeof sk[s]);
	sk[s].type = type;
	sk[s].st = S_NEW;
	return s;
}

static int udpbind(struct sk *k, unsigned port)
{
	poll();
	bndst = -1;
	if (request(TM_UBND, 0, (unsigned char *)0, port) < 0)
		return -1;
	if (!await((struct sk *)0, bnd_ready, 10L))
		return -1;
	if (bndst != TS_OK) {
		soerr = bndst == TS_BUSY && port ? SE_ADDRINUSE : fromts(bndst);
		return -1;
	}
	k->h = bndu;
	k->lport = bndport;
	k->st = S_BND;
	return 0;
}

int bind(int s, struct sockaddr *a, int alen)
{
	struct sk *k = getsk(s);
	unsigned port = ntohs(((struct sockaddr_in *)a)->sin_port);

	if (!k)
		return -1;
	if (k->st != S_NEW) {
		soerr = SE_INVAL;
		return -1;
	}
	if (k->type == SOCK_DGRAM)
		return udpbind(k, port);
	k->lport = port;                /* TCP: the port is claimed by listen() */
	return 0;
}

int listen(int s, int backlog)
{
	struct sk *k = getsk(s);

	if (!k)
		return -1;
	if (k->type != SOCK_STREAM || k->st != S_NEW || !k->lport) {
		soerr = SE_INVAL;
		return -1;
	}
	poll();
	lsnst = -1;
	if (request(TM_TLSN, 0, (unsigned char *)0, k->lport) < 0)
		return -1;
	if (!await((struct sk *)0, lsn_ready, 10L))
		return -1;
	if (lsnst != TS_OK) {
		soerr = SE_ADDRINUSE;
		return -1;
	}
	k->st = S_LSN;
	return 0;
}

int accept(int s, struct sockaddr *a, int *alen)
{
	struct sk *k = getsk(s);
	int n;
	unsigned char r[14];

	if (!k)
		return -1;
	if (k->st != S_LSN) {
		soerr = SE_INVAL;
		return -1;
	}
	want_passive = 1;
	want_lport = k->lport;
	if (!await(k, cq_ready, 0L))
		return -1;
	memcpy(r, cq[got_i], 14);
	cq_drop(got_i);
	if ((n = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		request(TM_TABT, r[2], (unsigned char *)0, 0);
		return -1;
	}
	if (takecon(&sk[n], r) < 0) {
		sk[n].type = 0;
		return -1;
	}
	setaddr(a, alen, sk[n].rip, sk[n].rport);
	return n;
}

int connect(int s, struct sockaddr *a, int alen)
{
	struct sk *k = getsk(s);
	struct sockaddr_in *in = (struct sockaddr_in *)a;
	unsigned char r[14];

	if (!k)
		return -1;
	if (k->type == SOCK_DGRAM) {            /* the default destination */
		memcpy(k->rip, &in->sin_addr, 4);
		k->rport = ntohs(in->sin_port);
		return 0;
	}
	if (k->st != S_NEW) {
		soerr = SE_INVAL;
		return -1;
	}
	poll();
	while (ncq > 0 && cq[0][12] == 0)       /* stale replies */
		cq_drop(0);
	if (request(TM_TCON, 0, (unsigned char *)&in->sin_addr, ntohs(in->sin_port)) < 0)
		return -1;
	want_passive = 0;
	if (!await((struct sk *)0, cq_ready, 60L))
		return -1;
	memcpy(r, cq[got_i], 14);
	cq_drop(got_i);
	return takecon(k, r);
}

static int tcpwrite(struct sk *k, char *buf, int len)
{
	int n, done = 0, c;

	while (done < len) {
		c = len - done;
		if ((unsigned)(buf + done) & 1) {       /* RSTS wants even buffers */
			if (c > (int)sizeof bw)
				c = sizeof bw;
			memcpy(bw, buf + done, c);
			n = dwr(CH0 + k->h, (char *)bw, c, 4096);
		} else
			n = dwr(CH0 + k->h, buf + done, c, 4096);
		if (n < 0) {
			poll();
			soerr = hs[k->h].reset ? SE_CONNRESET : SE_IO;
			return done ? done : -1;
		}
		done += n;
	}
	return done;
}

int send(int s, char *buf, int len, int flags)
{
	struct sk *k = getsk(s);

	if (!k)
		return -1;
	if (k->type == SOCK_DGRAM) {
		struct sockaddr_in to;
		if (!k->rport) {
			soerr = SE_INVAL;
			return -1;
		}
		setaddr((struct sockaddr *)&to, (int *)0, k->rip, k->rport);
		return sendto(s, buf, len, flags, (struct sockaddr *)&to, sizeof to);
	}
	if (k->st != S_CON || k->finsent) {
		soerr = SE_INVAL;
		return -1;
	}
	return tcpwrite(k, buf, len);
}

static int tcpread(struct sk *k, char *buf, int len)
{
	int n, h = k->h;
	char *b = (unsigned)buf & 1 ? (char *)bw : buf;
	long t0 = secs();

	if (b != buf && len > (int)sizeof bw)
		len = sizeof bw;
	for (;;) {
		n = drd(CH0 + h, b, len, 8192);
		if (n > 0) {
			/* room made in KBn:'s input: wake TCPIPD to fill it (a read
			 * that does not wait is no "state change" that wakes it) */
			request(TM_TGO, h, (unsigned char *)0, 0);
			break;
		}
		poll();
		if (hs[h].reset) {
			soerr = SE_CONNRESET;
			return -1;
		}
		if (hs[h].eof || hs[h].closed) {        /* data from before the EOF? */
			n = drd(CH0 + h, b, len, 8192);
			if (n <= 0)
				return 0;
			break;
		}
		if (k->nbio) {
			soerr = SE_AGAIN;
			return -1;
		}
		if (k->tmo && since(t0) >= k->tmo) {
			soerr = SE_TIMEDOUT;
			return -1;
		}
		ethslp(1);
	}
	if (b != buf)
		memcpy(buf, b, n);
	return n;
}

int recv(int s, char *buf, int len, int flags)
{
	struct sk *k = getsk(s);

	if (!k)
		return -1;
	if (k->type == SOCK_DGRAM)
		return recvfrom(s, buf, len, flags, (struct sockaddr *)0, (int *)0);
	if (k->st != S_CON) {
		soerr = SE_INVAL;
		return -1;
	}
	return tcpread(k, buf, len);
}

int sendto(int s, char *buf, int len, int flags, struct sockaddr *to, int tolen)
{
	struct sk *k = getsk(s);
	struct sockaddr_in *in = (struct sockaddr_in *)to;
	int f;

	if (!k)
		return -1;
	if (k->type != SOCK_DGRAM)
		return send(s, buf, len, flags);
	if (len < 0 || len > UDP_MAX) {
		soerr = SE_MSGSIZE;
		return -1;
	}
	if (k->st != S_BND && udpbind(k, 0) < 0)
		return -1;
	f = len > 512 ? len - 512 : 0;          /* first bytes in the parameters */
	memset(p, 0, 20);
	p[0] = TM_USND;
	p[1] = k->h;
	memcpy(p + 2, &in->sin_addr, 4);
	PUT16(p + 6, ntohs(in->sin_port));
	p[10] = f;
	memcpy(p + 11, buf, f);
	memcpy(dw, buf + f, len - f);
	if (msgsnd(TM_NAME, 0, (char *)p, (char *)dw, len - f) != 0) {
		soerr = SE_NOTRUN;
		return -1;
	}
	return len;
}

int recvfrom(int s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen)
{
	struct sk *k = getsk(s);
	struct dq *d;
	int n, i;

	if (!k)
		return -1;
	if (k->type != SOCK_DGRAM) {
		if ((n = recv(s, buf, len, flags)) >= 0)
			setaddr(from, fromlen, k->rip, k->rport);
		return n;
	}
	if (k->st != S_BND) {
		soerr = SE_INVAL;
		return -1;
	}
	want_u = k->h;
	if (!await(k, dq_ready, 0L))
		return -1;
	d = &dq[got_i];
	n = d->len < len ? d->len : len;        /* the rest is lost, as BSD */
	memcpy(buf, d->bw, n);
	setaddr(from, fromlen, d->ip, d->port);
	for (i = got_i; i < ndq - 1; i++)
		dq[i] = dq[i + 1];
	ndq--;
	return n;
}

int shutdown(int s, int how)
{
	struct sk *k = getsk(s);

	if (!k)
		return -1;
	if (k->type == SOCK_STREAM && k->st == S_CON && how != 0 && !k->finsent) {
		request(TM_TCLS, k->h, (unsigned char *)0, 0);
		k->finsent = 1;
	}
	return 0;
}

static int closed_h;
static int tcp_done() { return hs[closed_h].closed || hs[closed_h].reset; }

int closesocket(int s)
{
	struct sk *k = getsk(s);
	int r = 0;

	if (!k)
		return -1;
	if (k->type == SOCK_STREAM && k->st == S_CON) {
		if (!k->finsent)
			request(TM_TCLS, k->h, (unsigned char *)0, 0);
		closed_h = k->h;
		if (!await((struct sk *)0, tcp_done, 30L))
			r = -1;
		fcls(CH0 + k->h);
		hs[k->h].open = 0;
	} else if (k->type == SOCK_STREAM && k->st == S_LSN)
		request(TM_TUNL, 0, (unsigned char *)0, k->lport);
	else if (k->type == SOCK_DGRAM && k->st == S_BND)
		request(TM_UCLS, k->h, (unsigned char *)0, 0);
	k->type = 0;
	return r;
}

int getsockname(int s, struct sockaddr *a, int *alen)
{
	struct sk *k = getsk(s);
	static unsigned char any[4];

	if (!k)
		return -1;
	setaddr(a, alen, any, k->lport);
	return 0;
}

int getpeername(int s, struct sockaddr *a, int *alen)
{
	struct sk *k = getsk(s);

	if (!k)
		return -1;
	setaddr(a, alen, k->rip, k->rport);
	return 0;
}

int sonblk(int s, int on)
{
	struct sk *k = getsk(s);

	if (!k)
		return -1;
	k->nbio = on;
	return 0;
}

int sotmo(int s, int seconds)
{
	struct sk *k = getsk(s);

	if (!k)
		return -1;
	k->tmo = seconds;
	return 0;
}

int sokb(int s)
{
	struct sk *k = getsk(s);

	return k && k->type == SOCK_STREAM && k->st == S_CON ? hs[k->h].kb : -1;
}

unsigned htons(unsigned x)
{
	return (x & 0xFF) << 8 | (x >> 8 & 0xFF);
}

unsigned ntohs(unsigned x)
{
	return htons(x);
}

/* a long's bytes on the PDP-11: high word first, each word low byte first */
unsigned long htonl(unsigned long x)
{
	unsigned char b[4], *q = (unsigned char *)&x;

	b[0] = q[1]; b[1] = q[0]; b[2] = q[3]; b[3] = q[2];
	memcpy(&x, b, 4);
	return x;
}

unsigned long ntohl(unsigned long x)
{
	return htonl(x);
}

unsigned long inet_addr(char *cp)
{
	int a, b, c, d;
	unsigned char ip[4];
	unsigned long r;

	if (sscanf(cp, "%d.%d.%d.%d", &a, &b, &c, &d) != 4 ||
	    (a | b | c | d) < 0 || a > 255 || b > 255 || c > 255 || d > 255)
		return INADDR_NONE;
	ip[0] = a; ip[1] = b; ip[2] = c; ip[3] = d;
	memcpy(&r, ip, 4);
	return r;
}

char *inet_ntoa(struct in_addr in)
{
	static char s[16];
	unsigned char *q = (unsigned char *)&in.s_addr;

	sprintf(s, "%d.%d.%d.%d", q[0], q[1], q[2], q[3]);
	return s;
}

char *sostr(int e)
{
	switch (e) {
	case SE_BADF:        return "not an open socket";
	case SE_INVAL:       return "not valid now";
	case SE_AGAIN:       return "nothing yet";
	case SE_TIMEDOUT:    return "timed out";
	case SE_CONNREFUSED: return "connection refused";
	case SE_CONNRESET:   return "connection reset";
	case SE_NETDOWN:     return "TCP/IP has no address yet";
	case SE_NETUNREACH:  return "network unreachable";
	case SE_HOSTUNREACH: return "host unreachable";
	case SE_NOBUFS:      return "TCPIPD has no room";
	case SE_ADDRINUSE:   return "port in use";
	case SE_NOTRUN:      return "TCP/IP is not running";
	case SE_MFILE:       return "too many sockets";
	case SE_MSGSIZE:     return "datagram too long";
	}
	return "I/O error";
}
