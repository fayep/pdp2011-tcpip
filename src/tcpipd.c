/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* tcpipd.c - the RSTS/E TCP/IP job: ARP, ICMP echo, UDP, DHCP client,
 * ping service for local programs, and a TFTP server (RFC 1350, optional).
 *
 * One job, two Ethernet portals (IP and ARP), and the local message receiver
 * "TCPIP " (tcpmsg.h). The job polls the portals and its messages without
 * stalling and sleeps when there is nothing to do; a frame for either portal
 * or a queued message ends the sleep at once, and the sleep doubles as the
 * retransmit timer.
 *
 * Addresses: the next hop is the destination when (dst & mask) == (us & mask)
 * (plain CIDR, so a /23 works), else the gateway. ARP answers are kept in a
 * small cache; a request waits up to ARP_WAIT seconds for one.
 *
 * Files live only in FTP$: (a system logical for one account). Names are
 * upper-cased; anything with a device, account or directory is refused.
 * One transfer at a time; a second client gets "busy". netascii is sent as
 * stored: RSTS text files already end their lines with CR LF.
 *
 * Exact file lengths: a file written by TFTP gets RMS attributes (fixed
 * 512-byte records, end-of-file block and first free byte, as the task
 * builder writes them), so RSTS knows its true length. A file read is sent
 * up to the end its attributes record; one without attributes (C stdio and
 * CREATE write none) is sent in whole blocks, except that netascii drops the
 * NUL padding of the last block.
 */
#include <stdio.h>
#include <time.h>
#include <string.h>
#include "netcfg.h"
#include "tcpmsg.h"

#define CH_IP   12
#define CH_ARP  13
#define CH_RD   10              /* TFTP reads: RSTS block I/O on this channel */
#define TFTP_PORT 69
#define SEG     512
#define RETRY_SEC 2
#define MAX_TRY 5
#define ARP_N   8               /* ARP cache entries */
#define ARP_AGE 600             /* seconds an ARP entry is trusted */
#define ARP_WAIT 3              /* seconds to wait for an ARP reply */
#define PING_N  4               /* outstanding ping requests */

#define mymac cfgmac             /* from netcfg.c */
#define myip  cfgip
static unsigned bcastw[3] = { 0xFFFF, 0xFFFF, 0xFFFF };
#define bcast ((unsigned char *)bcastw)
/* kept in the task image: who wrote it and on what terms */
static char cpyrt[] = "RSTS/E TCP/IP V0.3  Copyright (c) 2026 Faye Salwin\n"
	"CC BY-NC 4.0: free for non-commercial use with attribution\n";
/* Frame buffers are word arrays: PDP-11 C does not align char arrays, and
 * the XE driver takes .READ/.WRITE buffers as given -- an odd one crashes
 * the monitor (odd-address trap in kernel mode). */
static unsigned pktw[757];         /* received frame */
#define pkt ((unsigned char *)pktw)
static unsigned outw[757];         /* frame being sent: replies, DHCP */
#define out ((unsigned char *)outw)
static unsigned xoutw[757];        /* the transfer's frame, kept for resends:
                                      nothing else may build in it */
#define xout ((unsigned char *)xoutw)

static struct {
	int active, writing;            /* transfer in progress; WRQ */
	int done;                       /* WRQ complete: file closed, lingering to re-ACK */
	unsigned char mac[6], ip[4];    /* client */
	unsigned cport, sport;          /* client and our transfer port */
	FILE *f;                        /* WRQ: written with stdio */
	int rd;                         /* RRQ: file open on CH_RD */
	unsigned nblk;                  /* RRQ: its size in blocks */
	unsigned block;                 /* last block sent (RRQ) or acked (WRQ) */
	int len;                        /* bytes in xout[] for a retransmit */
	int text;                       /* netascii */
	long size;                      /* RRQ: exact length from attributes; -1 unknown */
	char name[24];                  /* FTP$:NAME, for the attributes */
	int last;                       /* RRQ: last block was short */
	int tries;
	long sent;                      /* time of the last send */
	long bytes;
} xf;
static unsigned next_port = 1024;

static struct arpe {
	unsigned char ip[4], mac[6];
	long when;
} arpc[ARP_N];

static struct pingq {
	int job2;                       /* client: job number * 2; 0 = free */
	unsigned char dst[4], hop[4];   /* destination, next hop */
	unsigned seq, len;
	int waiting;                    /* for the next hop's ARP reply */
	long since;
} pq[PING_N];

static unsigned msgpw[10];              /* message parameters (20 bytes) */
#define msgp ((unsigned char *)msgpw)
static unsigned msgdw[128];             /* message data */
static int attached = 1;        /* still on the terminal: may print */

static unsigned cksum_add(unsigned long s, unsigned char *p, int n)
{
	while (n > 1) {
		s += GET16(p);
		p += 2;
		n -= 2;
	}
	if (n)
		s += (unsigned)p[0] << 8;
	while (s >> 16)
		s = (s & 0xFFFF) + (s >> 16);
	return (unsigned)s;
}

static unsigned cksum(unsigned char *p, int n)
{
	return (unsigned)~cksum_add(0L, p, n) & 0xFFFF;
}

/* UDP checksum over the pseudo header and the datagram */
static unsigned udp_cksum(unsigned char *src, unsigned char *dst, unsigned char *u, int ulen)
{
	unsigned long s;

	s = cksum_add(0L, src, 4);
	s = cksum_add(s, dst, 4);
	s += 17;
	s += (unsigned)ulen;
	s = cksum_add(s, u, ulen);
	s = (unsigned)~s & 0xFFFF;
	return s ? (unsigned)s : 0xFFFF;
}

static int ours(unsigned char *a)
{
	int i;

	for (i = 0; i < 4; i++)
		if (a[i] != myip[i])
			return 0;
	return 1;
}

static int ipup()               /* do we have an address? */
{
	return (myip[0] | myip[1] | myip[2] | myip[3]) != 0;
}

/* build and send a UDP datagram in frame f; data is at f+42 already */
static void udp_send(unsigned char *f, unsigned char *mac, unsigned char *ip, unsigned dport,
		     unsigned sport, int dlen)
{
	unsigned char *h = f + ETH_HDR, *u = h + 20;
	int i, n;
	static unsigned ipid;

	for (i = 0; i < 6; i++) {
		f[i] = mac[i];
		f[6 + i] = mymac[i];
	}
	f[12] = 0x08; f[13] = 0x00;
	h[0] = 0x45; h[1] = 0;
	PUT16(h + 2, 20 + 8 + dlen);
	PUT16(h + 4, ++ipid);
	PUT16(h + 6, 0);
	h[8] = 64; h[9] = 17;
	PUT16(h + 10, 0);
	for (i = 0; i < 4; i++) {
		h[12 + i] = myip[i];
		h[16 + i] = ip[i];
	}
	PUT16(h + 10, cksum(h, 20));
	PUT16(u, sport);
	PUT16(u + 2, dport);
	PUT16(u + 4, 8 + dlen);
	PUT16(u + 6, 0);
	PUT16(u + 6, udp_cksum(myip, ip, u, 8 + dlen));
	n = ETH_HDR + 20 + 8 + dlen;
	if ((i = ethput(CH_IP, (char *)f, n < 60 ? 60 : n)) != 0 && attached)
		printf("tcpipd: send to port %u failed, error %d\n", dport, -i);
}

#define UDATA (out + ETH_HDR + 28)      /* UDP payload in out[] */
#define TDATA (xout + ETH_HDR + 28)     /* the transfer's TFTP payload */

static void tftp_error(unsigned char *mac, unsigned char *ip, unsigned dport, unsigned sport,
		       int code, char *msg)
{
	int n = 0;

	PUT16(UDATA, 5);
	PUT16(UDATA + 2, code);
	while (msg[n] && n < 100) {
		UDATA[4 + n] = msg[n];
		n++;
	}
	UDATA[4 + n] = 0;
	udp_send(out, mac, ip, dport, sport, 4 + n + 1);
}

static void xf_send()                   /* (re)send what is in xout[] */
{
	udp_send(xout, xf.mac, xf.ip, xf.cport, xf.sport, xf.len);
	xf.sent = time((long *)0);
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
}

static void rrq_next()                  /* read and send the next data block */
{
	unsigned blk = xf.block + 1;
	int n = blk <= xf.nblk ? fblk(CH_RD, (char *)TDATA + 4, blk) : 0;

	if (n < 0)
		n = 0;
	if (xf.size >= 0) {                     /* stop at the recorded end */
		if (xf.bytes + n > xf.size)
			n = xf.size > xf.bytes ? (int)(xf.size - xf.bytes) : 0;
	} else if (xf.text && blk >= xf.nblk) { /* last block of a text file: no NULs */
		while (n > 0 && TDATA[4 + n - 1] == 0)
			n--;
	}
	xf.block++;
	PUT16(TDATA, 3);
	PUT16(TDATA + 2, xf.block);
	xf.len = 4 + n;
	xf.last = n < SEG;
	xf.bytes += n;
	xf.tries = 0;
	xf_send();
}

static void wrq_ack()                   /* acknowledge xf.block */
{
	PUT16(TDATA, 4);
	PUT16(TDATA + 2, xf.block);
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

/* RMS attributes for a file of len bytes: fixed 512-byte records, highest
 * block, end-of-file block and first free byte (as TKB writes them) */
static void set_length(char *name, long len)
{
	int w[7];
	long blocks = (len + SEG - 1) / SEG, eof = len / SEG + 1;

	w[0] = 1;                               /* fixed-length records */
	w[1] = SEG;
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

static void tftp_request(unsigned char *mac, unsigned char *ip, unsigned cport,
			 unsigned char *t, int tlen)
{
	unsigned char *m;
	unsigned op = GET16(t);
	char name[24], *fn;

	if (xf.active && xf.done)
		xf_end();               /* a finished write was only lingering */
	if (xf.active) {
		if (cport == xf.cport && memcmp(ip, xf.ip, 4) == 0)
			return;         /* the client resent its request */
		tftp_error(mac, ip, cport, TFTP_PORT, 0, "busy, try again later");
		return;
	}
	if ((fn = ftpname(t + 2, tlen - 2, name)) == 0) {
		tftp_error(mac, ip, cport, TFTP_PORT, 2, "only plain file names in FTP$:");
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
		tftp_error(mac, ip, cport, TFTP_PORT, op == 1 ? 1 : 2,
			   op == 1 ? "file not found" : "cannot create file");
		return;
	}
	memcpy(xf.mac, mac, 6);
	memcpy(xf.ip, ip, 4);
	xf.cport = cport;
	xf.sport = next_port++;
	if (next_port > 60000)
		next_port = 1024;
	xf.active = 1;
	xf.writing = op == 2;
	xf.done = 0;
	xf.block = 0;
	xf.bytes = 0;
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
		if (tlen > 4 && fwrite(t + 4, 1, tlen - 4, xf.f) != tlen - 4) {
			tftp_error(xf.mac, xf.ip, xf.cport, xf.sport, 3, "disk full or write error");
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
			set_length(xf.name, xf.bytes);
		}
	}
}

/* ---- ARP cache and next hop ---- */
static struct arpe *arp_find(unsigned char *ip)
{
	int i;
	long now = time((long *)0);

	for (i = 0; i < ARP_N; i++)
		if (arpc[i].when && memcmp(arpc[i].ip, ip, 4) == 0 && now - arpc[i].when < ARP_AGE)
			return &arpc[i];
	return 0;
}

static void arp_learn(unsigned char *ip, unsigned char *mac)
{
	int i, old = 0;
	struct arpe *e = 0;

	for (i = 0; i < ARP_N; i++) {
		if (memcmp(arpc[i].ip, ip, 4) == 0) {
			e = &arpc[i];
			break;
		}
		if (arpc[i].when < arpc[old].when)
			old = i;
	}
	if (!e)
		e = &arpc[old];
	memcpy(e->ip, ip, 4);
	memcpy(e->mac, mac, 6);
	e->when = time((long *)0);
}

static void arp_request(unsigned char *ip)
{
	unsigned char *a = out + ETH_HDR;
	int i;

	memset(out, 0, 60);
	for (i = 0; i < 6; i++) {
		out[i] = 0xFF;
		a[8 + i] = mymac[i];
	}
	PUT16(a, 1);                    /* Ethernet */
	PUT16(a + 2, 0x0800);           /* IP */
	a[4] = 6; a[5] = 4;
	PUT16(a + 6, 1);                /* request */
	memcpy(a + 14, myip, 4);
	memcpy(a + 24, ip, 4);
	ethput(CH_ARP, (char *)out, 60);
}

/* next hop for dst: dst itself on our network, else the gateway; 0 if none */
static unsigned char *next_hop(unsigned char *dst)
{
	int i;

	for (i = 0; i < 4; i++)
		if ((dst[i] & cfgmsk[i]) != (myip[i] & cfgmsk[i]))
			break;
	if (i == 4)
		return dst;
	if ((cfggw[0] | cfggw[1] | cfggw[2] | cfggw[3]) == 0)
		return 0;
	return cfggw;
}

static void ping_arp_done(unsigned char *ip);
static void tcp_arp_done(void);

static void arp_input(int n)
{
	unsigned char *a = pkt + ETH_HDR;
	int i;

	if (n < ETH_HDR + 28 || GET16(a) != 1 || GET16(a + 2) != 0x0800 ||
	    a[4] != 6 || a[5] != 4 || !ipup())
		return;
	if (ours(a + 24) || arp_find(a + 14)) {
		arp_learn(a + 14, a + 8);       /* the sender, if it talks to us */
		ping_arp_done(a + 14);
		tcp_arp_done();
	}
	if (GET16(a + 6) != 1 || !ours(a + 24))
		return;                         /* only requests for us get answers */
	for (i = 0; i < 6; i++) {
		pkt[i] = a[8 + i];
		a[18 + i] = a[8 + i];
		a[8 + i] = mymac[i];
	}
	for (i = 0; i < 4; i++) {
		a[24 + i] = a[14 + i];
		a[14 + i] = myip[i];
	}
	PUT16(a + 6, 2);
	ethput(CH_ARP, (char *)pkt, 60);
}

static void ping_reply(unsigned char *ip, unsigned char *ic);

static void icmp_echo(unsigned char *ip, int hl, int tot)
{
	unsigned char *ic = ip + hl, t;
	int i, n;

	if (cksum(ic, tot - hl) != 0)
		return;
	if (ic[0] == 0) {               /* echo reply: one of our clients' pings */
		ping_reply(ip, ic);
		return;
	}
	if (ic[0] != 8)
		return;
	for (i = 0; i < 6; i++) {
		t = pkt[i]; pkt[i] = pkt[6 + i]; pkt[6 + i] = t;
	}
	for (i = 0; i < 4; i++) {
		t = ip[12 + i]; ip[12 + i] = ip[16 + i]; ip[16 + i] = t;
	}
	ip[8] = 64;
	PUT16(ip + 10, 0);
	PUT16(ip + 10, cksum(ip, hl));
	ic[0] = 0;
	PUT16(ic + 2, 0);
	PUT16(ic + 2, cksum(ic, tot - hl));
	n = ETH_HDR + tot;
	ethput(CH_IP, (char *)pkt, n < 60 ? 60 : n);
}

/* ---- DHCP client (RFC 2131): DISCOVER, OFFER, REQUEST, ACK; renew at T1 ---- */
#define DH_INIT   0
#define DH_SELECT 1             /* DISCOVER sent, waiting for an OFFER */
#define DH_REQ    2             /* REQUEST sent, waiting for the ACK */
#define DH_BOUND  3
#define DH_RENEW  4             /* unicast REQUEST to our server */
static int dhst, dhtry;
static unsigned long dhxid;
static unsigned char dhsrv[4], dhoffr[4], dhsmac[6];
static unsigned char bcip[4] = { 255, 255, 255, 255 };
static long dhsent, dhgot, dhleas, dht1;

static unsigned char *dhopt(unsigned char *o, int code, int len, unsigned char *v)
{
	*o++ = code;
	*o++ = len;
	memcpy(o, v, len);
	return o + len;
}

static unsigned long get32(unsigned char *p)
{
	return (unsigned long)GET16(p) << 16 | GET16(p + 2);
}

static void dhsend(int type)    /* 1 DISCOVER, 3 REQUEST */
{
	unsigned char *b = UDATA, *o, v[8];
	int n;

	memset(b, 0, 300);
	b[0] = 1; b[1] = 1; b[2] = 6;                   /* BOOTREQUEST, Ethernet */
	b[4] = dhxid >> 24; b[5] = dhxid >> 16; b[6] = dhxid >> 8; b[7] = dhxid;
	if (dhst == DH_RENEW)
		memcpy(b + 12, myip, 4);                /* ciaddr */
	else
		b[10] = 0x80;                           /* please broadcast the reply */
	memcpy(b + 28, mymac, 6);                       /* chaddr */
	b[236] = 99; b[237] = 130; b[238] = 83; b[239] = 99;
	o = b + 240;
	v[0] = type;
	o = dhopt(o, 53, 1, v);
	v[0] = 1;
	memcpy(v + 1, mymac, 6);
	o = dhopt(o, 61, 7, v);                         /* client identifier */
	if (type == 3 && dhst != DH_RENEW) {
		o = dhopt(o, 50, 4, dhoffr);            /* requested address */
		o = dhopt(o, 54, 4, dhsrv);             /* server identifier */
	}
	o = dhopt(o, 12, strlen(cfghst), (unsigned char *)cfghst);  /* host name */
	v[0] = 1; v[1] = 3; v[2] = 51; v[3] = 58;
	o = dhopt(o, 55, 4, v);                         /* mask, router, lease, T1 */
	*o++ = 255;
	n = o - b;
	if (n < 300)
		n = 300;
	if (dhst == DH_RENEW)
		udp_send(out, dhsmac, dhsrv, 67, 68, n);
	else
		udp_send(out, bcast, bcip, 67, 68, n);
	dhsent = time((long *)0);
}

static void dhinput(unsigned char *b, int n)
{
	unsigned char *o, *end, type = 0, srv[4], mask[4], gw[4];
	int hmask = 0, hgw = 0, hsrv = 0;
	long lease = 0, t1 = 0;

	if (n < 241 || b[0] != 2 || memcmp(b + 28, mymac, 6) != 0 || get32(b + 4) != dhxid ||
	    b[236] != 99 || b[237] != 130 || b[238] != 83 || b[239] != 99)
		return;
	for (o = b + 240, end = b + n; o < end && *o != 255; ) {
		if (*o == 0) {
			o++;
			continue;
		}
		if (o + 2 > end || o + 2 + o[1] > end)
			break;
		if (o[0] == 53 && o[1] == 1) type = o[2];
		if (o[0] == 54 && o[1] == 4) { memcpy(srv, o + 2, 4); hsrv = 1; }
		if (o[0] == 1 && o[1] == 4) { memcpy(mask, o + 2, 4); hmask = 1; }
		if (o[0] == 3 && o[1] >= 4) { memcpy(gw, o + 2, 4); hgw = 1; }
		if (o[0] == 51 && o[1] == 4) lease = get32(o + 2);
		if (o[0] == 58 && o[1] == 4) t1 = get32(o + 2);
		o += 2 + o[1];
	}
	if (!hsrv) {                    /* no server identifier (SLiRP): the sender */
		memcpy(srv, pkt + ETH_HDR + 12, 4);
		hsrv = 1;
	}
	if (dhst == DH_SELECT && type == 2 && hsrv) {           /* OFFER */
		memcpy(dhoffr, b + 16, 4);
		memcpy(dhsrv, srv, 4);
		memcpy(dhsmac, pkt + 6, 6);
		dhst = DH_REQ;
		dhtry = 0;
		dhsend(3);
	} else if ((dhst == DH_REQ || dhst == DH_RENEW) && type == 5) {   /* ACK */
		memcpy(myip, b + 16, 4);
		if (hmask) memcpy(cfgmsk, mask, 4);
		if (hgw) memcpy(cfggw, gw, 4);
		if (hsrv) memcpy(dhsrv, srv, 4);
		memcpy(dhsmac, pkt + 6, 6);
		dhleas = lease > 0 ? lease : 3600L;
		dht1 = t1 > 0 && t1 < dhleas ? t1 : dhleas / 2;
		dhgot = time((long *)0);
		if (dhst != DH_RENEW && attached)
			printf("tcpipd: DHCP: %d.%d.%d.%d mask %d.%d.%d.%d router %d.%d.%d.%d lease %ld s\n",
			       myip[0], myip[1], myip[2], myip[3], cfgmsk[0], cfgmsk[1], cfgmsk[2], cfgmsk[3],
			       cfggw[0], cfggw[1], cfggw[2], cfggw[3], dhleas);
		dhst = DH_BOUND;
	} else if ((dhst == DH_REQ || dhst == DH_RENEW) && type == 6) {   /* NAK */
		memset(myip, 0, 4);
		dhst = DH_INIT;
	}
}

static int dhtick()             /* run the DHCP timers; returns a sleep time */
{
	long now = time((long *)0);

	switch (dhst) {
	case DH_INIT:
		dhxid = (unsigned long)now ^ ((unsigned long)mymac[4] << 8 | mymac[5]) << 16;
		dhst = DH_SELECT;
		dhsend(1);
		return 2;
	case DH_SELECT:
		if (now - dhsent >= 4)
			dhsend(1);
		return 2;
	case DH_REQ:
		if (now - dhsent >= 4) {
			if (++dhtry > 4)
				dhst = DH_INIT;
			else
				dhsend(3);
		}
		return 2;
	case DH_BOUND:
		if (now - dhgot >= dht1) {
			dhst = DH_RENEW;
			dhxid++;
			dhsend(3);
			return 5;
		}
		return dht1 - (now - dhgot) < 30 ? (int)(dht1 - (now - dhgot)) + 1 : 30;
	case DH_RENEW:
		if (now - dhgot >= dhleas) {            /* lease gone: start again */
			memset(myip, 0, 4);
			dhst = DH_INIT;
		} else if (now - dhsent >= 10)
			dhsend(3);
		return 5;
	}
	return 30;
}

/* ---- ping service: requests from local programs ---- */
static void ping_answer(int job2, int status, unsigned char *from, unsigned seq, int ttl)
{
	memset(msgp, 0, 20);
	msgp[0] = TM_PINGR;
	msgp[1] = status;
	if (from)
		memcpy(msgp + 2, from, 4);
	PUT16(msgp + 6, seq);
	msgp[8] = ttl;
	msgsnd((char *)0, job2, (char *)msgp, (char *)msgdw, 0);
}

static void ping_send(struct pingq *q, unsigned char *mac)
{
	unsigned char *h = out + ETH_HDR, *ic = h + 20;
	int i, n = 8 + q->len;
	static unsigned ipid = 0x4000;

	for (i = 0; i < 6; i++) {
		out[i] = mac[i];
		out[6 + i] = mymac[i];
	}
	out[12] = 0x08; out[13] = 0x00;
	h[0] = 0x45; h[1] = 0;
	PUT16(h + 2, 20 + n);
	PUT16(h + 4, ++ipid);
	PUT16(h + 6, 0);
	h[8] = 64; h[9] = 1;
	PUT16(h + 10, 0);
	memcpy(h + 12, myip, 4);
	memcpy(h + 16, q->dst, 4);
	PUT16(h + 10, cksum(h, 20));
	ic[0] = 8; ic[1] = 0;
	PUT16(ic + 2, 0);
	PUT16(ic + 4, 0x5200 | q->job2 / 2);    /* identifier: "R" + client job */
	PUT16(ic + 6, q->seq);
	for (i = 0; i < (int)q->len; i++)
		ic[8 + i] = 'a' + i % 23;
	PUT16(ic + 2, cksum(ic, n));
	n += ETH_HDR + 20;
	ethput(CH_IP, (char *)out, n < 60 ? 60 : n);
	q->waiting = 0;
}

static void ping_request(int job2, unsigned char *p)
{
	struct pingq *q = 0;
	struct arpe *e;
	unsigned char *hop;
	int i;

	if (!ipup()) {
		ping_answer(job2, TS_DOWN, 0, GET16(p + 6), 0);
		return;
	}
	if ((hop = next_hop(p + 2)) == 0) {
		ping_answer(job2, TS_NOROUTE, 0, GET16(p + 6), 0);
		return;
	}
	for (i = 0; i < PING_N; i++)            /* a client's newer ping replaces its older */
		if (pq[i].job2 == job2 || (!q && !pq[i].job2))
			q = &pq[i];
	if (!q) {
		ping_answer(job2, TS_BUSY, 0, GET16(p + 6), 0);
		return;
	}
	q->job2 = job2;
	memcpy(q->dst, p + 2, 4);
	memcpy(q->hop, hop, 4);
	q->seq = GET16(p + 6);
	q->len = GET16(p + 8);
	if (q->len > 256)
		q->len = 256;
	q->since = time((long *)0);
	if ((e = arp_find(hop)) != 0)
		ping_send(q, e->mac);
	else {
		q->waiting = 1;
		arp_request(hop);
	}
}

static void ping_arp_done(unsigned char *ip)
{
	struct arpe *e = arp_find(ip);
	int i;

	for (i = 0; e && i < PING_N; i++)
		if (pq[i].job2 && pq[i].waiting && memcmp(pq[i].hop, ip, 4) == 0)
			ping_send(&pq[i], e->mac);
}

static void ping_reply(unsigned char *ip, unsigned char *ic)
{
	int i;
	unsigned id = GET16(ic + 4), seq = GET16(ic + 6);

	for (i = 0; i < PING_N; i++)
		if (pq[i].job2 && !pq[i].waiting && id == (0x5200 | pq[i].job2 / 2) &&
		    seq == pq[i].seq && memcmp(ip + 12, pq[i].dst, 4) == 0) {
			ping_answer(pq[i].job2, TS_OK, ip + 12, seq, ip[8]);
			pq[i].job2 = 0;
		}
}

static void ping_tick()                 /* give up on unanswered ARP, forget old pings */
{
	long now = time((long *)0);
	int i;

	for (i = 0; i < PING_N; i++) {
		if (!pq[i].job2)
			continue;
		if (pq[i].waiting && now - pq[i].since >= ARP_WAIT) {
			ping_answer(pq[i].job2, TS_NOARP, pq[i].hop, pq[i].seq, 0);
			pq[i].job2 = 0;
		} else if (now - pq[i].since >= 10)
			pq[i].job2 = 0;         /* the client has long stopped waiting */
	}
}

/* ---- TCP (RFC 793; SACK, RFC 2018) ----
 * Up to TCB_N connections, each tied to a pseudo keyboard: what the program
 * writes to KBn: is read here from PKn: and sent; what arrives is written to
 * PKn: and the program reads it from KBn:.
 *
 * Receiving: a RWIN-byte window. In-order data waits in rbuf[0..rlen) until
 * the PK takes it; a segment that arrives out of order is parked at its place
 * in the window (rbuf[rlen + (seq - rcv_nxt)]) and noted as a range; when the
 * gap fills, the parked ranges that now join on are taken in. ACKs report
 * the parked ranges as SACK blocks when the peer allowed SACK in its SYN.
 *
 * Sending: up to SWIN bytes buffered; segments of the peer's MSS go out while
 * the peer's window allows. On a timeout, or three duplicate ACKs, the first
 * unacknowledged stretch the peer has not SACKed is sent again, with back-off.
 */
#define TCB_N    4
#define RWIN     4096           /* receive window per connection */
#define SWIN     2048           /* send buffer per connection */
#define MSS_US   1460           /* the largest segment we take */
#define NOOO     4              /* parked out-of-order ranges */
#define T_FREE   0
#define T_LISTEN 1
#define T_ARP    2              /* active open waiting for the next hop's ARP */
#define T_SYNSNT 3
#define T_SYNRCV 4
#define T_ESTAB  5
#define T_FINW1  6
#define T_FINW2  7
#define T_CLOSEW 8
#define T_CLOSNG 9
#define T_LASTAK 10
#define T_TIMEW  11
#define TF_FIN 1
#define TF_SYN 2
#define TF_RST 4
#define TF_PSH 8
#define TF_ACK 16
#define RTO_MAX 8               /* seconds */
#define TRY_MAX 10

static int tcb_chan[TCB_N] = { 8, 9, 14, 15 };  /* PK channels (stdio keeps to low ones) */

static struct tcb {
	int state;
	int job2;                       /* owner: job number * 2 */
	int kb;                         /* KB number of the PK */
	int ready;                      /* owner has opened KBn: */
	int closereq;                   /* owner asked to close */
	int finsent, peerfin, eofsent;
	int finpend;                    /* the peer's FIN arrived ahead of data */
	int orphan;                     /* the owner is gone: reset and free */
	int sackok;                     /* both sides allow SACK */
	unsigned char rip[4], hop[4], rmac[6];
	unsigned lport, rport;
	unsigned long iss, snd_una, snd_nxt, rcv_nxt, finseq;
	unsigned snd_wnd, pmss;
	int slen;                       /* bytes in sbuf from snd_una: sent and unsent */
	int rlen;                       /* in-order bytes in rbuf not yet in the PK */
	int nooo;                       /* parked ranges [oos, ooe) */
	unsigned long oos[NOOO], ooe[NOOO];
	int npsk;                       /* the peer's SACK blocks */
	unsigned long pks[3], pke[3];
	int dupacks;
	int tries;
	long sent, since;
	int rto;
	unsigned sbufw[SWIN / 2], rbufw[RWIN / 2];
} tcb[TCB_N];
static unsigned next_lport = 1024;
static unsigned pkbufw[256];            /* PK reads: an even address for RSTS */

#define SBUF(t) ((unsigned char *)(t)->sbufw)
#define RBUF(t) ((unsigned char *)(t)->rbufw)

static unsigned long get32(unsigned char *p);

static void tcp_event(struct tcb *t, int ev)
{
	memset(msgp, 0, 20);
	msgp[0] = TM_TEVT;
	msgp[1] = ev;
	msgp[2] = t - tcb;
	if (msgsnd((char *)0, t->job2, (char *)msgp, (char *)msgdw, 0) == 5)
		t->orphan = 1;          /* ?Can't find: the program has ended */
}

static void tcp_conreply(int job2, int status, struct tcb *t)
{
	memset(msgp, 0, 20);
	msgp[0] = TM_TCONR;
	msgp[1] = status;
	if (t) {
		msgp[2] = t - tcb;
		msgp[3] = t->kb;
		memcpy(msgp + 4, t->rip, 4);
		PUT16(msgp + 8, t->rport);
	}
	msgsnd((char *)0, job2, (char *)msgp, (char *)msgdw, 0);
}

static void tcp_free(struct tcb *t)
{
	if (t->state != T_FREE)
		fcls(tcb_chan[t - tcb]);
	t->state = T_FREE;
}

static unsigned tcp_wnd(struct tcb *t)
{
	return RWIN - t->rlen;
}

/* send a segment: flags, our sequence number seq, data (may be 0 bytes) */
static void tcp_send(struct tcb *t, int flags, unsigned long seq, unsigned char *data, int dlen)
{
	unsigned char *h = out + ETH_HDR, *th = h + 20, *o;
	int i, hlen, n, nb;
	unsigned long s;
	static unsigned ipid = 0x6000;

	for (i = 0; i < 6; i++) {
		out[i] = t->rmac[i];
		out[6 + i] = mymac[i];
	}
	out[12] = 0x08; out[13] = 0x00;
	o = th + 20;                            /* options */
	if (flags & TF_SYN) {
		*o++ = 2; *o++ = 4;             /* MSS */
		PUT16(o, MSS_US); o += 2;
		*o++ = 1; *o++ = 1;             /* NOP NOP SACK-permitted */
		*o++ = 4; *o++ = 2;
	} else if (t->sackok && t->nooo > 0 && !(flags & TF_RST)) {
		nb = t->nooo < 3 ? t->nooo : 3;
		*o++ = 1; *o++ = 1;             /* NOP NOP SACK */
		*o++ = 5; *o++ = 2 + 8 * nb;
		for (i = 0; i < nb; i++) {
			PUT16(o, (unsigned)(t->oos[i] >> 16)); PUT16(o + 2, (unsigned)t->oos[i]);
			PUT16(o + 4, (unsigned)(t->ooe[i] >> 16)); PUT16(o + 6, (unsigned)t->ooe[i]);
			o += 8;
		}
	}
	hlen = o - th;
	n = hlen + dlen;
	h[0] = 0x45; h[1] = 0;
	PUT16(h + 2, 20 + n);
	PUT16(h + 4, ++ipid);
	PUT16(h + 6, 0x4000);                   /* don't fragment */
	h[8] = 64; h[9] = 6;
	PUT16(h + 10, 0);
	memcpy(h + 12, myip, 4);
	memcpy(h + 16, t->rip, 4);
	PUT16(h + 10, cksum(h, 20));
	PUT16(th, t->lport);
	PUT16(th + 2, t->rport);
	PUT16(th + 4, (unsigned)(seq >> 16));
	PUT16(th + 6, (unsigned)seq);
	PUT16(th + 8, (unsigned)(t->rcv_nxt >> 16));
	PUT16(th + 10, (unsigned)t->rcv_nxt);
	th[12] = (hlen / 4) << 4;
	th[13] = flags | (t->state == T_SYNSNT && (flags & TF_SYN) ? 0 : TF_ACK);
	PUT16(th + 14, tcp_wnd(t));
	PUT16(th + 16, 0);
	PUT16(th + 18, 0);
	if (dlen)
		memcpy(th + hlen, data, dlen);
	s = cksum_add(0L, myip, 4);
	s = cksum_add(s, t->rip, 4);
	s += 6;
	s += (unsigned)n;
	s = cksum_add(s, th, n);
	PUT16(th + 16, (unsigned)~s & 0xFFFF);
	n += ETH_HDR + 20;
	ethput(CH_IP, (char *)out, n < 60 ? 60 : n);
}

static void tcp_ack(struct tcb *t)
{
	tcp_send(t, 0, t->snd_nxt, (unsigned char *)0, 0);
}

static void tcp_rst(unsigned char *mac, unsigned char *ip, unsigned char *th, int dlen)
{
	struct tcb *x = &tcb[0];        /* borrow a TCB's fields, then put them back */
	struct tcb save;
	unsigned long seq, ack;
	int flags = th[13];

	if (flags & TF_RST)
		return;
	memcpy(&save, x, sizeof save - sizeof save.sbufw - sizeof save.rbufw);
	memcpy(x->rmac, mac, 6);
	memcpy(x->rip, ip, 4);
	x->lport = GET16(th + 2);
	x->rport = GET16(th);
	x->state = T_ESTAB;
	x->sackok = 0;
	x->rlen = RWIN;                         /* window 0 */
	seq = get32(th + 4);
	ack = get32(th + 8);
	if (flags & TF_ACK) {
		x->rcv_nxt = 0;
		tcp_send(x, TF_RST, ack, (unsigned char *)0, 0);
	} else {
		x->rcv_nxt = seq + dlen + (flags & TF_SYN ? 1 : 0) + (flags & TF_FIN ? 1 : 0);
		tcp_send(x, TF_RST | TF_ACK, 0L, (unsigned char *)0, 0);
	}
	memcpy(x, &save, sizeof save - sizeof save.sbufw - sizeof save.rbufw);
}

static struct tcb *tcp_new(int job2)    /* a free TCB with its PK open */
{
	int i, kb;
	struct tcb *t;

	for (i = 0; i < TCB_N; i++)
		if (tcb[i].state == T_FREE)
			break;
	if (i == TCB_N)
		return 0;
	t = &tcb[i];
	memset(t, 0, sizeof *t - sizeof t->sbufw - sizeof t->rbufw);
	if ((kb = dopn("PK:", tcb_chan[i], 0)) < 0)
		return 0;
	kbset(kb, 012, 0200);                   /* no XON/XOFF into the data */
	t->kb = kb;
	t->job2 = job2;
	t->rto = 1;
	t->snd_wnd = 536;
	t->pmss = 536;
	t->iss = (unsigned long)time((long *)0) << 8 ^ (unsigned long)i << 20;
	t->snd_una = t->snd_nxt = t->iss;
	return t;
}

static void tcp_syn(struct tcb *t)
{
	t->snd_nxt = t->iss + 1;
	tcp_send(t, TF_SYN, t->iss, (unsigned char *)0, 0);
	t->sent = time((long *)0);
}

static void tcp_connect(int job2, unsigned char *p)
{
	struct tcb *t;
	struct arpe *e;
	unsigned char *hop;

	if (!ipup()) { tcp_conreply(job2, TS_DOWN, 0); return; }
	if ((hop = next_hop(p + 2)) == 0) { tcp_conreply(job2, TS_NOROUTE, 0); return; }
	if ((t = tcp_new(job2)) == 0) { tcp_conreply(job2, TS_BUSY, 0); return; }
	memcpy(t->rip, p + 2, 4);
	memcpy(t->hop, hop, 4);
	t->rport = GET16(p + 6);
	t->lport = next_lport++;
	if (next_lport > 60000)
		next_lport = 1024;
	t->since = time((long *)0);
	if ((e = arp_find(hop)) != 0) {
		memcpy(t->rmac, e->mac, 6);
		t->state = T_SYNSNT;
		tcp_syn(t);
	} else {
		t->state = T_ARP;
		arp_request(hop);
		t->sent = time((long *)0);
	}
}

static void tcp_listen(int job2, unsigned char *p)
{
	struct tcb *t;
	int i;

	for (i = 0; i < TCB_N; i++)
		if (tcb[i].state == T_LISTEN && tcb[i].lport == GET16(p + 6)) {
			tcp_conreply(job2, TS_BUSY, 0);
			return;
		}
	if ((t = tcp_new(job2)) == 0) { tcp_conreply(job2, TS_BUSY, 0); return; }
	t->lport = GET16(p + 6);
	t->state = T_LISTEN;
}

static void tcp_arp_done(void)          /* active opens waiting for ARP */
{
	struct arpe *e;
	int i;

	for (i = 0; i < TCB_N; i++)
		if (tcb[i].state == T_ARP && (e = arp_find(tcb[i].hop)) != 0) {
			memcpy(tcb[i].rmac, e->mac, 6);
			tcb[i].state = T_SYNSNT;
			tcp_syn(&tcb[i]);
		}
}

/* options of an incoming segment: MSS and SACK-permitted on a SYN, SACK
 * blocks on an ACK */
static void tcp_options(struct tcb *t, unsigned char *o, int len, int syn)
{
	int k, l, i;

	if (!syn)
		t->npsk = 0;
	while (len > 0) {
		k = o[0];
		if (k == 0)
			break;
		if (k == 1) {
			o++; len--;
			continue;
		}
		if (len < 2 || (l = o[1]) < 2 || l > len)
			break;
		if (syn && k == 2 && l == 4) {
			t->pmss = GET16(o + 2);
			if (t->pmss > MSS_US)
				t->pmss = MSS_US;
			if (t->pmss < 64)
				t->pmss = 64;
		} else if (syn && k == 4 && l == 2)
			t->sackok = 1;
		else if (!syn && k == 5)
			for (i = 0; i < (l - 2) / 8 && i < 3; i++) {
				t->pks[i] = get32(o + 2 + 8 * i);
				t->pke[i] = get32(o + 6 + 8 * i);
				t->npsk = i + 1;
			}
		o += l; len -= l;
	}
}

/* take in [seq, seq + len) of data (already trimmed to the window) */
static void tcp_take(struct tcb *t, unsigned long seq, unsigned char *data, int len)
{
	int i, j, off;
	unsigned long end = seq + len;

	off = t->rlen + (int)(seq - t->rcv_nxt);
	memcpy(RBUF(t) + off, data, len);
	if (seq == t->rcv_nxt) {
		t->rlen += len;
		t->rcv_nxt = end;
		for (i = 0; i < t->nooo; ) {            /* parked data that now joins on */
			if ((long)(t->oos[i] - t->rcv_nxt) <= 0) {
				if ((long)(t->ooe[i] - t->rcv_nxt) > 0) {
					t->rlen += (int)(t->ooe[i] - t->rcv_nxt);
					t->rcv_nxt = t->ooe[i];
				}
				for (j = i; j < t->nooo - 1; j++) {
					t->oos[j] = t->oos[j + 1];
					t->ooe[j] = t->ooe[j + 1];
				}
				t->nooo--;
				i = 0;                  /* the new end may reach another */
			} else
				i++;
		}
		return;
	}
	for (i = 0; i < t->nooo; i++)           /* join an overlapping/adjoining range */
		if ((long)(seq - t->ooe[i]) <= 0 && (long)(end - t->oos[i]) >= 0) {
			if ((long)(seq - t->oos[i]) < 0) t->oos[i] = seq;
			if ((long)(end - t->ooe[i]) > 0) t->ooe[i] = end;
			for (j = 0; j < t->nooo; j++)   /* it may now touch another */
				if (j != i && (long)(t->oos[j] - t->ooe[i]) <= 0 &&
				    (long)(t->ooe[j] - t->oos[i]) >= 0) {
					if ((long)(t->oos[j] - t->oos[i]) < 0) t->oos[i] = t->oos[j];
					if ((long)(t->ooe[j] - t->ooe[i]) > 0) t->ooe[i] = t->ooe[j];
					t->oos[j] = t->oos[t->nooo - 1];
					t->ooe[j] = t->ooe[t->nooo - 1];
					t->nooo--;
					break;
				}
			return;
		}
	if (t->nooo < NOOO) {                   /* a new range, most recent first */
		for (j = t->nooo; j > 0; j--) {
			t->oos[j] = t->oos[j - 1];
			t->ooe[j] = t->ooe[j - 1];
		}
		t->oos[0] = seq;
		t->ooe[0] = end;
		t->nooo++;
	}       /* else: no room to note it; the peer sends it again */
}

static void tcp_peerfin(struct tcb *t)
{
	t->peerfin = 1;
	t->finpend = 0;
	t->rcv_nxt++;
	if (t->state == T_ESTAB)
		t->state = T_CLOSEW;
	else if (t->state == T_FINW1)
		t->state = T_CLOSNG;
	else if (t->state == T_FINW2) {
		t->state = T_TIMEW;
		t->since = time((long *)0);
	}
}

/* the first unacknowledged stretch the peer has not SACKed: offset in sbuf */
static int tcp_hole(struct tcb *t)
{
	unsigned long s = t->snd_una;
	int i, moved = 1;

	while (moved) {
		moved = 0;
		for (i = 0; i < t->npsk; i++)
			if ((long)(t->pks[i] - s) <= 0 && (long)(t->pke[i] - s) > 0) {
				s = t->pke[i];
				moved = 1;
			}
	}
	if ((long)(s - t->snd_nxt) >= 0)
		s = t->snd_una;
	return (int)(s - t->snd_una);
}

static void tcp_resend(struct tcb *t)
{
	int off, len, inflight = (int)(t->snd_nxt - t->snd_una);

	if (t->state == T_SYNSNT || t->state == T_SYNRCV) {
		tcp_send(t, TF_SYN, t->iss, (unsigned char *)0, 0);
		return;
	}
	if (t->finsent && inflight == 1 && t->slen == 0) {
		tcp_send(t, TF_FIN, t->finseq, (unsigned char *)0, 0);
		return;
	}
	if (t->slen == 0 || inflight <= 0)
		return;
	off = tcp_hole(t);
	len = inflight - off;
	if (len > t->slen - off)
		len = t->slen - off;
	if (len > (int)t->pmss)
		len = t->pmss;
	if (len > 0)
		tcp_send(t, TF_PSH, t->snd_una + off, SBUF(t) + off, len);
}

static void tcp_input(unsigned char *ip, int hl, int tot)
{
	unsigned char *th = ip + hl, *data;
	int doff, dlen, flags, i, n;
	unsigned long seq, ack, s, wend;
	struct tcb *t = 0;
	unsigned sport, dport, wnd;

	if (tot - hl < 20)
		return;
	s = cksum_add(0L, ip + 12, 4);
	s = cksum_add(s, ip + 16, 4);
	s += 6;
	s += (unsigned)(tot - hl);
	if ((unsigned)~cksum_add(s, th, tot - hl) & 0xFFFF)
		return;
	doff = (th[12] >> 4) * 4;
	if (doff < 20 || doff > tot - hl)
		return;
	data = th + doff;
	dlen = tot - hl - doff;
	flags = th[13];
	sport = GET16(th);
	dport = GET16(th + 2);
	seq = get32(th + 4);
	ack = get32(th + 8);
	wnd = GET16(th + 14);
	for (i = 0; i < TCB_N; i++)
		if (tcb[i].state > T_LISTEN && tcb[i].lport == dport && tcb[i].rport == sport &&
		    memcmp(tcb[i].rip, ip + 12, 4) == 0)
			t = &tcb[i];
	if (!t)
		for (i = 0; i < TCB_N; i++)
			if (tcb[i].state == T_LISTEN && tcb[i].lport == dport)
				t = &tcb[i];
	if (!t) {
		tcp_rst(pkt + 6, ip + 12, th, dlen);
		return;
	}
	if (t->state == T_LISTEN) {
		if (flags & TF_RST)
			return;
		if (!(flags & TF_SYN) || (flags & TF_ACK)) {
			tcp_rst(pkt + 6, ip + 12, th, dlen);
			return;
		}
		memcpy(t->rip, ip + 12, 4);
		memcpy(t->rmac, pkt + 6, 6);
		arp_learn(ip + 12, pkt + 6);
		t->rport = sport;
		t->rcv_nxt = seq + 1;
		t->snd_wnd = wnd;
		tcp_options(t, th + 20, doff - 20, 1);
		t->state = T_SYNRCV;
		t->since = time((long *)0);
		tcp_syn(t);
		return;
	}
	if (t->state == T_SYNSNT) {
		if ((flags & TF_ACK) && ack != t->iss + 1)
			return;
		if (flags & TF_RST) {
			if (flags & TF_ACK) {
				tcp_conreply(t->job2, TS_REFUSED, t);
				tcp_free(t);
			}
			return;
		}
		if ((flags & TF_SYN) && (flags & TF_ACK)) {
			t->rcv_nxt = seq + 1;
			t->snd_una = ack;
			t->snd_wnd = wnd;
			tcp_options(t, th + 20, doff - 20, 1);
			t->state = T_ESTAB;
			t->tries = 0;
			t->rto = 1;
			tcp_ack(t);
			tcp_conreply(t->job2, TS_OK, t);
		}
		return;
	}
	if (flags & TF_RST) {
		if (t->state != T_TIMEW)
			tcp_event(t, TE_RESET);
		tcp_free(t);
		return;
	}
	if (flags & TF_ACK) {
		tcp_options(t, th + 20, doff - 20, 0);
		if ((long)(ack - t->snd_una) > 0 && (long)(ack - t->snd_nxt) <= 0) {
			n = (int)(ack - t->snd_una);
			if (t->state == T_SYNRCV) {
				n--;                            /* our SYN */
				t->state = T_ESTAB;
				tcp_conreply(t->job2, TS_OK, t);
			}
			if (t->finsent && ack == t->snd_nxt)
				n--;                            /* our FIN */
			if (n > t->slen)
				n = t->slen;
			if (n > 0) {
				memmove(SBUF(t), SBUF(t) + n, t->slen - n);
				t->slen -= n;
			}
			t->snd_una = ack;
			t->tries = 0;
			t->rto = 1;
			t->dupacks = 0;
			t->sent = time((long *)0);      /* restart the timer */
			if (t->finsent && ack == t->snd_nxt) {  /* our FIN is acked */
				if (t->state == T_FINW1)
					t->state = T_FINW2;
				else if (t->state == T_CLOSNG) {
					t->state = T_TIMEW;
					t->since = time((long *)0);
				} else if (t->state == T_LASTAK) {
					if (!t->eofsent)
						tcp_event(t, TE_EOF);
					tcp_event(t, TE_CLOSED);
					tcp_free(t);
					return;
				}
			}
		} else if (ack == t->snd_una && dlen == 0 && !(flags & (TF_SYN | TF_FIN)) &&
			   t->snd_una != t->snd_nxt && wnd == t->snd_wnd) {
			if (++t->dupacks == 3) {                /* fast retransmit */
				tcp_resend(t);
				t->sent = time((long *)0);
			}
		}
		t->snd_wnd = wnd;
	}
	/* data: trim to what is new and fits the window, then take it in */
	if (dlen > 0 && !t->peerfin) {
		if ((long)(seq - t->rcv_nxt) < 0) {            /* starts with old data */
			n = (int)(t->rcv_nxt - seq);
			if (n >= dlen)
				dlen = 0;
			else {
				data += n; dlen -= n; seq = t->rcv_nxt;
			}
		}
		wend = t->rcv_nxt + tcp_wnd(t);
		if (dlen > 0 && (long)(seq - wend) < 0) {
			if ((long)(seq + dlen - wend) > 0)
				dlen = (int)(wend - seq);
			tcp_take(t, seq, data, dlen);
		}
	}
	if ((flags & TF_FIN) && !t->peerfin) {
		t->finpend = 1;
		t->finseq = get32(th + 4) + (tot - hl - doff);
	}
	if (t->finpend && t->rcv_nxt == t->finseq)
		tcp_peerfin(t);
	if (tot - hl - doff > 0 || (flags & TF_FIN))
		tcp_ack(t);
}

static void tcp_close_req(int job2, unsigned char *p, int abort)
{
	struct tcb *t;

	if (p[2] >= TCB_N || (t = &tcb[p[2]])->state == T_FREE || t->job2 != job2)
		return;
	if (abort || t->state <= T_SYNSNT) {
		if (t->state > T_LISTEN && t->state != T_ARP)
			tcp_send(t, TF_RST, t->snd_nxt, (unsigned char *)0, 0);
		tcp_free(t);
		return;
	}
	t->closereq = 1;
}

static int tcp_tick()                   /* move data, timers; 1 if anything happened */
{
	int i, n, busy = 0, inflight, unsent, len, wasfull;
	struct tcb *t;
	long now = time((long *)0);

	for (i = 0; i < TCB_N; i++) {
		t = &tcb[i];
		if (t->state == T_FREE)
			continue;
		if (t->orphan) {
			if (t->state > T_LISTEN && t->state != T_ARP && t->state != T_TIMEW)
				tcp_send(t, TF_RST, t->snd_nxt, (unsigned char *)0, 0);
			tcp_free(t);
			continue;
		}
		if (t->state == T_LISTEN)
			continue;
		if (t->state == T_ARP) {
			if (now - t->sent >= 1) {
				if (++t->tries > 3) {
					tcp_conreply(t->job2, TS_NOARP, t);
					tcp_free(t);
				} else {
					arp_request(t->hop);
					t->sent = now;
				}
			}
			continue;
		}
		/* what arrived: into the PK as the program makes room */
		if (t->ready && t->rlen > 0) {
			n = dwr(tcb_chan[i], (char *)RBUF(t), t->rlen, 1);
			if (n > 0) {
				int keep = t->rlen;     /* move in-order and parked data down */
				int j;
				for (j = 0; j < t->nooo; j++)
					if (t->rlen + (int)(t->ooe[j] - t->rcv_nxt) > keep)
						keep = t->rlen + (int)(t->ooe[j] - t->rcv_nxt);
				wasfull = tcp_wnd(t) < (unsigned)t->pmss;
				memmove(RBUF(t), RBUF(t) + n, keep - n);
				t->rlen -= n;
				busy = 1;
				if (wasfull && tcp_wnd(t) >= (unsigned)t->pmss)
					tcp_ack(t);             /* window update */
			}
		}
		if (t->ready && t->peerfin && t->rlen == 0 && !t->eofsent) {
			t->eofsent = 1;
			tcp_event(t, TE_EOF);
		}
		if (t->state == T_TIMEW) {
			if (now - t->since >= 2 && t->rlen == 0) {
				if (t->peerfin && !t->eofsent)
					tcp_event(t, TE_EOF);
				tcp_event(t, TE_CLOSED);
				tcp_free(t);
			}
			continue;
		}
		/* what the program wrote: from the PK into sbuf, then segments */
		if (t->ready && !t->finsent && (t->state == T_ESTAB || t->state == T_CLOSEW)) {
			if (t->slen < SWIN) {
				len = SWIN - t->slen < (int)sizeof pkbufw ? SWIN - t->slen : (int)sizeof pkbufw;
				n = drd(tcb_chan[i], (char *)pkbufw, len, 0);
				if (n > 0) {
					memcpy(SBUF(t) + t->slen, pkbufw, n);
					t->slen += n;
					busy = 1;
				} else if (t->closereq && t->slen == 0) {      /* all sent and acked: FIN */
					t->finsent = 1;
					t->finseq = t->snd_nxt;
					tcp_send(t, TF_FIN, t->snd_nxt, (unsigned char *)0, 0);
					t->snd_nxt++;
					t->sent = now;
					t->state = t->state == T_ESTAB ? T_FINW1 : T_LASTAK;
					busy = 1;
				}
			}
			for (;;) {
				inflight = (int)(t->snd_nxt - t->snd_una);
				unsent = t->slen - inflight;
				if (unsent <= 0 || inflight >= (int)t->snd_wnd)
					break;
				len = unsent;
				if (len > (int)t->pmss)
					len = t->pmss;
				if (len > (int)t->snd_wnd - inflight)
					len = t->snd_wnd - inflight;
				if (inflight == 0)
					t->sent = now;          /* the timer starts with the first */
				tcp_send(t, TF_PSH, t->snd_nxt, SBUF(t) + inflight, len);
				t->snd_nxt += len;
				busy = 1;
			}
		}
		/* retransmit: SYN, data or FIN not yet acknowledged */
		if ((t->state == T_SYNSNT || t->state == T_SYNRCV || t->snd_una != t->snd_nxt) &&
		    now - t->sent >= t->rto) {
			if (++t->tries > TRY_MAX) {
				if (t->state == T_SYNSNT)
					tcp_conreply(t->job2, TS_TIMEOUT, t);
				else
					tcp_event(t, TE_RESET);
				tcp_send(t, TF_RST, t->snd_nxt, (unsigned char *)0, 0);
				tcp_free(t);
				continue;
			}
			tcp_resend(t);
			t->sent = now;
			if (t->rto < RTO_MAX)
				t->rto *= 2;
		}
	}
	return busy;
}

static int tcp_active()                 /* anything that needs a short sleep */
{
	int i;

	for (i = 0; i < TCB_N; i++)
		if (tcb[i].state > T_LISTEN)
			return 1;
	return 0;
}

static int msg_input()                  /* serve queued requests; 1 if any */
{
	int n, job2, any = 0;

	while ((n = msgrcv((char *)msgp, (char *)msgdw, sizeof msgdw, &job2)) >= 0 || n == -1) {
		any = 1;
		if (n < 0)
			continue;               /* not a data message */
		if (msgp[0] == TM_PING)
			ping_request(job2, msgp);
		else if (msgp[0] == TM_TCON)
			tcp_connect(job2, msgp);
		else if (msgp[0] == TM_TLSN)
			tcp_listen(job2, msgp);
		else if (msgp[0] == TM_TGO && msgp[2] < TCB_N && tcb[msgp[2]].job2 == job2)
			tcb[msgp[2]].ready = 1;
		else if (msgp[0] == TM_TCLS)
			tcp_close_req(job2, msgp, 0);
		else if (msgp[0] == TM_TABT)
			tcp_close_req(job2, msgp, 1);
	}
	return any;
}

static void ip_input(int n)
{
	unsigned char *ip = pkt + ETH_HDR, *u;
	int hl, tot, ulen;
	unsigned sport, dport, c;

	if (n < ETH_HDR + 20 || (ip[0] >> 4) != 4)
		return;
	hl = (ip[0] & 15) * 4;
	tot = GET16(ip + 2);
	if (hl < 20 || tot < hl + 8 || ETH_HDR + tot > n || cksum(ip, hl) != 0)
		return;
	if (!(ipup() && ours(ip + 16))) {
		/* not (yet) for our address: only DHCP replies, to us or broadcast */
		if (!cfgdhc || ip[9] != 17 || GET16(ip + hl + 2) != 68)
			return;
	}
	if (GET16(ip + 6) & 0x3FFF)
		return;                 /* fragments: not supported */
	if (ip[9] == 1) {
		icmp_echo(ip, hl, tot);
		return;
	}
	if (ip[9] == 6) {
		if (ipup() && ours(ip + 16))
			tcp_input(ip, hl, tot);
		return;
	}
	if (ip[9] != 17)
		return;
	u = ip + hl;
	ulen = GET16(u + 4);
	if (ulen < 8 || ulen > tot - hl)
		return;
	/* a stored checksum of 0 means none; otherwise the datagram, checksum
	 * included, must sum to all ones (udp_cksum then returns 0xFFFF) */
	if ((c = GET16(u + 6)) != 0 && udp_cksum(ip + 12, ip + 16, u, ulen) != 0xFFFF)
		return;
	sport = GET16(u);
	dport = GET16(u + 2);
	if (ulen < 12)
		return;
	if (dport == 68) {
		if (cfgdhc && sport == 67)
			dhinput(u + 8, ulen - 8);
		return;
	}
	if (!cfgtft)
		return;                 /* TFTP NO: nothing else listens on UDP */
	if (dport == TFTP_PORT) {
		unsigned op = GET16(u + 8);
		if (op == 1 || op == 2)
			tftp_request(pkt + 6, ip + 12, sport, u + 8, ulen - 8);
	} else if (xf.active && dport == xf.sport && sport == xf.cport && memcmp(ip + 12, xf.ip, 4) == 0) {
		tftp_transfer(u + 8, ulen - 8);
	} else if (!xf.active || dport != xf.sport) {
		unsigned op = GET16(u + 8);
		if (op != 5)
			tftp_error(pkt + 6, ip + 12, sport, dport, 5, "unknown transfer ID");
	}
}

int main()
{
	int n, e, busy;

	printf("%s", cpyrt);
	if (!cfgld()) {
		printf("tcpipd: %s\n", cfgwhy);
		return 1;
	}
	if (!cfgini)
		printf("tcpipd: cannot read TCPIP$:TCPIP.INI; using the defaults\n");
	if ((e = ethopn(CH_IP, cfgunt, PT_IP, 8)) != 0 ||
	    (e = ethopn(CH_ARP, cfgunt, PT_ARP, 4)) != 0 ||
	    (e = ethmul(CH_ARP, (char *)bcast, 1)) != 0 ||
	    (cfgdhc && (e = ethmul(CH_IP, (char *)bcast, 1)) != 0)) {
		printf("tcpipd: cannot open the Ethernet portals, error %d\n", e);
		return 1;
	}
	msgrem();                       /* in case an earlier run left one */
	if ((e = msgdcl(TM_NAME, 16)) != 0)
		printf("tcpipd: cannot declare receiver %s, error %d: no ping service\n", TM_NAME, e);
	if (cfgdhc)
		printf("tcpipd: address by DHCP");
	else
		printf("tcpipd: %d.%d.%d.%d", myip[0], myip[1], myip[2], myip[3]);
	printf(" on XE%d: %02X-%02X-%02X-%02X-%02X-%02X", cfgunt,
	       mymac[0], mymac[1], mymac[2], mymac[3], mymac[4], mymac[5]);
	printf(cfgtft ? ", TFTP files in FTP$:\n" : ", TFTP off\n");
	if (cfgdet) {
		if ((e = ethdet()) != 0)
			printf("tcpipd: cannot detach, error %d; running attached\n", e);
		else
			attached = 0;
	}
	for (;;) {
		int nap = 30;

		busy = 0;
		while ((n = ethget(CH_ARP, (char *)pkt, FRAME_MAX, 0)) > 0) {
			arp_input(n);
			busy = 1;
		}
		while ((n = ethget(CH_IP, (char *)pkt, FRAME_MAX, 0)) > 0) {
			ip_input(n);
			busy = 1;
		}
		if (msg_input())
			busy = 1;
		ping_tick();
		if (tcp_tick())
			busy = 1;
		if (xf.active && xf.done && time((long *)0) - xf.sent >= 2 * RETRY_SEC) {
			xf_end();               /* finished lingering after a write */
		} else if (xf.active && !xf.done && time((long *)0) - xf.sent >= RETRY_SEC) {
			if (++xf.tries > MAX_TRY)
				xf_end();               /* client vanished */
			else
				xf_send();
			busy = 1;
		}
		if (cfgdhc)
			nap = dhtick();
		if (xf.active)
			nap = 1;
		for (n = 0; n < PING_N; n++)
			if (pq[n].job2)
				nap = 1;
		if (tcp_active())
			nap = 1;
		if (!busy)
			ethslp(nap);
	}
}
