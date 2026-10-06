/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* tftpd.c - TFTP server for RSTS/E (RFC 1350), with ARP and ping.
 *
 * One job, two Ethernet portals (IP and ARP). The job polls both without
 * stalling and sleeps when there is nothing to do; a frame for either portal
 * ends the sleep at once (see netd.c), and the sleep doubles as the
 * retransmit timer during a transfer.
 *
 * Files live only in FTP$: (a system logical for one account). Names are
 * upper-cased; anything with a device, account or directory is refused.
 * One transfer at a time; a second client gets "busy". netascii is sent as
 * stored: RSTS text files already end their lines with CR LF.
 */
#include <stdio.h>
#include <time.h>
#include <string.h>
#include "netcfg.h"

#define CH_IP   12
#define CH_ARP  13
#define TFTP_PORT 69
#define SEG     512
#define RETRY_SEC 2
#define MAX_TRY 5

#define mymac cfgmac             /* from netcfg.c */
#define myip  cfgip
static unsigned bcastw[3] = { 0xFFFF, 0xFFFF, 0xFFFF };
#define bcast ((unsigned char *)bcastw)
/* kept in the task image: who wrote it and on what terms */
static char cpyrt[] = "RSTS/E TCP/IP V0.1  Copyright (c) 2026 Faye Salwin\n"
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
	FILE *f;
	unsigned block;                 /* last block sent (RRQ) or acked (WRQ) */
	int len;                        /* bytes in xout[] for a retransmit */
	int last;                       /* RRQ: last block was short */
	int tries;
	long sent;                      /* time of the last send */
	long bytes;
} xf;
static unsigned next_port = 1024;
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
		printf("tftpd: send to port %u failed, error %d\n", dport, -i);
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
	xf.f = 0;
	xf.active = 0;
	xf.done = 0;
}

static void rrq_next()                  /* read and send the next data block */
{
	int n = fread(TDATA + 4, 1, SEG, xf.f);

	if (n < 0)
		n = 0;
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

static void tftp_request(unsigned char *mac, unsigned char *ip, unsigned cport,
			 unsigned char *t, int tlen)
{
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
	xf.f = fopen(fn, op == 1 ? "rb" : "wb");
	if (!xf.f) {
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
		}
	}
}

static void arp_input(int n)
{
	unsigned char *a = pkt + ETH_HDR;
	int i;

	if (n < ETH_HDR + 28 || GET16(a) != 1 || GET16(a + 2) != 0x0800 ||
	    a[4] != 6 || a[5] != 4 || GET16(a + 6) != 1 || !ipup() || !ours(a + 24))
		return;
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

static void icmp_echo(unsigned char *ip, int hl, int tot)
{
	unsigned char *ic = ip + hl, t;
	int i, n;

	if (ic[0] != 8 || cksum(ic, tot - hl) != 0)
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
			printf("tftpd: DHCP: %d.%d.%d.%d mask %d.%d.%d.%d router %d.%d.%d.%d lease %ld s\n",
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
		printf("tftpd: %s\n", cfgwhy);
		return 1;
	}
	if (!cfgini)
		printf("tftpd: cannot read TCPIP$:TCPIP.INI; using the defaults\n");
	if ((e = ethopn(CH_IP, cfgunt, PT_IP, 8)) != 0 ||
	    (e = ethopn(CH_ARP, cfgunt, PT_ARP, 4)) != 0 ||
	    (e = ethmul(CH_ARP, (char *)bcast, 1)) != 0 ||
	    (cfgdhc && (e = ethmul(CH_IP, (char *)bcast, 1)) != 0)) {
		printf("tftpd: cannot open the Ethernet portals, error %d\n", e);
		return 1;
	}
	if (cfgdhc)
		printf("tftpd: address by DHCP");
	else
		printf("tftpd: %d.%d.%d.%d", myip[0], myip[1], myip[2], myip[3]);
	printf(" on XE%d: %02X-%02X-%02X-%02X-%02X-%02X, files in FTP$:\n", cfgunt,
	       mymac[0], mymac[1], mymac[2], mymac[3], mymac[4], mymac[5]);
	if (cfgdet) {
		if ((e = ethdet()) != 0)
			printf("tftpd: cannot detach, error %d; running attached\n", e);
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
		if (!busy)
			ethslp(nap);
	}
}
