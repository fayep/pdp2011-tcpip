/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* resolv.c - gethostbyname for RSTS/E programs: a DNS stub resolver
 * (RFC 1035) on the socket library.
 *
 * The name servers and domain come from TCPIPD (DHCP, or DNS and DOMAIN in
 * TCPIP.INI). A name without a dot is tried with the domain first; a name
 * ending in a dot is taken as complete. Each query asks for A records with
 * recursion, waits 2 seconds, and is tried 3 times, alternating between the
 * servers. CNAMEs in the answer are followed for the canonical name.
 */
#include <stdio.h>
#include <string.h>
#include "netcfg.h"
#include "sock.h"

#define QWAIT  2                /* seconds per try */
#define QTRIES 3
#define MAXADR 8

int h_errno;

static struct hostent he;
static char hname[256];
static char *alias0[1];
static char *alist[MAXADR + 1];
static unsigned long addrs[MAXADR];
static unsigned qw[160], rw[(UDP_MAX + 1) / 2];  /* even: RSTS buffers */
#define qb ((unsigned char *)qw)
#define rb ((unsigned char *)rw)

static int got(unsigned long *a, int n, char *name)
{
	int i;

	strncpy(hname, name, sizeof hname - 1);
	for (i = 0; i < n; i++) {
		addrs[i] = a[i];
		alist[i] = (char *)&addrs[i];
	}
	alist[n] = 0;
	alias0[0] = 0;
	he.h_name = hname;
	he.h_aliases = alias0;
	he.h_addrtype = AF_INET;
	he.h_length = 4;
	he.h_addr_list = alist;
	return 1;
}

/* a name in a reply at p, into out (dotted); bytes it takes at p, or -1 */
static int dname(unsigned char *msg, int len, unsigned char *p, char *out, int olen)
{
	int used = -1, hops = 0, n = 0, l;
	unsigned char *q = p;

	for (;;) {
		if (q < msg || q >= msg + len)
			return -1;
		l = *q;
		if ((l & 0xC0) == 0xC0) {               /* a pointer */
			if (q + 1 >= msg + len || ++hops > 20)
				return -1;
			if (used < 0)
				used = q + 2 - p;
			q = msg + ((l & 0x3F) << 8 | q[1]);
			continue;
		}
		if (l == 0)
			break;
		if (q + 1 + l > msg + len || n + l + 2 > olen)
			return -1;
		if (n)
			out[n++] = '.';
		memcpy(out + n, q + 1, l);
		n += l;
		q += 1 + l;
	}
	out[n] = 0;
	return used >= 0 ? used : q + 1 - p;
}

/* one name, as given: 1 found, 0 with h_errno set */
static int query(int s, struct soinf *inf, char *name)
{
	struct sockaddr_in ns, from;
	unsigned char *o;
	char *c, *dot, cname[256], rname[256];
	int n, l, try, i, an, alen, k, nadr;
	unsigned id, type, rdlen;
	unsigned long a[MAXADR];
	int w[3];

	if (strlen(name) > 250) {
		h_errno = HOST_NOT_FOUND;
		return 0;
	}
	tickd(w);
	id = (unsigned)(w[0] * 61 + w[1] * 7 + w[2]) ^ 0x5A5A;
	memset(qb, 0, 12);
	PUT16(qb, id);
	qb[2] = 0x01;                           /* recursion desired */
	qb[5] = 1;                              /* one question */
	o = qb + 12;
	for (c = name; *c; c = *dot ? dot + 1 : dot) {   /* labels */
		dot = strchr(c, '.');
		if (!dot)
			dot = c + strlen(c);
		l = dot - c;
		if (l < 1 || l > 63) {
			h_errno = HOST_NOT_FOUND;
			return 0;
		}
		*o++ = l;
		memcpy(o, c, l);
		o += l;
	}
	*o++ = 0;
	PUT16(o, 1);                            /* A */
	PUT16(o + 2, 1);                        /* IN */
	o += 4;
	h_errno = TRY_AGAIN;
	for (try = 0; try < QTRIES; try++) {
		i = try % 2 && inf->dns[1][0] ? 1 : 0;
		memset(&ns, 0, sizeof ns);
		ns.sin_family = AF_INET;
		ns.sin_port = htons(53);
		memcpy(&ns.sin_addr, inf->dns[i], 4);
		if (sendto(s, (char *)qb, o - qb, 0, (struct sockaddr *)&ns, sizeof ns) < 0) {
			h_errno = NO_RECOVERY;
			return 0;
		}
		for (;;) {                      /* the reply to this query */
			alen = sizeof from;
			n = recvfrom(s, (char *)rb, UDP_MAX, 0, (struct sockaddr *)&from, &alen);
			if (n < 0)
				break;          /* timed out: try again */
			if (n >= 12 && GET16(rb) == id && (rb[2] & 0x80) && ntohs(from.sin_port) == 53)
				goto reply;
		}
	}
	return 0;
reply:
	switch (rb[3] & 0x0F) {
	case 0:
		break;
	case 3:                                 /* no such name */
		h_errno = HOST_NOT_FOUND;
		return 0;
	default:
		h_errno = NO_RECOVERY;
		return 0;
	}
	strcpy(cname, name);
	o = rb + 12;
	for (i = GET16(rb + 4); i > 0; i--) {   /* skip the question */
		if ((k = dname(rb, n, o, rname, sizeof rname)) < 0)
			goto bad;
		o += k + 4;
	}
	nadr = 0;
	for (an = GET16(rb + 6); an > 0; an--) {
		if ((k = dname(rb, n, o, rname, sizeof rname)) < 0 || o + k + 10 > rb + n)
			goto bad;
		o += k;
		type = GET16(o);
		rdlen = GET16(o + 8);
		o += 10;
		if (o + rdlen > rb + n)
			goto bad;
		if (type == 5 && dname(rb, n, o, rname, sizeof rname) > 0)
			strcpy(cname, rname);           /* an alias: the real name */
		else if (type == 1 && rdlen == 4 && nadr < MAXADR)
			memcpy(&a[nadr++], o, 4);
		o += rdlen;
	}
	if (!nadr) {
		h_errno = NO_DATA;
		return 0;
	}
	return got(a, nadr, cname);
bad:
	h_errno = NO_RECOVERY;
	return 0;
}

struct hostent *gethostbyname(char *name)
{
	struct soinf inf;
	unsigned long a;
	char full[256];
	int s, ok = 0, l;

	if ((a = inet_addr(name)) != INADDR_NONE) {
		got(&a, 1, name);
		return &he;
	}
	if (soinfo(&inf) < 0 || !inf.dns[0][0]) {
		h_errno = NO_RECOVERY;
		return 0;
	}
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		h_errno = NO_RECOVERY;
		return 0;
	}
	sotmo(s, QWAIT);
	l = strlen(name);
	if (l > 0 && name[l - 1] == '.') {              /* complete as given */
		strncpy(full, name, sizeof full - 1);
		full[sizeof full - 1] = 0;
		full[l - 1] = 0;
		ok = query(s, &inf, full);
	} else {
		if (!strchr(name, '.') && inf.domain[0] && l + strlen(inf.domain) < 250) {
			sprintf(full, "%s.%s", name, inf.domain);
			ok = query(s, &inf, full);
		}
		if (!ok && h_errno != TRY_AGAIN)
			ok = query(s, &inf, name);
	}
	closesocket(s);
	return ok ? &he : 0;
}

char *hstrerror(int e)
{
	switch (e) {
	case HOST_NOT_FOUND: return "no such host";
	case TRY_AGAIN:      return "no answer from the name server";
	case NO_RECOVERY:    return "no name server, or a bad reply";
	case NO_DATA:        return "the name has no address";
	}
	return "name lookup failed";
}
