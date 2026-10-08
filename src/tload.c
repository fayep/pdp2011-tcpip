/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* tload.c - TLOAD and TDIR: the MiSTer tape library.
 *
 *	TLOAD name              put tape name (.TAP or .TPC) on MT0:
 *	TLOAD                   show the tape on MT0:
 *	TLOAD /UNLOAD           take the tape off MT0:
 *	TDIR [pattern]          list the library (* matches anything)
 *
 * The library is the PDP2011 core's directory on the MiSTer
 * (games/PDP2011). Requests go to MiSTer_pdp2011 as Ethernet frames of
 * type 88-B5 on an XE portal; it answers them itself, they never reach the
 * network (Main support/pdp2011/tapelib.h has the format). The drive goes
 * back to the load point with the new tape; MOUNT MT0: as usual after.
 * A tape in use (mounted, allocated or assigned by any job, this one too)
 * is not swapped: DISMOUNT, DEALLOCATE or DEASSIGN it first. Needs the XU
 * in the core and Host network not Off.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "netcfg.h"

#define CH_XE 11
#define CH_MT 10
#define PT_TLIB 0xB588          /* 88-B5 as the PDP-11 word */
#define TRIES 3
#define WAIT 2                  /* seconds per try */

static unsigned fw[760], rw[760];       /* word arrays: XE buffers must be even */
#define f ((unsigned char *)fw)
#define r ((unsigned char *)rw)
static char ccline[260];               /* room for qualsp's spaces */
static int seq;

static int lower(int c)
{
	return c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c;
}

static int get16(unsigned char *p)
{
	return (p[0] << 8) | p[1];
}

/* one request; the reply's data length, or -1 with no answer */
static int ask(int op, char *data, int dlen)
{
	static unsigned char lib[6] = { 0x02, 0x50, 0x44, 0x50, 0x54, 0x4C };
	int t, n, w;

	memset(f, 0, 60);
	memcpy(f, lib, 6);
	memcpy(f + 14, "TLIB", 4);
	f[18] = op;
	seq++;
	f[20] = seq >> 8; f[21] = seq;
	f[22] = dlen >> 8; f[23] = dlen;
	memcpy(f + 24, data, dlen);
	for (t = 0; t < TRIES; t++) {
		while (ethget(CH_XE, (char *)r, 1514, 0) > 0)
			;                       /* stale answers */
		if ((n = ethput(CH_XE, (char *)f, 24 + dlen < 60 ? 60 : 24 + dlen)) != 0) {
			printf("?TLOAD: cannot send (error %d)\n", -n);
			return -1;
		}
		for (w = 0; w <= WAIT; w++) {
			while ((n = ethget(CH_XE, (char *)r, 1514, 0)) > 0)
				if (n >= 24 && !memcmp(r + 14, "TLIB", 4) && r[18] == (op | 0x80) &&
				    get16(r + 20) == (seq & 0xFFFF))
					return get16(r + 22);
			ethslp(1);
		}
	}
	return -1;
}

static int fail(int st)
{
	switch (st) {
	case 1: printf("?TLOAD: no such tape in the library (TDIR lists them)\n"); break;
	case 2: printf("?TLOAD: not a tape name (NAME.TAP or NAME.TPC)\n"); break;
	case 3: printf("?TLOAD: the tape would not mount\n"); break;
	case 5: printf("MT0: has no tape\n"); return 0;
	default: printf("?TLOAD: library error %d\n", st);
	}
	return 1;
}

static void show(char *what)
{
	char *n = (char *)r + 24;
	printf("%s %s on MT0: (%s)\n", what, n, n + strlen(n) + 1);
}

/* * matches anything, case ignored */
static int match(char *p, char *s)
{
	if (!*p)
		return !*s;
	if (*p == '*')
		return match(p + 1, s) || (*s && match(p, s + 1));
	return *s && lower(*p) == lower(*s) && match(p + 1, s + 1);
}

static int tdir(char *pat)
{
	int first = 0, total = 1, shown = 0, n, i, k;
	char d[2], *p;

	while (first < total) {
		d[0] = first >> 8; d[1] = first;
		if ((n = ask(3, d, 2)) < 4)
			return -1;
		total = get16(r + 24);
		k = get16(r + 26);
		if (k == 0)
			break;
		for (p = (char *)r + 28, i = 0; i < k; i++, p += strlen(p) + 1)
			if (!pat || match(pat, p)) {
				printf("  %s\n", p);
				shown++;
			}
		first += k;
	}
	printf("%d tape%s%s\n", shown, shown == 1 ? "" : "s", pat ? " matched" : " in the library");
	return 0;
}

/* qualifiers may be written onto a word, RSTS style (TLOAD/UNLOAD,
 * NETDATE/SET/QUICK): put a space before each / outside quotes */
static void qualsp(char *s, int size)
{
	int q = 0, n = strlen(s);

	for (; *s; s++, n--) {
		if (*s == '"')
			q = !q;
		else if (*s == '/' && !q && n + 2 < size) {
			memmove(s + 1, s, n + 1);
			*s++ = ' ';
			size--;
		}
		size--;
	}
}

/* the job that owns MT0: (MOUNT, ASSIGN or an open file), this one
 * included: the owner byte of its DDB (DDJBNO, job number * 2, 0 when
 * free), found through the monitor's device tables as SHOW DEVICE does.
 * 0 when free, -1 when the tables cannot be read. */
static int mt_owner()
{
	unsigned fq[16], devcnt, devptr, devnam, type, maxu, ucp;

	if (uutbl(-3, (char *)fq))
		return -1;
	devcnt = fq[3];                 /* maximum unit number of each device */
	devptr = fq[4];                 /* -> each device's DDB pointers */
	if (uutbl(-12, (char *)fq))
		return -1;
	devnam = fq[3];                 /* device names */
	for (;;) {
		type = rpeek(devnam);
		maxu = rpeek(devcnt);
		ucp = rpeek(devptr);           /* -> the DDB of each unit */
		devnam += 2; devcnt += 2; devptr += 2;
		if (type == 0xFFFF)
			return -1;              /* no MT in this monitor */
		if (maxu == 0xFFFF || maxu > 255)
			continue;               /* no units, or a synonym */
		if (type == ('M' | 'T' << 8))
			return (rpeek(rpeek(ucp) + 2) & 0377) / 2;     /* unit 0 */
	}
}

/* MT0: in use: by its owner byte, else (no tables) by trying to open it */
static int mt_busy()
{
	int e, j = mt_owner();

	if (j >= 0)
		return j > 0;
	if ((e = dopn("_MT0:", CH_MT, 0)) == 0)
		fcls(CH_MT);
	return e == 3 || e == 8;
}

int main(int argc, char **argv)
{
	char *w[4], *p, *q;
	int n = 0, isdir, e, st, unload = 0;

	/* the whole command line (case kept in quotes), else the runtime's */
	if (getcc(ccline) > 0 && (lower(ccline[0]) != 't' ||
	    (lower(ccline[1]) != 'l' && lower(ccline[1]) != 'd')))
		ccline[0] = 0;          /* not our command line (RUN): use argv */
	if (ccline[0]) {
		qualsp(ccline, sizeof ccline);
		for (p = ccline; *p && n < 4; ) {
			while (*p == ' ' || *p == '\t')
				p++;
			if (!*p)
				break;
			if (*p == '"') {
				w[n++] = q = ++p;
				while (*p && *p != '"')
					q++, p++;
				if (*p)
					*p++ = 0;
				*q = 0;
				continue;
			}
			w[n++] = p;
			while (*p && *p != ' ' && *p != '\t')
				p++;
			if (*p)
				*p++ = 0;
		}
	} else
		for (n = 0; n < argc && n < 4; n++)
			w[n] = argv[n];
	isdir = n > 0 && lower(w[0][0]) == 't' && lower(w[0][1]) == 'd';
	if (n > 1 && (w[1][0] == '/' || w[1][0] == '-')) {
		if (lower(w[1][1]) != 'u') {
			printf("?TLOAD: TLOAD name, TLOAD, TLOAD /UNLOAD; TDIR [pattern]\n");
			return 1;
		}
		unload = 1;
	}

	if ((e = ethopn(CH_XE, 0, PT_TLIB, 2)) != 0) {
		printf("?TLOAD: cannot open XE0: (error %d)\n", e);
		return 1;
	}
	if (isdir)
		st = tdir(n > 1 ? w[1] : (char *)0);
	else if (unload || n > 1) {
		if (mt_busy()) {
			printf("?TLOAD: MT0: is in use - DISMOUNT, DEALLOCATE or DEASSIGN it first\n");
			ethcls(CH_XE);
			return 1;
		}
		st = unload ? ask(2, "", 0) : ask(1, w[1], strlen(w[1]));
		if (st >= 0) {
			if (r[19])
				st = fail(r[19]);
			else {
				if (unload)
					printf("MT0: unloaded\n");
				else
					show("Loaded");
				st = 0;
			}
		}
	} else if ((st = ask(4, "", 0)) >= 0) {
		if (r[19])
			st = fail(r[19]);
		else {
			show("Tape");
			st = 0;
		}
	}
	ethcls(CH_XE);
	if (st < 0) {
		printf("?TLOAD: no answer from the tape library (needs MiSTer_pdp2011\n");
		printf("        with TLOAD support, and Host network not Off)\n");
		return 1;
	}
	return st;
}
