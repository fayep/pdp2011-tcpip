/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* netdat.c - NETDATE: the date and time from a network time server (SNTP).
 *
 *	NETDATE [server]          show the server's time and how far off we are
 *	NETDATE /SET [server]     set the system date and time from it
 *	NETDATE /SET /DETACH      the same, detached (for the start-up file)
 *
 * The server is the one given, else NTP in TCPIP$:TCPIP.INI, else the
 * gateway. The time zone is TIMEZONE in TCPIP.INI, written as a POSIX TZ
 * string (PST8PDT,M3.2.0,M11.1.0 - standard name, hours west of UTC,
 * daylight name, and when daylight time starts and ends); without one
 * NETDATE shows UTC and will not set the clock (TIMEZONE UTC0 for UTC).
 *
 * RSTS sets the time in whole minutes and starts the seconds again at the
 * next minute, so NETDATE waits for the start of a minute by the server's
 * clock and sets it on the system's second boundary nearest to it: good to
 * half a second. (Needs the set-time fix XEPAT installs; without it the
 * first second after a set lasts over 4 s.)
 * Setting needs DATES privilege. RSTS dates end on 31-Dec-2035.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "netcfg.h"
#include "sock.h"

#define HZ 60                   /* line clock ticks per second */
#define NTPPORT 123
#define TRIES 3

static unsigned pw[24];         /* the NTP packet (48 bytes), word aligned */
#define pk ((unsigned char *)pw)

static char server[64], tzs[64];
static int quiet;

/* --- time zone: POSIX TZ ------------------------------------------------ */

static long stdoff, dstoff;     /* seconds to add to UTC for local time */
static int hasdst;
static int rm[2], rw[2], rd[2]; /* rule month, week (5 = last), weekday */
static long rt[2];              /* rule time, seconds after local midnight */
static char stdname[8], dstname[8];

static char *tzname(char *p, char *out)
{
	int n = 0;

	if (*p == '<') {
		for (p++; *p && *p != '>'; p++)
			if (n < 7) out[n++] = *p;
		if (*p) p++;
	} else
		for (; (*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z'); p++)
			if (n < 7) out[n++] = *p;
	out[n] = 0;
	return p;
}

static char *tztime(char *p, long *v)   /* [+-]h[:mm[:ss]] in seconds */
{
	int neg = 0;
	long h = 0, m = 0, s = 0;

	if (*p == '+' || *p == '-')
		neg = *p++ == '-';
	while (*p >= '0' && *p <= '9') h = h * 10 + *p++ - '0';
	if (*p == ':') {
		for (p++; *p >= '0' && *p <= '9'; p++) m = m * 10 + *p - '0';
		if (*p == ':')
			for (p++; *p >= '0' && *p <= '9'; p++) s = s * 10 + *p - '0';
	}
	*v = h * 3600L + m * 60L + s;
	if (neg) *v = -*v;
	return p;
}

static char *tzrule(char *p, int i)     /* ,Mm.w.d[/time] */
{
	rt[i] = 7200L;
	if (*p != ',' || p[1] != 'M')
		return 0;
	p += 2;
	rm[i] = atoi(p);
	if (!(p = strchr(p, '.'))) return 0;
	rw[i] = atoi(++p);
	if (!(p = strchr(p, '.'))) return 0;
	rd[i] = atoi(++p);
	while (*p >= '0' && *p <= '9') p++;
	if (*p == '/')
		p = tztime(p + 1, &rt[i]);
	return rm[i] >= 1 && rm[i] <= 12 && rw[i] >= 1 && rw[i] <= 5 && rd[i] <= 6 ? p : 0;
}

static int tzparse(char *p)
{
	long v;

	p = tzname(p, stdname);
	if (!stdname[0])
		return 0;
	p = tztime(p, &v);
	stdoff = -v;                    /* POSIX gives hours west */
	if (!*p)
		return 1;
	p = tzname(p, dstname);
	if (!dstname[0])
		return 0;
	dstoff = stdoff + 3600L;
	if (*p && *p != ',') {
		p = tztime(p, &v);
		dstoff = -v;
	}
	if (!*p) {                      /* no rules: the US ones */
		rm[0] = 3; rw[0] = 2; rd[0] = 0; rt[0] = 7200L;
		rm[1] = 11; rw[1] = 1; rd[1] = 0; rt[1] = 7200L;
	} else if (!(p = tzrule(p, 0)) || !(p = tzrule(p, 1)) || *p)
		return 0;
	hasdst = 1;
	return 1;
}

/* --- calendar ------------------------------------------------------------ */

static int leap(long y)
{
	return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
}

static int mdays[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

/* days since 1-Jan-1970 -> year, day of year (1..366) */
static void civil(long d, long *y, int *doy)
{
	long yy = 1970;

	for (;;) {
		int n = leap(yy) ? 366 : 365;
		if (d < n) break;
		d -= n;
		yy++;
	}
	*y = yy;
	*doy = (int)d + 1;
}

static long daysto(long y)      /* days from 1-Jan-1970 to 1-Jan of year y */
{
	long d = 0, yy;

	for (yy = 1970; yy < y; yy++)
		d += leap(yy) ? 366 : 365;
	return d;
}

/* the day (since 1970) of rule i in year y */
static long ruleday(long y, int i)
{
	long d = daysto(y);
	int m, n, wd, first;

	for (m = 1; m < rm[i]; m++)
		d += mdays[m - 1] + (m == 2 && leap(y));
	wd = (int)((d + 4) % 7);                /* 1-Jan-1970 was a Thursday */
	first = (rd[i] - wd + 7) % 7;           /* first such weekday of the month */
	n = mdays[rm[i] - 1] + (rm[i] == 2 && leap(y));
	if (rw[i] == 5) {
		int day = first + 28;
		while (day >= n) day -= 7;
		return d + day;
	}
	return d + first + 7 * (rw[i] - 1);
}

/* local time offset for the UTC instant (days, seconds) */
static long zone(long days, long secs)
{
	long y, s, e, t;
	int doy;

	if (!hasdst)
		return stdoff;
	civil(days, &y, &doy);
	/* the change instants as UTC seconds since 1970 (as days*86400 + secs) */
	s = ruleday(y, 0) * 86400L + rt[0] - stdoff;
	e = ruleday(y, 1) * 86400L + rt[1] - dstoff;
	t = days * 86400L + secs;
	if (s < e)
		return t >= s && t < e ? dstoff : stdoff;
	return t >= s || t < e ? dstoff : stdoff;   /* southern hemisphere */
}

/* --- the RSTS clock ------------------------------------------------------ */

static long ticks()             /* ticks since midnight */
{
	int w[3];

	tickd(w);
	return ((1440L - w[0]) * 60L + (60 - w[1])) * HZ + (HZ - w[2]);
}

/* RSTS's local time now, as seconds since 1970 (no time zone) */
static long rstsnow(int *frac)
{
	int w[3], date;
	long y, d;

	date = datnow();
	tickd(w);
	y = 1970L + (unsigned)date / 1000;
	d = daysto(y) + (unsigned)date % 1000 - 1;
	*frac = HZ - w[2];
	return d * 86400L + (1440L - w[0]) * 60L + (60 - w[1]);
}

/* --- SNTP ---------------------------------------------------------------- */

/* ask; *utc = server time at our receive (seconds since 1970, UTC),
 * *sub = ticks into that second, *at = our tick count at the receive */
static int ask(struct sockaddr_in *sa, long *utc, int *sub, long *at)
{
	int s, n, i, alen;
	long t0, t1, hi, lo, sec, rtt;
	unsigned fr;
	struct sockaddr_in from;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return -1;
	sotmo(s, 2);
	for (i = 0; i < TRIES; i++) {
		memset(pk, 0, 48);
		pk[0] = 0x23;                   /* LI 0, version 4, client */
		t0 = ticks();
		if (sendto(s, (char *)pk, 48, 0, (struct sockaddr *)sa, sizeof *sa) < 0)
			break;
		alen = sizeof from;
		n = recvfrom(s, (char *)pk, 48, 0, (struct sockaddr *)&from, &alen);
		t1 = ticks();
		if (n < 48 || (pk[0] & 7) != 4 || pk[1] == 0)
			continue;               /* not a server reply, or kiss-o'-death */
		closesocket(s);
		if (t1 < t0) t1 += 86400L * HZ;
		rtt = t1 - t0;
		/* transmit timestamp: seconds since 1900 at 40, fraction at 44 */
		hi = ((long)pk[40] << 8) | pk[41];
		lo = ((long)pk[42] << 8) | pk[43];
		sec = (hi << 16) | lo;
		sec -= ((long)0x83AA << 16) | 0x7E80;   /* 1900 -> 1970 (mod 2^32) */
		fr = ((unsigned)pk[44] << 8) | pk[45];
		/* + half the round trip */
		n = (int)(((long)fr * HZ) >> 16) + (int)(rtt / 2);
		sec += n / HZ;
		*sub = n % HZ;
		*utc = sec;
		*at = t1;
		return 0;
	}
	closesocket(s);
	return -1;
}

/* --- TCPIP.INI ------------------------------------------------------------ */

static int lower(int c)
{
	return c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c;
}

static int keyis(char *k, char *w)
{
	while (*w)
		if (lower(*k++) != *w++)
			return 0;
	return !*k;
}

static void readini()
{
	FILE *f = fopen("TCPIP$:TCPIP.INI", "r");
	char l[120], k[20], v[80];

	if (!f)
		return;
	while (fgets(l, sizeof l, f)) {
		char *c = strchr(l, '!');
		if (c)
			*c = 0;
		if (sscanf(l, "%19s %79s", k, v) != 2)
			continue;
		if (keyis(k, "ntp") && !server[0])
			strncpy(server, v, sizeof server - 1);
		else if (keyis(k, "timezone"))
			strncpy(tzs, v, sizeof tzs - 1);
	}
	fclose(f);
}

/* --- main ---------------------------------------------------------------- */

static char *mon[12] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
			 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

static void show(char *what, long t)    /* t: local seconds since 1970 */
{
	long y, s = t % 86400L;
	int doy, m = 0;

	civil(t / 86400L, &y, &doy);
	while (m < 11 && doy > mdays[m] + (m == 1 && leap(y))) {
		doy -= mdays[m] + (m == 1 && leap(y));
		m++;
	}
	printf("%s %02d-%s-%ld %02ld:%02ld:%02ld", what, doy, mon[m], y,
	       s / 3600, s / 60 % 60, s % 60);
}

int main(int argc, char **argv)
{
	struct soinf inf;
	struct sockaddr_in sa;
	struct hostent *hp;
	long utc, at, loc, off, now, wait, target, next, y, d;
	int sub, frac, i, doy, set = 0, det = 0, e;
	char *w;

	for (i = 1; i < argc; i++) {
		w = argv[i];
		if (*w == '/' || *w == '-') {
			switch (lower(w[1])) {
			case 's': set = 1; break;
			case 'd': det = 1; quiet = 1; break;
			case 'q': quiet = 1; break;
			default:
				printf("?NETDATE: NETDATE [/SET] [/DETACH] [server]\n");
				return 1;
			}
		} else
			strncpy(server, w, sizeof server - 1);
	}
	readini();
	if (tzs[0] && !tzparse(tzs)) {
		printf("?NETDATE: TIMEZONE %s is not a POSIX TZ string\n", tzs);
		return 1;
	}

	if (set && !tzs[0]) {
		printf("?NETDATE: no TIMEZONE in TCPIP$:TCPIP.INI (TIMEZONE UTC0 for UTC); not set\n");
		return 1;
	}
	if (det)                        /* start-up: don't hold up the command file */
		ethdet();

	/* the network may still be coming up (start-up): wait for an address */
	for (i = 0; ; i++) {
		if (soinfo(&inf) == 0 && inf.up)
			break;
		if (i >= 60) {
			printf("?NETDATE: TCP/IP has no address\n");
			return 1;
		}
		ethslp(1);
	}
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(NTPPORT);
	if (server[0]) {
		if (!(hp = gethostbyname(server))) {
			printf("?NETDATE: %s: %s\n", server, hstrerror(h_errno));
			return 1;
		}
		memcpy(&sa.sin_addr, hp->h_addr, 4);
	} else
		memcpy(&sa.sin_addr, inf.gw, 4);

	if (ask(&sa, &utc, &sub, &at) < 0) {
		printf("?NETDATE: no answer from the time server %s\n", inet_ntoa(sa.sin_addr));
		return 1;
	}
	off = zone(utc / 86400L, utc % 86400L);
	loc = utc + off;
	now = rstsnow(&frac);
	if (!quiet) {
		show("Server", loc);
		printf(".%02d %s (%s)\n", sub * 100 / HZ,
		       off == stdoff ? (stdname[0] ? stdname : "UTC") : dstname,
		       inet_ntoa(sa.sin_addr));
		d = (loc - now) * HZ + sub - frac;     /* ticks the system is behind */
		show("System", now);
		printf(".%02d, %s by %ld.%02ld s\n", frac * 100 / HZ, d >= 0 ? "slow" : "fast",
		       (d < 0 ? -d : d) / HZ, (d < 0 ? -d : d) % HZ * 100 / HZ);
	}
	if (!set)
		return 0;
	civil(loc / 86400L, &y, &doy);
	if (y > 2035) {
		printf("?NETDATE: %ld is after 2035, the last year RSTS can hold\n", y);
		return 1;
	}

	/* set it at the start of the next minute, at least 2 s away */
	next = loc - loc % 60 + 60;
	wait = (next - loc) * HZ - sub;
	if (wait < 2 * HZ) {
		next += 60;
		wait += 60L * HZ;
	}
	target = at + wait;
	loc = next;
	/* The monitor sets the minute and seconds but leaves the tick counter
	 * (TIMCLK) as it was, so the seconds keep ticking over where they did
	 * before. Set on the system's own second boundary nearest the server's
	 * minute: off by at most half a second. (Ticks since midnight count
	 * from the system's seconds, so its boundaries are multiples of HZ.) */
	target = (target + HZ / 2) / HZ * HZ;
	for (;;) {                              /* sleep, then the last second by polling */
		now = ticks();
		if (now < at) now += 86400L * HZ;
		if (target - now <= 0)
			break;
		if (target - now > 2 * HZ)
			ethslp((int)((target - now) / HZ) - 1);
	}
	civil(loc / 86400L, &y, &doy);
	e = setdt((int)((y - 1970) * 1000 + doy), (int)(1440L - loc % 86400L / 60));
	if (e) {
		printf("?NETDATE: cannot set the date and time (error %d%s)\n", -e,
		       -e == 10 ? ": needs DATES privilege" : "");
		return 1;
	}
	if (!quiet) {
		show("Set to", loc);
		printf("\n");
	}
	return 0;
}
