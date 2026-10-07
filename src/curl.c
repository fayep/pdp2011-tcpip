/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* curl.c - fetch a URL over HTTP for RSTS/E.
 *
 *	CURL [-i] [-I] [-L] [-s] [-v] [-k] [-t|-b] [-x proxy] [-o file] url
 *
 *	-o file   write the body to file instead of the terminal: a text/...
 *	          response as an RSTS text file (CR LF, no attributes), anything
 *	          else as binary (undefined records, exact length in RMS
 *	          attributes)
 *	-t / -b   with -o: treat the body as text / binary whatever its type
 *	-i        show the response headers too;  -I  ask for headers only
 *	-L        follow redirects (up to 5)
 *	-s        no progress or error chatter
 *	-v        show how the proxy's TLS went (X-TLS-* headers)
 *	-k        fetch even when the certificate does not check out
 *	-x h:p    use this proxy (-x none: no proxy); else PROXY in TCPIP.INI
 *
 * url is [http[s]://]host[:port][/path]. RSTS/E has no TLS, so https://
 * goes through a proxy that has (tools/sslproxy.py, e.g. on the MiSTer):
 * CURL sends it "GET https://..." in plain HTTP; it fetches over TLS,
 * checks the certificate and reports in X-TLS-* headers. http:// goes
 * through the proxy too when one is set.
 * The request is HTTP/1.0 (Connection: close), so the body ends when the
 * server closes and is never chunked.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "netcfg.h"
#include "sock.h"

#define MAXREDIR 5
#define SEG 512

static unsigned bw[256], rqw[300];             /* even buffers */
#define buf ((char *)bw)
#define req ((char *)rqw)
static char host[128], path[400], url[520], loc[520], hdr[600];
static unsigned port, pport;
static int tls;                         /* https */
static char proxy[80];                  /* proxy host; "" = none */
static char verified[8], tlserr[120];
static int opt_i, opt_I, opt_L, opt_s, opt_v, opt_k, opt_t, opt_b;
static int ctext;                       /* this response is text/... */
static int prevcr;                      /* text: last byte written was CR */
static char *ofile;
static FILE *of;
static long total;

static int lower(int c)
{
	return c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c;
}

static int prefix(char *s, char *p)     /* s starts with p, any case */
{
	while (*p)
		if (lower(*s++) != *p++)
			return 0;
	return 1;
}

static int parse(char *u)               /* url -> host, port, path */
{
	char *h, *e, *c;
	int n;

	tls = prefix(u, "https://");
	if (tls && !proxy[0]) {
		printf("?CURL: https needs a proxy that does TLS (PROXY in TCPIP.INI, or -x)\n");
		return 0;
	}
	h = tls ? u + 8 : prefix(u, "http://") ? u + 7 : u;
	e = strchr(h, '/');
	n = e ? e - h : strlen(h);
	if (n < 1 || n >= (int)sizeof host) {
		printf("?CURL: bad URL %s\n", u);
		return 0;
	}
	memcpy(host, h, n);
	host[n] = 0;
	port = tls ? 443 : 80;
	if ((c = strchr(host, ':')) != 0) {
		*c = 0;
		port = (unsigned)atol(c + 1);
	}
	strncpy(path, e ? e : "/", sizeof path - 1);
	path[sizeof path - 1] = 0;
	return 1;
}

/* a Location: value -> url (absolute, or relative to the current one) */
static void relocate(char *l)
{
	char *q;

	char *sc = tls ? "https" : "http";

	if (prefix(l, "http://") || prefix(l, "https://"))
		strcpy(url, l);
	else if (l[0] == '/' && l[1] == '/')
		sprintf(url, "%s:%s", sc, l);
	else if (l[0] == '/')
		sprintf(url, "%s://%s:%u%s", sc, host, port, l);
	else {
		if ((q = strrchr(path, '/')) != 0)
			q[1] = 0;
		sprintf(url, "%s://%s:%u%s%s", sc, host, port, path, l);
	}
}

static void body(char *p, int n)
{
	if (n <= 0 || opt_I)
		return;
	if (of && (opt_t || (ctext && !opt_b))) {      /* text: LF -> CR LF */
		int i;
		for (i = 0; i < n; i++) {
			if (p[i] == '\n' && !prevcr)
				putc('\r', of);
			putc(p[i], of);
			prevcr = p[i] == '\r';
		}
	} else if (of)
		fwrite(p, 1, n, of);
	else
		fwrite(p, 1, n, stdout);
	total += n;
}

/* one request: the HTTP status, or -1 */
static int fetch()
{
	struct hostent *h;
	struct sockaddr_in sa;
	int s, n, hl = 0, inhdr = 1, status = -1, i;
	char *e, *line, *nl;

	char *to = proxy[0] ? proxy : host, target[160];
	unsigned toport = proxy[0] ? pport : port;

	if ((h = gethostbyname(to)) == 0) {
		printf("?CURL: %s: %s\n", to, hstrerror(h_errno));
		return -1;
	}
	if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("?CURL: %s\n", sostr(soerr));
		return -1;
	}
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(toport);
	memcpy(&sa.sin_addr, h->h_addr, 4);
	if (!opt_s && proxy[0])
		printf("[connecting to proxy %s (%s) port %u for %s]\n", proxy,
		       inet_ntoa(sa.sin_addr), pport, host);
	else if (!opt_s)
		printf("[connecting to %s (%s) port %u]\n", host, inet_ntoa(sa.sin_addr), port);
	if (connect(s, (struct sockaddr *)&sa, sizeof sa) < 0) {
		printf("?CURL: %s: %s\n", to, sostr(soerr));
		closesocket(s);
		return -1;
	}
	if (proxy[0] && port != (tls ? 443 : 80))       /* proxies want the whole URL */
		sprintf(target, "%s://%s:%u", tls ? "https" : "http", host, port);
	else if (proxy[0])
		sprintf(target, "%s://%s", tls ? "https" : "http", host);
	else
		target[0] = 0;
	sprintf(req, "%s %s%s HTTP/1.0\r\nHost: %s\r\nUser-Agent: RSTS-curl/0.3\r\n"
		"Accept: */*\r\n%sConnection: close\r\n\r\n",
		opt_I ? "HEAD" : "GET", target, path, host,
		opt_k ? "X-TLS-Insecure: 1\r\n" : "");
	verified[0] = tlserr[0] = 0;
	if (send(s, req, strlen(req), 0) < 0) {
		printf("?CURL: %s\n", sostr(soerr));
		closesocket(s);
		return -1;
	}
	loc[0] = 0;
	ctext = 0;
	prevcr = 0;
	sotmo(s, 60);
	while ((n = recv(s, buf, sizeof bw, 0)) > 0) {
		if (!inhdr) {
			body(buf, n);
			continue;
		}
		/* headers: gather them in hdr, a line at a time */
		for (i = 0; i < n && inhdr; i++) {
			if (hl < (int)sizeof hdr - 1)
				hdr[hl++] = buf[i];
			if (buf[i] != '\n')
				continue;
			hdr[hl] = 0;
			line = hdr;
			if ((nl = strchr(line, '\r')) != 0 || (nl = strchr(line, '\n')) != 0)
				*nl = 0;
			if (opt_i || opt_I)
				printf("%s\n", line);
			else if (opt_v && (prefix(line, "x-tls-") || prefix(line, "via:")))
				printf("[%s]\n", line);
			if (prefix(line, "x-tls-verified:")) {
				for (e = line + 15; *e == ' '; e++)
					;
				strncpy(verified, e, sizeof verified - 1);
			} else if (prefix(line, "x-tls-error:")) {
				for (e = line + 12; *e == ' '; e++)
					;
				strncpy(tlserr, e, sizeof tlserr - 1);
			}
			if (status < 0) {
				if (prefix(line, "http/") && (e = strchr(line, ' ')) != 0)
					status = atoi(e + 1);
				else
					status = 0;
			} else if (prefix(line, "content-type:")) {
				for (e = line + 13; *e == ' ' || *e == '\t'; e++)
					;
				ctext = prefix(e, "text/");
			} else if (prefix(line, "location:")) {
				for (e = line + 9; *e == ' ' || *e == '\t'; e++)
					;
				strncpy(loc, e, sizeof loc - 1);
				loc[sizeof loc - 1] = 0;
			} else if (line[0] == 0)
				inhdr = 0;              /* the blank line: body follows */
			hl = 0;
		}
		if (!inhdr && status == 502 && verified[0] == 'n')
			break;                  /* certificate refused: said below */
		if (!inhdr && i < n)
			body(buf + i, n - i);
	}
	if (n < 0 && !opt_s)
		printf("\n?CURL: %s\n", sostr(soerr));
	closesocket(s);
	if (status == 502 && verified[0] == 'n')
		printf("?CURL: %s: certificate not trusted (%s); -k fetches anyway\n",
		       host, tlserr[0] ? tlserr : "no reason given");
	else if (tls && verified[0] == 'n' && !opt_s)
		printf("\n[warning: %s's certificate was not verified: %s]\n", host, tlserr);
	else if (tls && !verified[0] && status > 0 && !opt_s)
		printf("\n[warning: the proxy did not say whether the certificate checked out]\n");
	return status;
}

/* PROXY host:port from TCPIP$:TCPIP.INI (unless -x said) */
static void inproxy(char *v)
{
	char *c;

	strncpy(proxy, v, sizeof proxy - 1);
	proxy[sizeof proxy - 1] = 0;
	pport = 3128;
	if ((c = strchr(proxy, ':')) != 0) {
		*c = 0;
		pport = (unsigned)atol(c + 1);
	}
	if (prefix(proxy, "none"))
		proxy[0] = 0;
}

static void readproxy()
{
	FILE *f = fopen("TCPIP$:TCPIP.INI", "r");
	char l[120], k[20], v[80];

	if (!f)
		return;
	while (fgets(l, sizeof l, f)) {
		char *c = strchr(l, '!');
		if (c)
			*c = 0;
		if (sscanf(l, "%19s %79s", k, v) == 2 && prefix(k, "proxy") && !k[5])
			inproxy(v);
	}
	fclose(f);
}

/* RMS attributes for a binary file of len bytes: undefined record format
 * (a byte stream, nothing for RMS to pad), highest block, end-of-file block
 * and first free byte - the exact end */
static void set_length(char *name, long len)
{
	int w[7];
	long blocks = (len + SEG - 1) / SEG, eof = len / SEG + 1;

	w[0] = 0;                       /* undefined record format */
	w[1] = 0;
	w[2] = (int)(blocks >> 16); w[3] = (int)blocks;
	w[4] = (int)(eof >> 16);    w[5] = (int)eof;
	w[6] = (int)(len % SEG);
	fatw(name, w, 7);
}

/* The C runtime takes arguments from the RSX command buffer: 80
 * characters, cut with "-" - too short for many URLs. A CCL command's
 * whole line (up to 127) is in core common; split it ourselves when it is
 * ours. As DCL does, unquoted words come uppercased (we lowercase them) and
 * "quoted" ones keep their case, so a URL with capitals must be quoted. */
static char ccline[130], *ccargv[24];

static int fullargs(int *argcp, char ***argvp)
{
	char *p, *q;
	int n = 0;

	if (*argcp < 2 || getcc(ccline) <= 0)
		return 0;
	for (p = ccline; *p && n < 23; ) {
		while (*p == ' ' || *p == '\t')
			p++;
		if (!*p)
			break;
		if (*p == '"') {                        /* "quoted": case kept */
			ccargv[n++] = q = ++p;
			while (*p && *p != '"')
				*q++ = *p++;
			if (*p)
				p++;
			*q = 0;
			if (*p == ' ')
				p++;
			continue;
		}
		ccargv[n++] = p;
		for (; *p && *p != ' ' && *p != '\t'; p++)
			*p = lower(*p);
		if (*p)
			*p++ = 0;
	}
	ccargv[n] = 0;
	if (n < 2 || !prefix(ccargv[0], (*argvp)[0]))
		return 0;               /* not our command line: keep the runtime's */
	*argcp = n;
	*argvp = ccargv;
	return 1;
}

int main(int argc, char **argv)
{
	int i, st, redirs = 0, xgiven = 0;
	char line[200], *u = 0;

	fullargs(&argc, &argv);

	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-' && argv[i][1]) {
			switch (lower(argv[i][1])) {
			case 'i':
				if (argv[i][1] == 'I') opt_I = 1; else opt_i = 1;
				break;
			case 'l': opt_L = 1; break;
			case 's': opt_s = 1; break;
			case 'v': opt_v = 1; break;
			case 'k': opt_k = 1; break;
			case 't': opt_t = 1; break;
			case 'b': opt_b = 1; break;
			case 'x':
				if (++i < argc) {
					inproxy(argv[i]);
					xgiven = 1;
				}
				break;
			case 'o':
				if (++i < argc)
					ofile = argv[i];
				break;
			default:
				printf("?CURL: unknown option %s\n", argv[i]);
				return 1;
			}
		} else
			u = argv[i];
	}
	if (!u) {
		printf("URL? ");
		if (!fgets(line, sizeof line, stdin) || !(u = strtok(line, " \t\r\n")))
			return 1;
	}
	if (!xgiven)
		readproxy();
	strncpy(url, u, sizeof url - 1);
	if (ofile) {
		fdel(ofile);            /* stdio cannot open a file with attributes */
		if ((of = fopen(ofile, "wb")) == 0) {
			printf("?CURL: cannot create %s\n", ofile);
			return 1;
		}
	}
	for (;;) {
		if (!parse(url))
			return 1;
		st = fetch();
		if (opt_L && (st == 301 || st == 302 || st == 303 || st == 307 || st == 308) &&
		    loc[0] && redirs++ < MAXREDIR) {
			relocate(loc);
			if (!opt_s)
				printf("[redirected to %s]\n", url);
			total = 0;
			if (of) {               /* start the file again */
				fclose(of);
				fdel(ofile);
				of = fopen(ofile, "wb");
			}
			continue;
		}
		break;
	}
	if (of) {
		int text = opt_t || (ctext && !opt_b);
		fclose(of);
		if (!text)
			set_length(ofile, total);
		if (!opt_s)
			printf("[%ld bytes written to %s as %s]\n", total, ofile,
			       text ? "text" : "binary");
	} else if (!opt_I)
		fflush(stdout);
	if (st >= 300 && st < 400 && loc[0] && !opt_L && !opt_s)
		printf("[%d: moved to %s; -L follows]\n", st, loc);
	if (st >= 400 && !opt_s)
		printf("\n?CURL: the server said %d\n", st);
	return st >= 200 && st < 400 ? 0 : 1;
}
