/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* curl.c - fetch a URL over HTTP for RSTS/E.
 *
 *	CURL [-i] [-I] [-L] [-s] [-o file] url
 *
 *	-o file   write the body to file (exact length, binary) instead of
 *	          the terminal
 *	-i        show the response headers too;  -I  ask for headers only
 *	-L        follow redirects (up to 5)
 *	-s        no progress or error chatter
 *
 * url is [http://]host[:port][/path]. https:// needs TLS, which this
 * system has not got: use an HTTP server or a proxy that speaks HTTP.
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
static unsigned port;
static int opt_i, opt_I, opt_L, opt_s;
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

	if (prefix(u, "https://")) {
		printf("?CURL: https needs TLS, which RSTS/E has not got; try http://\n");
		return 0;
	}
	h = prefix(u, "http://") ? u + 7 : u;
	e = strchr(h, '/');
	n = e ? e - h : strlen(h);
	if (n < 1 || n >= (int)sizeof host) {
		printf("?CURL: bad URL %s\n", u);
		return 0;
	}
	memcpy(host, h, n);
	host[n] = 0;
	port = 80;
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

	if (prefix(l, "http://") || prefix(l, "https://"))
		strcpy(url, l);
	else if (l[0] == '/' && l[1] == '/')
		sprintf(url, "http:%s", l);
	else if (l[0] == '/')
		sprintf(url, "http://%s:%u%s", host, port, l);
	else {
		if ((q = strrchr(path, '/')) != 0)
			q[1] = 0;
		sprintf(url, "http://%s:%u%s%s", host, port, path, l);
	}
}

static void body(char *p, int n)
{
	if (n <= 0 || opt_I)
		return;
	if (of)
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

	if ((h = gethostbyname(host)) == 0) {
		printf("?CURL: %s: %s\n", host, hstrerror(h_errno));
		return -1;
	}
	if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("?CURL: %s\n", sostr(soerr));
		return -1;
	}
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	memcpy(&sa.sin_addr, h->h_addr, 4);
	if (!opt_s)
		printf("[connecting to %s (%s) port %u]\n", host, inet_ntoa(sa.sin_addr), port);
	if (connect(s, (struct sockaddr *)&sa, sizeof sa) < 0) {
		printf("?CURL: %s: %s\n", host, sostr(soerr));
		closesocket(s);
		return -1;
	}
	sprintf(req, "%s %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: RSTS-curl/0.3\r\n"
		"Accept: */*\r\nConnection: close\r\n\r\n",
		opt_I ? "HEAD" : "GET", path, host);
	if (send(s, req, strlen(req), 0) < 0) {
		printf("?CURL: %s\n", sostr(soerr));
		closesocket(s);
		return -1;
	}
	loc[0] = 0;
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
			if (status < 0) {
				if (prefix(line, "http/") && (e = strchr(line, ' ')) != 0)
					status = atoi(e + 1);
				else
					status = 0;
			} else if (prefix(line, "location:")) {
				for (e = line + 9; *e == ' ' || *e == '\t'; e++)
					;
				strncpy(loc, e, sizeof loc - 1);
				loc[sizeof loc - 1] = 0;
			} else if (line[0] == 0)
				inhdr = 0;              /* the blank line: body follows */
			hl = 0;
		}
		if (!inhdr && i < n)
			body(buf + i, n - i);
	}
	if (n < 0 && !opt_s)
		printf("\n?CURL: %s\n", sostr(soerr));
	closesocket(s);
	return status;
}

/* RMS attributes for a file of len bytes, so RSTS knows its exact length */
static void set_length(char *name, long len)
{
	int w[7];
	long blocks = (len + SEG - 1) / SEG, eof = len / SEG + 1;

	w[0] = 1;
	w[1] = SEG;
	w[2] = (int)(blocks >> 16); w[3] = (int)blocks;
	w[4] = (int)(eof >> 16);    w[5] = (int)eof;
	w[6] = (int)(len % SEG);
	fatw(name, w, 7);
}

int main(int argc, char **argv)
{
	int i, st, redirs = 0;
	char line[200], *u = 0;

	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-' && argv[i][1]) {
			switch (lower(argv[i][1])) {
			case 'i':
				if (argv[i][1] == 'I') opt_I = 1; else opt_i = 1;
				break;
			case 'l': opt_L = 1; break;
			case 's': opt_s = 1; break;
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
		fclose(of);
		set_length(ofile, total);
		if (!opt_s)
			printf("[%ld bytes written to %s]\n", total, ofile);
	} else if (!opt_I)
		fflush(stdout);
	if (st >= 300 && st < 400 && loc[0] && !opt_L && !opt_s)
		printf("[%d: moved to %s; -L follows]\n", st, loc);
	if (st >= 400 && !opt_s)
		printf("\n?CURL: the server said %d\n", st);
	return st >= 200 && st < 400 ? 0 : 1;
}
