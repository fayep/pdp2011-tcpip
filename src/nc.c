/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* nc.c - netcat for RSTS/E: a TCP connection to the terminal or files.
 *
 *	NC [-i file] [-o file] [-t|-b] host port        connect
 *	NC [-i file] [-o file] [-t|-b] -L port          wait for one connection
 *
 *	-i file   send the file, then end-of-file (FIN) - like nc < file
 *	          (-S is the same). Sent up to its recorded length; a text file
 *	          without one loses the NUL padding of its last block.
 *	-o file   write what arrives to the file instead of the terminal - like
 *	          nc > file. Text (decided from the first data, or -t) becomes
 *	          an ordinary RSTS text file (CR LF, no attributes); otherwise
 *	          binary (-b) with RMS attributes of undefined record format
 *	          and the exact length.
 *
 * Without -i, lines typed are sent as typed (ending CR LF); CTRL/Z sends
 * end-of-file. The program ends when the other side closes.
 * RSTS has no pipes or redirection: -i and -o stand in for them.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "netcfg.h"
#include "sock.h"
#include "cmdlin.h"

#define SEG 512
#define CH_IN 10

static unsigned bw[128], lw[64], fw[256];
#define buf ((char *)bw)
#define line ((char *)lw)

static FILE *of;
static int otext = -1;                  /* -o: 1 text, 0 binary, -1 not yet known */
static int prevcr;
static long got;

static int lower(int c)
{
	return c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c;
}

/* looks like text: printable, tab, CR, LF, FF (and a final ^Z) */
static int textlike(char *p, int n)
{
	int i, c;

	for (i = 0; i < n; i++) {
		c = p[i] & 0377;
		if (!(c >= 040 && c < 0177) && c != '\t' && c != '\r' && c != '\n' &&
		    c != '\f' && c != 032)
			return 0;
	}
	return 1;
}

static void out(char *p, int n)
{
	int i;

	if (!of) {
		fwrite(p, 1, n, stdout);
		fflush(stdout);
		return;
	}
	if (otext < 0)
		otext = textlike(p, n);
	if (otext)
		for (i = 0; i < n; i++) {       /* LF -> CR LF */
			if (p[i] == '\n' && !prevcr)
				putc('\r', of);
			putc(p[i], of);
			prevcr = p[i] == '\r';
		}
	else
		fwrite(p, 1, n, of);
	got += n;
}

/* RMS attributes for a binary file of len bytes: undefined record format,
 * highest block, end-of-file block and first free byte */
static void set_length(char *name, long len)
{
	int w[7];
	long blocks = (len + SEG - 1) / SEG, eof = len / SEG + 1;

	w[0] = 0;
	w[1] = 0;
	w[2] = (int)(blocks >> 16); w[3] = (int)blocks;
	w[4] = (int)(eof >> 16);    w[5] = (int)eof;
	w[6] = (int)(len % SEG);
	fatw(name, w, 7);
}

static int usage()
{
	printf("?NC: NC [-i file] [-o file] [-t|-b] host port, or ... -L port\n");
	return 1;
}

int main(int argc, char **argv)
{
	struct sockaddr_in sa;
	int h, ls, n, i, lsn = 0, sentfin = 0, idle, alen, force = -1;
	unsigned port;
	char in[120], *a[3], *ifile = 0, *ofile = 0, *pa[24], *tok;
	int na = 0, pac;
	unsigned blk = 0, nblk = 0;
	long size = -1L, sent = 0;

	cmdarg("NC", 0, &argc, &argv);          /* the whole line (CMDLIN) */
	if (argc < 2) {                         /* ask for the whole line */
		printf("NC? ");
		if (!fgets(in, sizeof in, stdin))
			return 1;
		pa[0] = argv[0];
		pac = 1;
		for (tok = strtok(in, " \t\n"); tok && pac < 23; tok = strtok((char *)0, " \t\n"))
			pa[pac++] = tok;
		argc = pac;
		argv = pa;
	}
	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-' && argv[i][1] && !argv[i][2]) {
			switch (lower(argv[i][1])) {
			case 'l': lsn = 1; break;
			case 't': force = 1; break;
			case 'b': force = 0; break;
			case 'i':
			case 's':
				if (++i >= argc) return usage();
				ifile = argv[i];
				break;
			case 'o':
				if (++i >= argc) return usage();
				ofile = argv[i];
				break;
			default:
				return usage();
			}
		} else if (na < 2)
			a[na++] = argv[i];
		else
			return usage();
	}
	if (na != (lsn ? 1 : 2))
		return usage();
	port = (unsigned)atol(a[lsn ? 0 : 1]);
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	if (!lsn) {
		struct hostent *hp = gethostbyname(a[0]);
		if (!hp) {
			printf("?NC: %s: %s\n", a[0], hstrerror(h_errno));
			return 1;
		}
		memcpy(&sa.sin_addr, hp->h_addr, 4);
	}
	if (ifile) {                            /* the recorded length, if any */
		int w[11];
		long eof;
		if (fatr(ifile, w) == 0 && (eof = (long)(unsigned)w[4] << 16 | (unsigned)w[5]) != 0)
			size = (eof - 1) * SEG + (unsigned)w[6];
		if (fopn(ifile, CH_IN, &nblk) != 0) {
			printf("?NC: cannot open %s\n", ifile);
			return 1;
		}
	}
	if (ofile) {
		fdel(ofile);            /* stdio cannot open a file with attributes */
		if ((of = fopen(ofile, "wb")) == 0) {
			printf("?NC: cannot create %s\n", ofile);
			return 1;
		}
		otext = force;
	}
	if ((h = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("?NC: %s\n", sostr(soerr));
		return 1;
	}
	if (lsn) {
		ls = h;
		if (bind(ls, (struct sockaddr *)&sa, sizeof sa) < 0 || listen(ls, 1) < 0) {
			printf("?NC: %s\n", sostr(soerr));
			return 1;
		}
		printf("Listening on port %u\n", port);
		alen = sizeof sa;
		h = accept(ls, (struct sockaddr *)&sa, &alen);
		closesocket(ls);                /* one connection only */
	} else if (connect(h, (struct sockaddr *)&sa, sizeof sa) < 0)
		h = -1;
	if (h < 0) {
		printf("?NC: %s\n", sostr(soerr));
		return 1;
	}
	alen = sizeof sa;
	getpeername(h, (struct sockaddr *)&sa, &alen);
	printf("Connected %s %s port %u (KB%d:)\n", lsn ? "from" : "to",
	       inet_ntoa(sa.sin_addr), ntohs(sa.sin_port), sokb(h));
	sonblk(h, 1);
	fflush(stdout);
	for (;;) {
		idle = 1;
		n = recv(h, buf, sizeof bw, 0);
		if (n > 0) {
			out(buf, n);
			idle = 0;
		} else if (n == 0) {
			if (!of)
				printf("\n");
			printf("[connection closed by the other side]\n");
			break;
		} else if (soerr != SE_AGAIN) {
			printf("\n[%s]\n", sostr(soerr));
			break;
		}
		if (ifile && !sentfin) {                /* the next block of the file */
			n = ++blk <= nblk ? fblk(CH_IN, (char *)fw, blk) : 0;
			if (size >= 0) {                /* stop at the recorded end */
				if (sent + n > size)
					n = size > sent ? (int)(size - sent) : 0;
			} else if (n > 0 && blk == nblk)
				while (n > 0 && ((char *)fw)[n - 1] == 0)
					n--;            /* the NUL padding of the last block */
			if (n > 0) {
				sent += n;
				send(h, (char *)fw, n, 0);
			} else {
				fcls(CH_IN);
				shutdown(h, 1);
				sentfin = 1;
				printf("[%ld bytes sent from %s]\n", sent, ifile);
			}
			idle = 0;
		} else if (!sentfin) {
			n = drd(0, line, sizeof lw - 2, 8192);  /* a typed line, if any */
			if (n > 0) {
				if (line[n - 1] == '\r')       /* the line ends CR: send CR LF */
					line[n++] = '\n';
				send(h, line, n, 0);
				idle = 0;
			} else if (n == -11) {                  /* CTRL/Z */
				shutdown(h, 1);
				sentfin = 1;
				idle = 0;
			}
		}
		if (idle)
			ethslp(1);      /* typing, data or a message ends the sleep */
	}
	closesocket(h);
	if (of) {
		int text = otext > 0;
		fclose(of);
		if (!text)
			set_length(ofile, got);
		printf("[%ld bytes written to %s as %s]\n", got, ofile, text ? "text" : "binary");
	}
	return 0;
}
