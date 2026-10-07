/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* nc.c - netcat for RSTS/E: a TCP connection to the terminal.
 *
 *	NC host port            connect (a name, or an address a.b.c.d)
 *	NC -L port              wait for one connection
 *	NC -S file address port send a file, then close (like nc < file)
 *
 * Lines typed are sent as typed (ending CR LF); what arrives is shown.
 * CTRL/Z sends end-of-file (FIN); the program ends when the other side
 * closes too.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "netcfg.h"
#include "sock.h"

static unsigned bw[128], lw[64], fw[256];
#define buf ((char *)bw)
#define line ((char *)lw)

int main(int argc, char **argv)
{
	struct sockaddr_in sa;
	int h, ls, n, lsn = 0, sentfin = 0, idle, alen;
	unsigned port;
	char in[80], *a1, *a2, *file = 0;
	unsigned blk = 0, nblk = 0;

	if (argc > 4 && (argv[1][1] == 'S' || argv[1][1] == 's') && argv[1][0] == '-') {
		file = argv[2];
		argv += 2;
		argc -= 2;
	}
	if (argc > 2) {
		a1 = argv[1];
		a2 = argv[2];
	} else {
		printf("NC address port, or NC -L port? ");
		if (!fgets(in, sizeof in, stdin))
			return 1;
		a1 = strtok(in, " \t\n");
		a2 = strtok((char *)0, " \t\n");
	}
	if (!a1 || !a2) {
		printf("?NC: give an address and a port, or -L and a port\n");
		return 1;
	}
	lsn = (a1[0] == '-' && (a1[1] == 'L' || a1[1] == 'l'));
	port = (unsigned)atol(a2);
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	if (!lsn) {
		struct hostent *hp = gethostbyname(a1);
		if (!hp) {
			printf("?NC: %s: %s\n", a1, hstrerror(h_errno));
			return 1;
		}
		memcpy(&sa.sin_addr, hp->h_addr, 4);
	}
	if (file && fopn(file, 10, &nblk) != 0) {
		printf("?NC: cannot open %s\n", file);
		return 1;
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
			fwrite(buf, 1, n, stdout);
			fflush(stdout);
			idle = 0;
		} else if (n == 0) {
			printf("\n[connection closed by the other side]\n");
			break;
		} else if (soerr != SE_AGAIN) {
			printf("\n[%s]\n", sostr(soerr));
			return 1;
		}
		if (file && !sentfin) {                         /* the next block of the file */
			n = ++blk <= nblk ? fblk(10, (char *)fw, blk) : 0;
			if (n > 0 && blk == nblk)
				while (n > 0 && ((char *)fw)[n - 1] == 0)
					n--;            /* the NUL padding of the last block */
			if (n > 0)
				send(h, (char *)fw, n, 0);
			else {
				fcls(10);
				shutdown(h, 1);
				sentfin = 1;
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
	return 0;
}
