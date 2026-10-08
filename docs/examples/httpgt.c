/* httpgt.c - a TCP client: fetch a web page and print it.
 *
 *	RUN HTTPGT, or as a command:  HTTPGT host [path]
 *
 * Shows: gethostbyname, socket/connect, send, recv until the server
 * closes, closesocket, and reporting errors with sostr(soerr).
 */
#include <stdio.h>
#include <string.h>
#include "sock.h"

static char line[80], req[200];
static unsigned bw[256];                /* word array: an even buffer */
#define buf ((char *)bw)

int main(int argc, char **argv)
{
	struct sockaddr_in sa;
	struct hostent *hp;
	char *host, *path;
	int s, n;
	long total = 0;

	if (argc > 1) {
		host = argv[1];
		path = argc > 2 ? argv[2] : "/";
	} else {
		printf("Host? ");
		if (!fgets(line, sizeof line, stdin))
			return 1;
		host = strtok(line, " \t\n");
		path = strtok((char *)0, " \t\n");
		if (!host)
			return 1;
		if (!path)
			path = "/";
	}

	/* the address: a name (DNS) or a.b.c.d */
	if (!(hp = gethostbyname(host))) {
		printf("?HTTPGT: %s: %s\n", host, hstrerror(h_errno));
		return 1;
	}
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(80);                /* ports in network order */
	memcpy(&sa.sin_addr, hp->h_addr, 4);

	if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0
	    || connect(s, (struct sockaddr *)&sa, sizeof sa) < 0) {
		printf("?HTTPGT: %s\n", sostr(soerr));
		return 1;
	}

	/* HTTP/1.0: the server closes the connection after the reply */
	sprintf(req, "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host);
	if (send(s, req, strlen(req), 0) < 0) {
		printf("?HTTPGT: %s\n", sostr(soerr));
		return 1;
	}

	/* recv gives what has arrived (1 to len bytes), 0 at the end */
	while ((n = recv(s, buf, sizeof bw, 0)) > 0) {
		fwrite(buf, 1, n, stdout);
		total += n;
	}
	if (n < 0)
		printf("\n?HTTPGT: %s\n", sostr(soerr));
	closesocket(s);
	printf("\n[%ld bytes]\n", total);
	return 0;
}
