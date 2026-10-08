/* echod.c - a TCP server: echo back what each client sends.
 *
 *	RUN ECHOD, or as a command:  ECHOD [port]   (default 7777)
 *
 * Shows: bind/listen, accept, recv/send on the new socket, the end of a
 * connection (recv gives 0), and serving clients one after another.
 * CTRL/C stops it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sock.h"

static unsigned bw[256];
#define buf ((char *)bw)

int main(int argc, char **argv)
{
	struct sockaddr_in sa, peer;
	int ls, s, n, alen;
	unsigned port = argc > 1 ? (unsigned)atoi(argv[1]) : 7777;

	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = INADDR_ANY;
	if ((ls = socket(AF_INET, SOCK_STREAM, 0)) < 0
	    || bind(ls, (struct sockaddr *)&sa, sizeof sa) < 0
	    || listen(ls, 1) < 0) {
		printf("?ECHOD: %s\n", sostr(soerr));
		return 1;
	}
	printf("Echo server on port %u\n", port);

	for (;;) {
		alen = sizeof peer;
		if ((s = accept(ls, (struct sockaddr *)&peer, &alen)) < 0) {
			printf("?ECHOD: %s\n", sostr(soerr));
			break;
		}
		printf("Connection from %s port %u\n", inet_ntoa(peer.sin_addr),
		       ntohs(peer.sin_port));
		while ((n = recv(s, buf, sizeof bw, 0)) > 0)
			if (send(s, buf, n, 0) < 0)
				break;
		closesocket(s);
		printf("Closed\n");
	}
	closesocket(ls);
	return 0;
}
