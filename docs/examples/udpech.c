/* udpech.c - UDP: send a line to a server and print its reply.
 *
 *	RUN UDPECH, or as a command:  UDPECH host port text
 *
 * Shows: a datagram socket, sendto/recvfrom, and sotmo() to stop waiting
 * for a reply that may never come (UDP does not retry by itself).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sock.h"

static unsigned bw[UDP_MAX / 2 + 1];      /* room for a NUL after a full datagram */
#define buf ((char *)bw)

int main(int argc, char **argv)
{
	struct sockaddr_in sa, from;
	struct hostent *hp;
	int s, n, i, alen;

	if (argc < 4) {
		printf("?UDPECH: UDPECH host port text\n");
		return 1;
	}
	if (!(hp = gethostbyname(argv[1]))) {
		printf("?UDPECH: %s: %s\n", argv[1], hstrerror(h_errno));
		return 1;
	}
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons((unsigned)atoi(argv[2]));
	memcpy(&sa.sin_addr, hp->h_addr, 4);

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("?UDPECH: %s\n", sostr(soerr));
		return 1;
	}
	sotmo(s, 3);                            /* recvfrom gives up after 3 s */
	for (i = 1; i <= 3; i++) {              /* and we try 3 times */
		if (sendto(s, argv[3], strlen(argv[3]), 0, (struct sockaddr *)&sa, sizeof sa) < 0) {
			printf("?UDPECH: %s\n", sostr(soerr));
			break;
		}
		alen = sizeof from;
		n = recvfrom(s, buf, UDP_MAX, 0, (struct sockaddr *)&from, &alen);
		if (n >= 0) {
			buf[n] = 0;
			printf("%d bytes from %s port %u: %s\n", n,
			       inet_ntoa(from.sin_addr), ntohs(from.sin_port), buf);
			break;
		}
		if (soerr != SE_TIMEDOUT) {
			printf("?UDPECH: %s\n", sostr(soerr));
			break;
		}
		printf("(no reply, try %d)\n", i);
	}
	closesocket(s);
	return 0;
}
