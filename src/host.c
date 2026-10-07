/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* host.c - look up names with DNS, or show the network settings.
 *
 *	HOST name ...           the addresses of each name
 *	HOST                    our address, mask, gateway, name servers
 */
#include <stdio.h>
#include <string.h>
#include "netcfg.h"
#include "sock.h"

static void ip4(char *what, unsigned char *a)
{
	printf("%-12s %d.%d.%d.%d\n", what, a[0], a[1], a[2], a[3]);
}

int main(int argc, char **argv)
{
	struct hostent *h;
	struct in_addr in;
	struct soinf inf;
	char line[80], *name, **ap;
	int i, bad = 0;

	if (argc < 2) {
		if (soinfo(&inf) < 0) {
			printf("?HOST: %s\n", sostr(soerr));
			return 1;
		}
		printf("%-12s %s\n", "Host name", inf.host);
		ip4("Address", inf.ip);
		ip4("Mask", inf.mask);
		ip4("Gateway", inf.gw);
		for (i = 0; i < 2; i++)
			if (inf.dns[i][0])
				ip4("Name server", inf.dns[i]);
		if (inf.domain[0])
			printf("%-12s %s\n", "Domain", inf.domain);
		return 0;
	}
	for (i = 1; i < argc; i++) {
		strncpy(line, argv[i], sizeof line - 1);
		line[sizeof line - 1] = 0;
		name = line;
		if ((h = gethostbyname(name)) == 0) {
			printf("%s: %s\n", name, hstrerror(h_errno));
			bad = 1;
			continue;
		}
		if (strcmp(h->h_name, name) != 0 && inet_addr(name) == INADDR_NONE)
			printf("%s is an alias for %s\n", name, h->h_name);
		for (ap = h->h_addr_list; *ap; ap++) {
			memcpy(&in, *ap, 4);
			printf("%s has address %s\n", h->h_name, inet_ntoa(in));
		}
	}
	return bad;
}
