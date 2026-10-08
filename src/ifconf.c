/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* ifconf.c - IFCONFIG: the TCP/IP interface, its addresses and statistics.
 *
 *	IFCONFIG
 */
#include <stdio.h>
#include <string.h>
#include "netcfg.h"
#include "sock.h"

static void ip4(unsigned char *a)
{
	printf("%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
}

int main()
{
	struct soinf inf;
	unsigned char bc[4];
	int i;
	long l;

	if (soinfo(&inf) < 0) {
		printf("?IFCONFIG: %s\n", sostr(soerr));
		return 1;
	}
	for (i = 0; i < 4; i++)
		bc[i] = inf.ip[i] | (unsigned char)~inf.mask[i];
	printf("XE0: flags=%s,BROADCAST  mtu 1500\n", inf.up ? "UP" : "DOWN");
	printf("     ether %02x:%02x:%02x:%02x:%02x:%02x\n", inf.mac[0], inf.mac[1],
	       inf.mac[2], inf.mac[3], inf.mac[4], inf.mac[5]);
	printf("     inet ");
	ip4(inf.ip);
	printf("  netmask ");
	ip4(inf.mask);
	printf("  broadcast ");
	ip4(bc);
	printf("\n     gateway ");
	ip4(inf.gw);
	if (inf.dhcp) {
		l = inf.lease > 0 ? inf.lease : 0L;
		printf("  (DHCP, lease %ld:%02ld:%02ld left)\n", l / 3600, l / 60 % 60, l % 60);
	} else
		printf("  (fixed)\n");
	for (i = 0; i < 2; i++)
		if (inf.dns[i][0]) {
			printf("     nameserver ");
			ip4(inf.dns[i]);
			printf("\n");
		}
	if (inf.domain[0] || inf.host[0])
		printf("     host %s%s%s\n", inf.host, inf.domain[0] ? "  domain " : "", inf.domain);
	printf("     RX packets %ld  bytes %ld  errors %ld\n", inf.rxpk, inf.rxby, inf.rxerr);
	printf("     TX packets %ld  bytes %ld  errors %ld\n", inf.txpk, inf.txby, inf.txerr);
	return 0;
}
