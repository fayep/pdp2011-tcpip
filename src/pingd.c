/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* pingd.c - answer ICMP echo (ping) for MY_IP on the RSTS/E Ethernet portal.
 * First milestone of the TFTP server; ARP is answered by arpd.
 */
#include <stdio.h>
#include "netcfg.h"

#define CH_IP 12

static unsigned char myip[4] = MY_IP;
/* Frame buffers are word arrays: PDP-11 C does not align char arrays, and
 * the XE driver takes .READ/.WRITE buffers as given -- an odd one crashes
 * the monitor (odd-address trap in kernel mode). */
static unsigned pktw[757];
#define pkt ((unsigned char *)pktw)

/* ones-complement sum of n bytes, big-endian words */
static unsigned cksum(unsigned char *p, int n)
{
	unsigned long s = 0;

	while (n > 1) {
		s += GET16(p);
		p += 2;
		n -= 2;
	}
	if (n)
		s += (unsigned)p[0] << 8;
	while (s >> 16)
		s = (s & 0xFFFF) + (s >> 16);
	return (unsigned)~s & 0xFFFF;
}

main()
{
	int n, i, e, hl, tot;
	unsigned char *ip, *ic, t;

	if ((e = ethopn(CH_IP, XE_UNIT, PT_IP, 8)) != 0) {
		printf("pingd: open XE%d: IP portal failed, error %d\n", XE_UNIT, e);
		return 1;
	}
	printf("pingd: answering ping for %d.%d.%d.%d\n", myip[0], myip[1], myip[2], myip[3]);
	for (;;) {
		n = ethget(CH_IP, (char *)pkt, FRAME_MAX, 1);
		if (n < 0) {
			if (n != -13)
				printf("pingd: read error %d\n", -n);
			continue;
		}
		ip = pkt + ETH_HDR;
		if (n < ETH_HDR + 20 || (ip[0] >> 4) != 4)
			continue;
		hl = (ip[0] & 15) * 4;
		tot = GET16(ip + 2);
		if (hl < 20 || tot < hl + 8 || ETH_HDR + tot > n || cksum(ip, hl) != 0)
			continue;
		for (i = 0; i < 4; i++)
			if (ip[16 + i] != myip[i])
				break;
		if (i < 4 || ip[9] != 1)
			continue;
		ic = ip + hl;
		if (ic[0] != 8 || cksum(ic, tot - hl) != 0)
			continue;
		/* echo reply: swap MACs and IPs, type 0, new checksums */
		for (i = 0; i < 6; i++) {
			t = pkt[i]; pkt[i] = pkt[6 + i]; pkt[6 + i] = t;
		}
		for (i = 0; i < 4; i++) {
			t = ip[12 + i]; ip[12 + i] = ip[16 + i]; ip[16 + i] = t;
		}
		ip[8] = 64;
		PUT16(ip + 10, 0);
		PUT16(ip + 10, cksum(ip, hl));
		ic[0] = 0;
		PUT16(ic + 2, 0);
		PUT16(ic + 2, cksum(ic, tot - hl));
		n = ETH_HDR + tot;
		if (n < 60)
			n = 60;
		if ((e = ethput(CH_IP, (char *)pkt, n)) != 0)
			printf("pingd: send error %d\n", -e);
	}
}
