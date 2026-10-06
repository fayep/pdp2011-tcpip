/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* arpd.c - answer ARP requests for MY_IP on the RSTS/E Ethernet portal.
 * Runs as its own job, stalled on the ARP portal (RSTS cannot wait on two
 * portals at once), so the IP programs never have to handle ARP requests.
 */
#include <stdio.h>
#include "netcfg.h"

#define CH_ARP 13

static unsigned char mymac[6] = MY_MAC;
static unsigned char myip[4] = MY_IP;
static unsigned bcastw[3] = { 0xFFFF, 0xFFFF, 0xFFFF };
#define bcast ((unsigned char *)bcastw)
/* Frame buffers are word arrays: PDP-11 C does not align char arrays, and
 * the XE driver takes .READ/.WRITE buffers as given -- an odd one crashes
 * the monitor (odd-address trap in kernel mode). */
static unsigned pktw[757];
#define pkt ((unsigned char *)pktw)

main()
{
	int n, i, e;
	unsigned char *a;

	if ((e = ethopn(CH_ARP, XE_UNIT, PT_ARP, 4)) != 0) {
		printf("arpd: open XE%d: ARP portal failed, error %d\n", XE_UNIT, e);
		return 1;
	}
	if ((e = ethmul(CH_ARP, (char *)bcast, 1)) != 0) {
		printf("arpd: enable broadcast failed, error %d\n", e);
		return 1;
	}
	printf("arpd: answering ARP for %d.%d.%d.%d\n", myip[0], myip[1], myip[2], myip[3]);
	for (;;) {
		n = ethget(CH_ARP, (char *)pkt, FRAME_MAX, 1);
		if (n < 0) {
			if (n != -13)
				printf("arpd: read error %d\n", -n);
			continue;
		}
		if (n < ETH_HDR + 28)
			continue;
		a = pkt + ETH_HDR;
		/* Ethernet/IPv4 request for our address? */
		if (GET16(a) != 1 || GET16(a + 2) != 0x0800 || a[4] != 6 || a[5] != 4 ||
		    GET16(a + 6) != 1)
			continue;
		for (i = 0; i < 4; i++)
			if (a[24 + i] != myip[i])
				break;
		if (i < 4)
			continue;
		/* reply: to the asker, from us */
		for (i = 0; i < 6; i++) {
			pkt[i] = a[8 + i];            /* Ethernet destination = sender HW */
			a[18 + i] = a[8 + i];         /* target HW = sender HW */
			a[8 + i] = mymac[i];          /* sender HW = us */
		}
		for (i = 0; i < 4; i++) {
			a[24 + i] = a[14 + i];        /* target IP = sender IP */
			a[14 + i] = myip[i];          /* sender IP = us */
		}
		PUT16(a + 6, 2);
		if ((e = ethput(CH_ARP, (char *)pkt, 60)) != 0)
			printf("arpd: send error %d\n", -e);
	}
}
