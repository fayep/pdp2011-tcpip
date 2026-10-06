/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* netd.c - one job answering ARP and ping for MY_IP.
 *
 * RSTS cannot stall on two portals at once, so the job polls each portal
 * without stalling and, when both are empty, sleeps; the Ethernet driver
 * ends the sleep as soon as a frame arrives for one of the job's portals
 * (xedvr.mac: IOFIN4 with JS.XE!JSTIM). This loop is the core the TFTP
 * server is built on.
 */
#include <stdio.h>
#include "netcfg.h"

#define CH_IP  12
#define CH_ARP 13
#define IDLE_SLEEP 30           /* seconds; a frame ends it early */

static unsigned char mymac[6] = MY_MAC;
static unsigned char myip[4] = MY_IP;
static unsigned bcastw[3] = { 0xFFFF, 0xFFFF, 0xFFFF };
#define bcast ((unsigned char *)bcastw)
/* Frame buffers are word arrays: PDP-11 C does not align char arrays, and
 * the XE driver takes .READ/.WRITE buffers as given -- an odd one crashes
 * the monitor (odd-address trap in kernel mode). */
static unsigned pktw[757];
#define pkt ((unsigned char *)pktw)
static long nwake, nframe;

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

static int ours(unsigned char *a)
{
	int i;

	for (i = 0; i < 4; i++)
		if (a[i] != myip[i])
			return 0;
	return 1;
}

static void arp_input(int n)
{
	unsigned char *a = pkt + ETH_HDR;
	int i;

	if (n < ETH_HDR + 28 || GET16(a) != 1 || GET16(a + 2) != 0x0800 ||
	    a[4] != 6 || a[5] != 4 || GET16(a + 6) != 1 || !ours(a + 24))
		return;
	for (i = 0; i < 6; i++) {
		pkt[i] = a[8 + i];
		a[18 + i] = a[8 + i];
		a[8 + i] = mymac[i];
	}
	for (i = 0; i < 4; i++) {
		a[24 + i] = a[14 + i];
		a[14 + i] = myip[i];
	}
	PUT16(a + 6, 2);
	ethput(CH_ARP, (char *)pkt, 60);
}

static void ip_input(int n)
{
	unsigned char *ip = pkt + ETH_HDR, *ic, t;
	int hl, tot, i;

	if (n < ETH_HDR + 20 || (ip[0] >> 4) != 4)
		return;
	hl = (ip[0] & 15) * 4;
	tot = GET16(ip + 2);
	if (hl < 20 || tot < hl + 8 || ETH_HDR + tot > n || cksum(ip, hl) != 0 || !ours(ip + 16))
		return;
	if (ip[9] != 1)
		return;                 /* only ICMP so far */
	ic = ip + hl;
	if (ic[0] != 8 || cksum(ic, tot - hl) != 0)
		return;
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
	ethput(CH_IP, (char *)pkt, n < 60 ? 60 : n);
}

int main()
{
	int n, e, busy;

	if ((e = ethopn(CH_IP, XE_UNIT, PT_IP, 8)) != 0 ||
	    (e = ethopn(CH_ARP, XE_UNIT, PT_ARP, 4)) != 0 ||
	    (e = ethmul(CH_ARP, (char *)bcast, 1)) != 0) {
		printf("netd: cannot open the Ethernet portals, error %d\n", e);
		return 1;
	}
	printf("netd: %d.%d.%d.%d answering ARP and ping\n", myip[0], myip[1], myip[2], myip[3]);
	for (;;) {
		busy = 0;
		while ((n = ethget(CH_ARP, (char *)pkt, FRAME_MAX, 0)) > 0) {
			arp_input(n);
			busy = 1;
			nframe++;
		}
		while ((n = ethget(CH_IP, (char *)pkt, FRAME_MAX, 0)) > 0) {
			ip_input(n);
			busy = 1;
			nframe++;
		}
		if (!busy) {
			ethslp(IDLE_SLEEP);
			nwake++;
		}
	}
}
