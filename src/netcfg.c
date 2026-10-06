/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* netcfg.c - settings for the RSTS/E IP programs.
 *
 * TCPIP$:TCPIP.INI, one setting per line, "!" starts a comment:
 *	IP       a.b.c.d | DHCP   our address, or ask the network (DHCP)
 *	MASK     a.b.c.d          subnet mask (DHCP supplies it otherwise)
 *	GATEWAY  a.b.c.d          default router (DHCP supplies it otherwise)
 *	DECNET   area.node [name] DECnet node address (and node name), needed
 *	                          only while DECnet runs: DECnet sets the
 *	                          controller's address to AA-00-04-00 + node, and
 *	                          RSTS gives programs no way to read the current
 *	                          address. The node name is also our host name.
 *	HOSTNAME name             host name for DHCP (default: the DECnet node
 *	                          name, else RSTS); a DHCP server that registers
 *	                          names then knows us as e.g. rsts1.lan
 *	MAC      xx-xx-xx-xx-xx-xx  override the controller address entirely
 *	DETACH   YES | NO         detach from the terminal once running
 *	UNIT     n                Ethernet controller XEn: (default 0)
 *	TFTP     YES | NO         run the TFTP server (default YES)
 *
 * Without DECnet the controller's hardware address is read the way SHOW
 * DEVICE XE does it (170101/ushdev.b2s): monitor tables UU.TB1/UU.TB2, the
 * XE entry's DDB, and three words at DDB+66 (needs RDMEM). The tables'
 * offsets are from the Directives Manual (UU.TB1: DEVCNT FIRQB+6, DEVPTR
 * FIRQB+10; UU.TB2: DEVNAM FIRQB+6); global names are unique in 6 chars.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "netcfg.h"

unsigned char cfgmac[6], cfgip[4], cfgmsk[4], cfggw[4];
int cfgdhc, cfgdet, cfgunt, cfgini, cfgtft;
char cfghst[33] = "RSTS";       /* host name sent to DHCP */
char cfgwhy[100];

static int dn_node;             /* DECnet area*1024+node, 0 if not given */
static int mac_given;

static int parse_ip(char *s, unsigned char *ip)
{
	int a, b, c, d;

	if (sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d) != 4 ||
	    (a | b | c | d) < 0 || a > 255 || b > 255 || c > 255 || d > 255)
		return 0;
	ip[0] = a; ip[1] = b; ip[2] = c; ip[3] = d;
	return 1;
}

static int parse_mac(char *s, unsigned char *m)
{
	unsigned v[6];
	int i;

	if (sscanf(s, "%x-%x-%x-%x-%x-%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
		return 0;
	for (i = 0; i < 6; i++)
		m[i] = v[i];
	return 1;
}

/* the controller's hardware (default) address, as SHOW DEVICE XE gets it */
int hwmac(int unit, unsigned char *mac)
{
	unsigned fq[16], devcnt, devptr, devnam, type, maxu, ucp, ddb, w;
	int i;

	if (uutbl(-3, (char *)fq))
		return 0;
	devcnt = fq[3];         /* FIRQB+6: max unit number table */
	devptr = fq[4];         /* FIRQB+10: pointers to device DDBs */
	if (uutbl(-12, (char *)fq))
		return 0;
	devnam = fq[3];         /* FIRQB+6: device name table */
	for (;;) {
		type = rpeek(devnam);
		maxu = rpeek(devcnt);
		ucp = rpeek(devptr);
		devnam += 2; devcnt += 2; devptr += 2;
		if (type == 0xFFFF)
			return 0;
		if (maxu == 0xFFFF || maxu > 255)
			continue;               /* no units, or a synonym */
		if (type == ('X' | 'E' << 8)) {
			if (unit > maxu)
				return 0;
			ddb = rpeek(ucp + 2 * unit);
			for (i = 0; i < 3; i++) {
				w = rpeek(ddb + 66 + 2 * i);
				mac[2 * i] = w & 255;
				mac[2 * i + 1] = w >> 8;
			}
			return 1;
		}
	}
}

/* is DECnet running on the controller? (its portal, type 60-03, is open) */
static int decnet_up(int unit)
{
	int e = ethopn(15, unit, 0x0360, 1);

	if (e == 0)
		ethcls(15);
	return e == 3;          /* ?Account or device in use */
}

/* read the settings and work out our address; 0 and cfgwhy on error */
int cfgld()
{
	FILE *f;
	char line[120], key[20], val[60], name[33];
	int a, n, hgiven = 0;

	cfgdhc = 1;           /* defaults: DHCP, stay attached, XE0: */
	cfgdet = 0;
	cfgunt = 0;
	cfgtft = 1;
	if ((cfgini = (f = fopen("TCPIP$:TCPIP.INI", "r")) != 0) != 0) {
		while (fgets(line, sizeof line, f)) {
			char *c = strchr(line, '!');
			if (c)
				*c = 0;
			name[0] = 0;
			if (sscanf(line, "%19s %59s %32s", key, val, name) < 2)
				continue;
			for (c = key; *c; c++)
				if (*c >= 'a' && *c <= 'z')
					*c -= 'a' - 'A';
			if (!strcmp(key, "IP")) {
				if (val[0] == 'D' || val[0] == 'd')
					cfgdhc = 1;
				else if (parse_ip(val, cfgip))
					cfgdhc = 0;
				else
					goto bad;
			} else if (!strcmp(key, "MASK")) {
				if (!parse_ip(val, cfgmsk))
					goto bad;
			} else if (!strcmp(key, "GATEWAY")) {
				if (!parse_ip(val, cfggw))
					goto bad;
			} else if (!strcmp(key, "DECNET")) {
				if (sscanf(val, "%d.%d", &a, &n) != 2 || a < 1 || a > 63 || n < 1 || n > 1023)
					goto bad;
				dn_node = a * 1024 + n;
				if (name[0] && !hgiven)
					strcpy(cfghst, name);
			} else if (!strcmp(key, "MAC")) {
				if (!parse_mac(val, cfgmac))
					goto bad;
				mac_given = 1;
			} else if (!strcmp(key, "DETACH")) {
				cfgdet = val[0] == 'Y' || val[0] == 'y';
			} else if (!strcmp(key, "HOSTNAME")) {
				strncpy(cfghst, val, 32);
				cfghst[32] = 0;
				hgiven = 1;
			} else if (!strcmp(key, "TFTP")) {
				cfgtft = val[0] == 'Y' || val[0] == 'y';
			} else if (!strcmp(key, "UNIT")) {
				cfgunt = atoi(val);
			}
			continue;
bad:
			sprintf(cfgwhy, "TCPIP.INI: bad value for %s: %s", key, val);
			fclose(f);
			return 0;
		}
		fclose(f);
	}
	if (mac_given)
		return 1;
	if (decnet_up(cfgunt)) {
		if (!dn_node) {
			strcpy(cfgwhy, "DECnet is running: give its node address (DECNET area.node) in TCPIP.INI");
			return 0;
		}
		cfgmac[0] = 0xAA; cfgmac[1] = 0x00; cfgmac[2] = 0x04; cfgmac[3] = 0x00;
		cfgmac[4] = dn_node & 255;
		cfgmac[5] = dn_node >> 8;
		return 1;
	}
	if (!hwmac(cfgunt, cfgmac)) {
		strcpy(cfgwhy, "cannot read the controller address (needs RDMEM; or give MAC in TCPIP.INI)");
		return 0;
	}
	return 1;
}
