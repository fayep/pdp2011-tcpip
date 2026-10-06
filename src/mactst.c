/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* mactst.c - print the controller's hardware address as SHOW DEVICE XE does */
#include <stdio.h>
#include "netcfg.h"

int main()
{
	unsigned char m[6];

	if (!hwmac(0, m)) {
		printf("mactst: cannot read the XE0: address\n");
		return 1;
	}
	printf("mactst: XE0: hardware address %02X-%02X-%02X-%02X-%02X-%02X\n", m[0], m[1], m[2], m[3], m[4], m[5]);
	return 0;
}
