/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* timtst.c - does time() advance on this system? */
#include <stdio.h>
#include <time.h>
#include "netcfg.h"

int main()
{
	long a, b;

	a = time((long *)0);
	ethslp(3);
	b = time((long *)0);
	printf("timtst: time() %ld then %ld after a 3 s sleep (difference %ld)\n", a, b, b - a);
	return 0;
}
