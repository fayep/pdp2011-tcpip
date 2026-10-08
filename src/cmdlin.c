/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* cmdlin.c - the whole command line, split RSTS style: see cmdlin.h. */
#include <string.h>
#include "netcfg.h"
#include "cmdlin.h"

#define MAXW 24

static char cl[130], wb[260], *wv[MAXW + 1];

static int lowc(int c)
{
	return c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c;
}

/* is word w (n characters) one of names, or at least two letters of one? */
static int ours(char *names, char *w, int n)
{
	char *p = names;
	int i;

	if (n < 2)
		return 0;
	while (*p) {
		while (*p == ' ')
			p++;
		for (i = 0; i < n && p[i] && p[i] != ' ' && lowc(p[i]) == lowc(w[i]); i++)
			;
		if (i == n)
			return 1;
		while (*p && *p != ' ')
			p++;
	}
	return 0;
}

int cmdarg(char *names, int lower, int *argcp, char ***argvp)
{
	char *p = cl, *o = wb, *s;
	int n = 0, split;

	if (getcc(cl) <= 0)
		return 0;
	for (;;) {
		while (*p == ' ' || *p == '\t')
			p++;
		if (!*p || n >= MAXW)
			break;
		wv[n] = o;
		if (*p == '"') {                        /* quoted: one word, as is */
			for (p++; *p && *p != '"'; )
				*o++ = *p++;
			if (*p)
				p++;
		} else {
			/* the command word and qualifiers split at "/" */
			split = n == 0 || *p == '/';
			s = p;
			do {
				*o++ = lower && n > 0 ? lowc(*p) : *p;
				p++;
			} while (*p && *p != ' ' && *p != '\t' && *p != '"'
				 && !(split && *p == '/'));
			if (n == 0 && !ours(names, s, (int)(p - s)))
				return 0;               /* not our line (RUN): keep argv */
		}
		*o++ = 0;
		n++;
	}
	if (n == 0)
		return 0;
	wv[n] = 0;
	*argcp = n;
	*argvp = wv;
	return 1;
}
