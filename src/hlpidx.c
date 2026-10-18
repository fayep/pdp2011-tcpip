/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* hlpidx.c - HLPIDX: merge HELP topics into a HELP index file.
 *
 *	HLPIDX index entries [backup]
 *
 * The kits' installers use it to add their commands to HELP, on RSTS/E
 * (HELP$:HELP.HLP: "*TOPIC" then "@HELP$:FILE.HLP", " " lines between
 * topics, "*|ALIAS" for another name) and on RSX-11M-PLUS (LB:[1,2]MCR.HLP
 * and HELP.HLP: "1 TOPIC" then "@FILE"). A topic line is one starting with
 * "*" or "1 "; whatever follows it, up to the next topic line, belongs to
 * it. entries holds the topics to add, written as they go into the index.
 *
 * Each entry whose topic (or an alias of it) is not in the index already
 * goes in before the first index topic that sorts after it, case ignored;
 * the rest go at the end. If the index separates its topics with lines of
 * blanks, the entries get one too. Nothing missing: the index is left
 * alone. Otherwise backup, when given and not there yet, gets a copy of
 * the index first (on RSX the old index stays as the previous version).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAXBUF 24000            /* the indexes are 4K-6K bytes */
#define MAXLIN 1600
#define MAXENT 32
#define LINLEN 132

static char ibuf[MAXBUF], ebuf[2048];
static char *il[MAXLIN], *el[128];
static int ni, ne;

static int upc(int c)
{
	return c >= 'a' && c <= 'z' ? c - 'a' + 'A' : c;
}

/* read a text file into buf as lines; returns the line count, -1 if it
 * cannot be read, -2 if it is too big */
static int slurp(char *name, char *buf, int size, char **lines, int maxl)
{
	FILE *f = fopen(name, "r");
	char line[LINLEN + 2];
	int n = 0, used = 0, l;

	if (!f)
		return -1;
	while (fgets(line, LINLEN + 1, f)) {
		l = strlen(line);
		while (l > 0 && (line[l - 1] == '\n' || line[l - 1] == '\r'))
			line[--l] = 0;
		if (n >= maxl || used + l + 1 > size) {
			fclose(f);
			return -2;
		}
		lines[n++] = strcpy(buf + used, line);
		used += l + 1;
	}
	fclose(f);
	return n;
}

/* a topic line: "*NAME" (not an alias), "1 NAME"; alias lines "*|NAME" */
static int topic(char *s)
{
	return (s[0] == '*' && s[1] != '|' && s[1]) || (s[0] == '1' && s[1] == ' ');
}

static int alias(char *s)
{
	return s[0] == '*' && s[1] == '|';
}

/* the topic's name, upper case, without marker or trailing blanks */
static char *key(char *s, char *k)
{
	char *p = s + (s[0] == '*' ? (alias(s) ? 2 : 1) : 2);
	int n = 0;

	while (*p == ' ')
		p++;
	while (*p && n < 40)
		k[n++] = upc(*p++);
	while (n > 0 && k[n - 1] == ' ')
		n--;
	k[n] = 0;
	return k;
}

static int blank(char *s)
{
	while (*s == ' ' || *s == '\t')
		s++;
	return !*s;
}

/* is the topic k in the index, as a topic or an alias? */
static int present(char *k)
{
	char k2[44];
	int i;

	for (i = 0; i < ni; i++)
		if ((topic(il[i]) || alias(il[i])) && !strcmp(key(il[i], k2), k))
			return 1;
	return 0;
}

int main(int argc, char **argv)
{
	int es[MAXENT], ee[MAXENT], todo[MAXENT], nent = 0, sep = 0, i, j, k, add = 0;
	char ka[44], kb[44];
	FILE *f;

	printf("Updating Help index\n");
	if (argc < 3) {
		printf("?HLPIDX: HLPIDX index entries [backup]\n");
		return 1;
	}
	if ((ni = slurp(argv[1], ibuf, MAXBUF, il, MAXLIN)) < 0) {
		printf("?HLPIDX: %s %s\n", argv[1], ni == -1 ? "cannot be read" : "is too big");
		return 1;
	}
	if ((ne = slurp(argv[2], ebuf, sizeof ebuf, el, 128)) < 0) {
		printf("?HLPIDX: %s %s\n", argv[2], ne == -1 ? "cannot be read" : "is too big");
		return 1;
	}
	/* the entries: from each topic line to the line before the next */
	for (i = 0; i < ne && nent < MAXENT; i++)
		if (topic(el[i])) {
			if (nent)
				ee[nent - 1] = i;
			es[nent++] = i;
		}
	if (nent)
		ee[nent - 1] = ne;
	for (j = 0; j < nent; j++) {
		while (ee[j] > es[j] + 1 && blank(el[ee[j] - 1]))
			ee[j]--;                /* the separator is ours to write */
		todo[j] = !present(key(el[es[j]], ka));
		add += todo[j];
	}
	if (!add) {
		printf("The topics are in %s already\n", argv[1]);
		return 0;
	}
	/* does the index put a blank line before each topic? */
	for (i = 1; i < ni; i++)
		if (topic(il[i])) {
			sep = blank(il[i - 1]);
			break;
		}
	if (argc > 3 && (f = fopen(argv[3], "r")) == NULL) {
		if ((f = fopen(argv[3], "w")) == NULL) {
			printf("?HLPIDX: cannot write %s; %s not changed\n", argv[3], argv[1]);
			return 1;
		}
		for (i = 0; i < ni; i++)
			fprintf(f, "%s\n", il[i]);
		fclose(f);
	} else if (argc > 3)
		fclose(f);
	if ((f = fopen(argv[1], "w")) == NULL) {
		printf("?HLPIDX: cannot write %s\n", argv[1]);
		return 1;
	}
	for (i = 0; i < ni; i++) {
		if (topic(il[i]))
			for (j = 0; j < nent; j++)
				if (todo[j] && strcmp(key(el[es[j]], ka), key(il[i], kb)) < 0) {
					for (k = es[j]; k < ee[j]; k++)
						fprintf(f, "%s\n", el[k]);
					if (sep)
						fprintf(f, " \n");
					todo[j] = 0;
				}
		fprintf(f, "%s\n", il[i]);
	}
	for (j = 0; j < nent; j++)
		if (todo[j]) {
			if (sep)
				fprintf(f, " \n");
			for (k = es[j]; k < ee[j]; k++)
				fprintf(f, "%s\n", el[k]);
		}
	fclose(f);
	printf("%d topic%s added to %s\n", add, add == 1 ? "" : "s", argv[1]);
	return 0;
}
