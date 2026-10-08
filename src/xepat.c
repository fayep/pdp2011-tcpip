/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* xepat.c - make the ONLPAT command file that fixes the RSTS/E 10.1 XE
 * (DEUNA/DELUA) driver crash on received frames of 629-632 bytes.
 *
 *	XEPAT [-Q] [file [sil]] default TCPIP$:XEPAT.CMD, the installed SIL;
 *	                        -Q: say nothing when the fix is already there
 *
 * Exit status: 0 = command file written (run ONLPAT on it, then reboot),
 * 1 = already patched, 2 = not this driver / cannot tell (nothing done).
 *
 * The bug: the driver receives into 632-byte buffers and chains longer
 * frames. MLEN counts the 4 CRC bytes, so when only CRC bytes land in the
 * last buffer, GETPKT gives that buffer a length of 0..-3; XEREAD's signed
 * compare passes it to MOVMEM, which needs at least 1 -> a runaway copy
 * and a monitor crash. Real DEUNAs and SIMH both do this.
 *
 * The fix, in XEREAD (module UNA): skip MOVMEM when the count is <= 0.
 * The count has already been added to XRBC, so the program sees the true
 * frame length. Room for TST R2 / BLE comes from turning
 * BIC #170000,R1 / BIS #120000,R1 (APR6 -> APR5) into SUB #20000,R1 (the
 * pointer is always in the APR6 window); the code below moves up two
 * words, with its PC-relative operands (@DPAR6, @IOSTS) and BEQ adjusted.
 *
 * It also fixes UU.DAT (set date/time, module OVR): MOV #60.,@#TIMSEC is a
 * word move, so it zeroes TIMCLK (ticks to the next second) too; that wraps
 * to 255 and the first second after a set lasts over 4 s (NETDATE). The
 * fix is MOVB (Paul Koning's timfix.cmd, found here by its pattern since
 * its offset differs between monitors). OVR is read from the SIL on each
 * use, so that fix works at once; the XE one, in resident code, needs a
 * reboot, so XEPAT also writes <cmdfile>.RBT (TCPIP$:XEPAT.RBT) only when
 * the command file holds the XE fix.
 *
 * Every word is checked here against the expected instruction pattern, and
 * the command file carries each old value, which ONLPAT verifies before it
 * writes: a monitor that differs is refused, never altered.
 */
#include <stdio.h>
#include <string.h>
#include "netcfg.h"

#define CH 10
#define LOAD 0120000

static unsigned bw[256];
static unsigned mw[4096];               /* the UNA module (8K bytes) */
static unsigned nmw;
static char r50c[] = " ABCDEFGHIJKLMNOPQRSTUVWXYZ$.%0123456789";

static void r50(unsigned w, char *s)
{
	s[0] = r50c[w / 1600];
	s[1] = r50c[w / 40 % 40];
	s[2] = r50c[w % 40];
}

static int rdblk(unsigned blk)          /* file block blk (0-based) into bw */
{
	return fblk(CH, (char *)bw, blk + 1);
}

/* the installed SIL's name from [0,1]INIT.SYS, as NAME.SIL */
static int silname(char *name)
{
	unsigned nb, p;
	char s[7];
	int i, n = 0;

	if (fopn("SY:[0,1]INIT.SYS", CH, &nb) != 0)
		return -1;
	if (rdblk(0) <= 0) { fcls(CH); return -1; }
	p = bw[072 / 2];                        /* where INIT keeps SILNAM */
	if (rdblk(p >> 9) <= 0) { fcls(CH); return -1; }
	r50(bw[(p & 0777) / 2], s);
	r50(bw[(p & 0777) / 2 + 1], s + 3);
	fcls(CH);
	for (i = 0; i < 6; i++)
		if (s[i] != ' ')
			name[n++] = s[i];
	if (!n)
		return -1;
	strcpy(name + n, ".SIL");
	return 0;
}

/* open the SIL on CH and find module want (6 chars, space filled) in its
 * directory: e[4] block, e[13] offset, e[8] size, e[7] load address.
 * 0 (SIL left open) or -1 (closed) */
static int findmod(char *sil, char *want, unsigned *e)
{
	char path[40], nm[7];
	unsigned nb, num, i;

	if (strchr(sil, '[') || strchr(sil, ':'))
		strcpy(path, sil);
	else
		sprintf(path, "SY:[0,1]%s", sil);
	if (fopn(path, CH, &nb) != 0)
		return -1;
	if (rdblk(0) <= 0) { fcls(CH); return -1; }
	num = bw[0];
	for (i = 0; i < num; i++) {
		if (i < 15)
			memcpy(e, (char *)bw + 2 + i * 32, 32);
		else {
			if (rdblk(1 + (i - 15) / 16) <= 0) break;
			memcpy(e, (char *)bw + (i - 15) % 16 * 32, 32);
			rdblk(0);
		}
		r50(e[0], nm); r50(e[1], nm + 3); nm[6] = 0;
		if (strcmp(nm, want) == 0)
			return 0;
	}
	fcls(CH);
	return -1;
}

/* module UNA of the SIL into mw; 0 or -1 */
static int getuna(char *sil)
{
	unsigned e[16], b, o, siz, got;
	long pos, end;
	int k;

	if (findmod(sil, "UNA   ", e) < 0)
		return -1;
	b = e[4]; o = e[13]; siz = e[8];
	if (e[7] != LOAD || siz > sizeof mw) { fcls(CH); return -1; }
	pos = (long)b * 512 + o;
	end = pos + siz;
	got = 0;
	while (pos < end) {                     /* copy the module out, block by block */
		if (rdblk((unsigned)(pos / 512)) <= 0) { fcls(CH); return -1; }
		k = 512 - (int)(pos % 512);
		if (k > end - pos) k = (int)(end - pos);
		memcpy((char *)mw + got, (char *)bw + (int)(pos % 512), k);
		got += k;
		pos += k;
	}
	fcls(CH);
	nmw = siz / 2;
	return 0;
}

#define W(i) mw[i]

static int orig(unsigned i)             /* the unpatched XEREAD pattern at i? */
{
	return W(i) == 0042701 && W(i+1) == 0170000 && W(i+2) == 0052701 && W(i+3) == 0120000
	    && W(i+4) == 0012677 && W(i+6) == 0021302 && W(i+7) == 0002005
	    && W(i+8) == 0112777 && W(i+11) == 0011302 && (W(i+12) & 0177400) == 0001400
	    && W(i+13) == 0160213 && W(i+16) == 0060263 && W(i+20) == 0010503
	    && W(i+21) == 0060205 && W(i+22) == 0004737;
}

static int patched(unsigned i)          /* our patch already there? */
{
	return W(i) == 0162701 && W(i+1) == 0020000 && W(i+2) == 0012677
	    && W(i+4) == 0021302 && W(i+5) == 0002005 && W(i+6) == 0112777
	    && W(i+9) == 0011302 && W(i+11) == 0160213 && W(i+19) == 0060205
	    && W(i+20) == 0005702 && W(i+21) == 0003402 && W(i+22) == 0004737;
}

/* UU.DAT in module OVR: MOV R0,@#TIME; MOV #60.,@#TIMSEC (or the MOVB fix)
 * - count both and return the offset of the MOV/MOVB word; -1 if no OVR */
static unsigned ovload;
static int scanovr(char *sil, unsigned *at, int *norig, int *nfix)
{
	unsigned e[16], win[5], k, n, w;
	long pos, end;
	int i;

	*norig = *nfix = 0;
	if (findmod(sil, "OVR   ", e) < 0)
		return -1;
	ovload = e[7];
	pos = (long)e[4] * 512 + e[13];
	end = pos + e[8];
	n = 0;
	for (; pos < end; pos += 512 - (int)(pos % 512)) {      /* block by block */
		if (rdblk((unsigned)(pos / 512)) <= 0) { fcls(CH); return -1; }
		for (k = (unsigned)(pos % 512) / 2; k < 256 && pos + 2 * (k - (unsigned)(pos % 512) / 2) < end; k++) {
			for (i = 0; i < 4; i++) win[i] = win[i + 1];
			win[4] = w = bw[k];
			if (++n < 5) continue;
			if (win[0] == 0010037 && win[3] == 0000074 && win[4] - win[1] == 2
			    && (win[2] == 0012737 || win[2] == 0112737)) {
				if (win[2] == 0012737) (*norig)++; else (*nfix)++;
				*at = (unsigned)((n - 3) * 2);          /* module offset of the MOV */
			}
		}
	}
	fcls(CH);
	return 0;
}

int main(int argc, char **argv)
{
	char sil[40], *out;
	unsigned i, at = 0, nw[22], beq, target, s = 0, tat = 0;
	int norig = 0, npat = 0, k, d, quiet = 0, xe, tf, tor, tfx;
	FILE *f;

	if (argc > 1 && argv[1][0] == '-' && (argv[1][1] == 'q' || argv[1][1] == 'Q')) {
		quiet = 1;
		argc--;
		argv++;
	}
	out = argc > 1 ? argv[1] : "TCPIP$:XEPAT.CMD";
	if (argc > 2)
	{
		strncpy(sil, argv[2], sizeof sil - 1);
		sil[sizeof sil - 1] = 0;
	}
	if (argc <= 2 && silname(sil) < 0) {
		printf("xepat: cannot read the installed monitor (privilege?); nothing done\n");
		return 2;
	}

	/* the XE receive fix (module UNA) */
	xe = 0;
	if (getuna(sil) < 0)
		printf("xepat: %s: no DEUNA driver (UNA) found; XE fix skipped\n", sil);
	else {
		for (i = 0; i + 23 < nmw; i++) {
			if (orig(i)) { norig++; at = i; }
			if (patched(i)) npat++;
		}
		if (npat == 1 && norig == 0) {
			if (!quiet)
				printf("xepat: %s: the XE receive fix is already installed\n", sil);
		} else if (norig != 1)
			printf("xepat: %s: XEREAD is not as expected; XE fix not made\n", sil);
		else
			xe = 1;
	}
	if (xe) {
		s = LOAD + 2 * at;
		nw[0] = 0162701;                        /* SUB #20000,R1 */
		nw[1] = 0020000;
		for (k = 0; k < 8; k++)                 /* MOV (SP)+,@DPAR6 ... MOV (R3),R2 */
			nw[2 + k] = W(at + 4 + k);
		nw[3] += 4;                             /* PC-relative: 4 bytes further */
		nw[8] += 4;
		beq = W(at + 12);                       /* BEQ 40$ moves up 4 bytes */
		d = beq & 0200 ? (int)(beq & 0377) - 0400 : (int)(beq & 0377);
		target = s + 26 + d * 2;                /* old: at s+24, PC s+26 */
		d = (int)(target - (s + 22)) / 2;       /* new: at s+20, PC s+22 */
		if (d <= 0 || d > 0177) {
			printf("xepat: unexpected branch; XE fix not made\n");
			xe = 0;
		}
		nw[10] = 0001400 | d;
		for (k = 0; k < 9; k++)                 /* SUB R2,(R3) ... ADD R2,R5 */
			nw[11 + k] = W(at + 13 + k);
		nw[20] = 0005702;                       /* TST R2 */
		nw[21] = 0003402;                       /* BLE over JSR PC,@#MOVMEM */
	}

	/* the set-time fix (module OVR) */
	tf = 0;
	if (scanovr(sil, &tat, &tor, &tfx) < 0)
		printf("xepat: %s: module OVR not found; time fix skipped\n", sil);
	else if (tfx == 1 && tor == 0) {
		if (!quiet)
			printf("xepat: %s: the set-time fix is already installed\n", sil);
	} else if (tor != 1)
		printf("xepat: %s: UU.DAT is not as expected; time fix not made\n", sil);
	else
		tf = 1;

	if (!xe && !tf)
		return 1;
	if ((f = fopen(out, "w")) == 0) {
		printf("xepat: cannot create %s\n", out);
		return 2;
	}
	fprintf(f, "File to patch? %s\n", sil);
	if (xe) {
		fprintf(f, "Module name? UNA\n");
		fprintf(f, "Base address? %o\n", LOAD);
		fprintf(f, "Offset address? %o\n", s - LOAD);
		fprintf(f, " Base\tOffset  Old     New?\n");
		for (k = 0; k < 22; k++)
			fprintf(f, "%06o\t%06o\t%06o\t? %06o\n", LOAD, s - LOAD + 2 * k, W(at + k), nw[k]);
		fprintf(f, "%06o\t%06o\t%06o\t? ^Z\n", LOAD, s - LOAD + 44, W(at + 22));
		fprintf(f, "Offset address? ^Z\nBase address? ^Z\n");
	}
	if (tf) {
		fprintf(f, "Module name? OVR\n");
		fprintf(f, "Base address? %o\n", ovload);
		fprintf(f, "Offset address? %o\n", tat);
		fprintf(f, " Base\tOffset  Old     New?\n");
		fprintf(f, "%06o\t%06o\t%06o\t? %06o\n", ovload, tat, 0012737, 0112737);
		fprintf(f, "%06o\t%06o\t%06o\t? ^Z\n", ovload, tat + 2, 0000074);
		fprintf(f, "Offset address? ^Z\nBase address? ^Z\n");
	}
	fprintf(f, "Module name? ^Z\nFile to patch? ^Z\n");
	fclose(f);
	if (xe) {                               /* resident code: the fix needs a reboot */
		char rbt[48], *dot;
		strncpy(rbt, out, sizeof rbt - 5);
		rbt[sizeof rbt - 5] = 0;
		if ((dot = strrchr(rbt, '.')) != 0 && dot > strrchr(rbt, ']') && dot > strrchr(rbt, ':'))
			*dot = 0;
		strcat(rbt, ".RBT");
		if ((f = fopen(rbt, "w")) != 0) {
			fprintf(f, "XE fix in the monitor file: reboot to use it\n");
			fclose(f);
		}
	}
	printf("xepat: %s: %s%s%s written to %s\n", sil, xe ? "the XE receive fix" : "",
	       xe && tf ? " and " : "", tf ? "the set-time fix" : "", out);
	return 0;
}
