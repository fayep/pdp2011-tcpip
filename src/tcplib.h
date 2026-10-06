/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* tcplib.h - TCP for RSTS/E programs, through the TCPIPD job.
 * Buffers passed to tcpred/tcpwrt must be at even addresses (word arrays). */
#define TCP_MAXH 4

extern int tcpopn(void);                        /* once per program: 0 or -error */
extern int tcpcon(unsigned char *ip, unsigned port);    /* handle, or -status */
extern int tcplsn(unsigned port);               /* wait for one connection: handle or -status */
extern int tcpred(int h, char *buf, int size);  /* >0 bytes, 0 end of input, -1 nothing yet,
						   -2 reset */
extern int tcpwrt(int h, char *buf, int len);   /* 0 or -error */
extern void tcpfin(int h);                      /* no more to send: FIN after the data */
extern int tcpcls(int h);                       /* close and wait until done */
extern void tcpabt(int h);                      /* abort (RST) */
extern int tcpkb(int h);                        /* the connection's KB number */
extern unsigned char tcprip[4];                 /* remote address of the last connection */
extern unsigned tcprpt;                         /* and its port */
