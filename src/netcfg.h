/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* netcfg.h - shared settings and helpers for the RSTS/E IP programs.
 *
 * MY_MAC must be the controller's current physical address: RSTS/E does not
 * let a program read it. Without DECnet it is the hardware address shown by
 * SHOW DEVICE XE; with DECnet it is AA-00-04-00-xx-yy from the node address
 * (area*1024+node, low byte first). Development system: node 1.10.
 */
#define MY_MAC   { 0xAA, 0x00, 0x04, 0x00, 0x0A, 0x04 }   /* arpd/pingd/netd only */
#define MY_IP    { 192, 168, 51, 240 }

#define XE_UNIT  0

/* netcfg.c: settings from TCPIP$:TCPIP.INI and the controller's address */
extern unsigned char cfgmac[6], cfgip[4], cfgmsk[4], cfggw[4];
extern int cfgdhc, cfgdet, cfgunt, cfgini;  /* cfgini: TCPIP.INI was read */
extern int cfgtft;                       /* run the TFTP server (TFTP YES|NO) */
extern char cfgwhy[];
extern char cfghst[];            /* host name for DHCP */
extern int cfgld(void);
extern int hwmac(int unit, unsigned char *mac);
#define PT_IP    0x0008        /* 08-00 as the PDP-11 word of the type field */
#define PT_ARP   0x0608        /* 08-06 */

extern int ethopn(int chan, int unit, int ptype, int nbuf);
extern int ethcls(int chan);
extern int ethmul(int chan, char *addrs, int count);
extern int ethget(int chan, char *buf, int size, int wait);
extern int ethput(int chan, char *buf, int len);
extern int ethslp(int seconds);      /* int, not void: PDP-11 C reserves the result
                                        word only for non-void functions, and
                                        ethio.mac expects it */
extern int ethdet(void);
extern int msgdcl(char *name, int maxmsg);
extern int msgrem(void);
extern int msgsnd(char *name, int jobx2, char *params, char *buf, int len);
extern int msgrcv(char *params, char *buf, int size, int *jobx2);
extern int tickd(int *w);
extern int fatr(char *name, int *w);
extern int fatw(char *name, int *w, int n);
extern int fopn(char *name, int chan, unsigned *blocks);
extern int fblk(int chan, char *buf, unsigned blk);
extern int fcls(int chan);
extern int fdel(char *name);
extern unsigned rpeek(unsigned addr);
extern int uutbl(int fn, char *buf);

#define FRAME_MAX 1514         /* largest frame: header + 1500 */
#define ETH_HDR  14            /* dst 6, src 6, type 2 (unpadded portal) */
#define B(p, i)  (((unsigned char *)(p))[i])
#define GET16(p) ((unsigned)B(p, 0) << 8 | B(p, 1))
/* PUT16 evaluates v exactly once: with v written twice, PUT16(u + 6,
 * udp_cksum(...)) summed again after the high byte was stored, and when
 * the right checksum ended in 00 the second sum came to FFFF -> 0 -> sent
 * as FFFF, so 1 frame in 256 went out as xxFF; PUT16(h, ++id) counted twice */
static unsigned put16v;
#define PUT16(p, v) (put16v = (unsigned)(v), B(p, 0) = (unsigned char)(put16v >> 8), \
		     B(p, 1) = (unsigned char)put16v)
