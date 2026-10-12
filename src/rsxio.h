/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* rsxio.h - RSXIO.MAC: the XE: line and system calls for RSX-11M-PLUS
 * programs; the Ethernet routines take ETHIO's arguments (see RSXIO.MAC). */
extern int ethopn(int lun, int unit, int ptype, int nbuf);
extern int ethcls(int lun);
extern int ethput(int lun, char *buf, int len);
extern int ethget(int lun, char *buf, int size, int wait);
extern int ethslp(int seconds);
extern int tpbusy(int dev, int unit);
