/* Copyright (c) 2026 Faye Salwin. Licensed CC BY-NC 4.0:
 * free for non-commercial use with attribution (see LICENSE). */
/* sock.h - BSD-style sockets for RSTS/E programs, through the TCPIPD job.
 *
 * As BSD, with these differences:
 *  - closesocket() closes (close() is C's own); soerr holds the error,
 *    sostr(soerr) describes it (errno is the C library's).
 *  - sonblk(s, 1) makes a socket non-blocking (recv, accept give -1 with
 *    soerr SE_AGAIN); sotmo(s, seconds) bounds a blocking wait (SE_TIMEDOUT).
 *  - a datagram carries at most UDP_MAX (521) bytes.
 *  - names are given as a.b.c.d for now (inet_addr); DNS comes later.
 * Ports in sockaddr_in are in network order, as BSD: use htons().
 */
#define SOCK_STREAM 1
#define SOCK_DGRAM  2
#define AF_INET     2
#define INADDR_ANY  0L
#define INADDR_NONE 0xFFFFFFFFL
#define SO_MAX      8           /* sockets per program */
#ifndef UDP_MAX
#define UDP_MAX     521
#endif

struct in_addr {
	unsigned long s_addr;   /* the four address bytes in network order */
};
struct sockaddr_in {
	short sin_family;
	unsigned short sin_port;        /* network order */
	struct in_addr sin_addr;
	char sin_zero[8];
};
struct sockaddr {
	short sa_family;
	char sa_data[14];
};

/* soerr values */
#define SE_BADF        1        /* not an open socket */
#define SE_INVAL       2        /* not valid in this state */
#define SE_AGAIN       3        /* non-blocking: nothing yet */
#define SE_TIMEDOUT    4
#define SE_CONNREFUSED 5
#define SE_CONNRESET   6
#define SE_NETDOWN     7        /* TCP/IP has no address yet */
#define SE_NETUNREACH  8        /* no route */
#define SE_HOSTUNREACH 9        /* no ARP reply */
#define SE_NOBUFS      10       /* TCPIPD has no free connection/socket */
#define SE_ADDRINUSE   11
#define SE_NOTRUN      12       /* TCPIPD is not running */
#define SE_MFILE       13       /* too many sockets */
#define SE_MSGSIZE     14
#define SE_IO          15       /* RSTS error on the connection's KB */

struct soinf {                  /* TCPIPD's settings (soinfo) */
	unsigned char ip[4], mask[4], gw[4];
	unsigned char dns[2][4];        /* name servers; 0.0.0.0 = none */
	char domain[33];                /* for short names */
	char host[33];                  /* our host name */
	unsigned char mac[6];           /* the interface's Ethernet address */
	int dhcp, up;                   /* address by DHCP; have an address */
	long lease;                     /* DHCP: seconds of lease left */
	long rxpk, rxby, txpk, txby;    /* frames and bytes received / sent */
	long rxerr, txerr;              /* bad IP packets in; failed sends */
};

/* gethostbyname: as BSD; h_errno says why it gave 0 */
struct hostent {
	char *h_name;                   /* the canonical name */
	char **h_aliases;
	int h_addrtype;                 /* AF_INET */
	int h_length;                   /* 4 */
	char **h_addr_list;             /* addresses, network order, 0-ended */
};
#define h_addr h_addr_list[0]
#define HOST_NOT_FOUND 1
#define TRY_AGAIN      2                /* no answer from the name servers */
#define NO_RECOVERY    3                /* no name server set, or bad replies */
#define NO_DATA        4                /* the name exists but has no address */
extern int h_errno;
extern struct hostent *gethostbyname(char *name);
extern char *hstrerror(int e);
extern int soinfo(struct soinf *inf);   /* 0, or -1 (soerr: SE_NOTRUN) */

extern int soerr;
extern char *sostr(int e);

extern int socket(int domain, int type, int protocol);
extern int bind(int s, struct sockaddr *a, int alen);
extern int listen(int s, int backlog);
extern int accept(int s, struct sockaddr *a, int *alen);
extern int connect(int s, struct sockaddr *a, int alen);
extern int send(int s, char *buf, int len, int flags);
extern int recv(int s, char *buf, int len, int flags);
extern int sendto(int s, char *buf, int len, int flags, struct sockaddr *to, int tolen);
extern int recvfrom(int s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen);
extern int shutdown(int s, int how);
extern int closesocket(int s);
extern int getsockname(int s, struct sockaddr *a, int *alen);
extern int getpeername(int s, struct sockaddr *a, int *alen);
extern int sonblk(int s, int on);
extern int sotmo(int s, int seconds);
extern int sokb(int s);                 /* a TCP socket's KB number, or -1 */
extern unsigned htons(unsigned x);
extern unsigned ntohs(unsigned x);
extern unsigned long htonl(unsigned long x);
extern unsigned long ntohl(unsigned long x);
extern unsigned long inet_addr(char *cp);
extern char *inet_ntoa(struct in_addr in);
