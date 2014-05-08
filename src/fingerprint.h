#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#include <net/if.h>
#include <string.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/timeb.h>

#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__bsdi__) || defined(__386BSD__)
#include <net/bpf.h>
#endif

#include <netinet/if_ether.h>
#include <netdb.h>
#include <ctype.h>
#include <sys/stat.h>
#include <errno.h>
#include "zopt.h"

#define VERSION         	" 1.5.4-beta-alx"
#define TCPHDR          	sizeof(struct tcphdr)
#define PSEUHDR         	sizeof(struct pseudohdr)
#define IP              	struct ip
#define TCP             	struct tcphdr
#define UDP			struct udphdr
#define RETURNBUFSIZE		100
#define DEFAULT_SYN_AMOUNT      3
#define DEFAULT_DELAY		1800

#define TCPSYNSCAN		0
#define UDPSCAN			1

#define LOG_OPEN 		1
#define LOG_ADD			2
#define LOG_CLOSE 		3

#define ENABLED 		1
#define DISABLED		0

#define PROTO_ICMP		1
#define PROTO_TCP		6
#define PROTO_UDP		17

void banner ();
void usage (char *name);
void logging(char *buffer, char *logfilename, char command);
void sighandler (int signal);
void sigTERMhandler (int sig, siginfo_t *siginfo, void *context);
void read_FPs ();
const char *get_OS (char *query_fp);
char *checkFingerprint(char *buffer, int len);
void write_fingerprint(const char *output);
void fingerprint(char *buffer, int len);
typedef unsigned int u32;


struct pseudohdr {
unsigned long saddr;
unsigned long daddr;
unsigned char useless;
unsigned char protocol;
unsigned short length;
};


struct replylist {
unsigned long ip;
unsigned short sourceport;
time_t timeout;
struct replylist *next;
};


typedef struct _tcpinfo {
unsigned short srcPort;
unsigned short dstPort;
unsigned char flags;
unsigned long seq;
unsigned long ack;
unsigned long optionsLength;
unsigned char *options;
unsigned long payloadLength;
unsigned char *payload;
unsigned char payloadNeedFree;
} TCPINFO;

struct recvstruct {
int sendsock, recvsock;
unsigned long targetip;
unsigned short startport;
unsigned short stopport;
unsigned short scanport;
unsigned int startIp;
unsigned int bitmask;
unsigned int portAmount;
unsigned int packetAmount;
unsigned int randValue;
unsigned short *portArray;
char dstip[16];
char logfilename[50];
char dbase_file[250];
char banner;
char randomscan;
char verbose;
char logging;
char scantype;
char displayClosedPorts;		//display closed ports? 0 no, 1 yes. Default 0
char insane;				//if value==1, packets will be sent with max speed. default is 0(slower, better results)
char fingerprint;
char daemonize;
char remoteLog[100];			//should be enough
};

struct handover {
unsigned long saddr;
unsigned short port;
char logfilename[50];
char logging;
char dbase_file[250];
int proto;
char os[250]; //enough??????
char fingerprint;
char randomscan;
char daemonize;
char country[5];
char remoteLog[100];
char verbose;
unsigned char *udpPayload;
unsigned int udpPayloadSize;
};

struct scanhost {
unsigned int scanip;
unsigned short scanport;
};
