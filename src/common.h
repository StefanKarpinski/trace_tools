#include <netinet/in.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <pcap.h>
#include <glib.h>

#include "ether.h"
#include "ip.h"
#include "udp.h"
#include "tcp.h"

#define ETHERTYPE_IP   0x0008
#define ETHERTYPE_ARP  0x0608
#define ETHERTYPE_RARP 0x3508

#define IP_PROTO_ICMP  1
#define IP_PROTO_TCP   6
#define IP_PROTO_UDP  17

#define TCP_MAX_SKIP ((1<<16)-1)

#define INFINITY (1.0/0.0)

#define MAX_IP_LENGTH 15

#define DEBUG fprintf(stderr,"LINE %u\n",__LINE__);

#define errstr strerror(errno)
#define g_hash_table_exists(h,x) g_hash_table_lookup_extended(h,x,NULL,NULL)

// error handling

int warn(const char * fmt, ...);
int  die(const char * fmt, ...);

// #define warn(fmt,...) warn("%u: " fmt,__LINE__,__VA_ARGS__)
// #define  die(fmt,...)  die("%u: " fmt,__LINE__,__VA_ARGS__)

// other utility functions

char *suffix(char *file, char sep);
FILE *cmd_read(const char *arg, ...);
void file_cloexec(FILE *file);

