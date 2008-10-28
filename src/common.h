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

#define FLOW_RECORD_SIZE 17
#define PACKET_RECORD_SIZE 22

// error handling

int warn(const char * fmt, ...);
int  die(const char * fmt, ...);

// other utility functions

void file_cloexec(FILE *file);
FILE *cmd_read(const char *arg, ...);
FILE *open_arg(const char *arg);
