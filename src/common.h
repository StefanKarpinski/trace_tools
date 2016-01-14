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

#define ETHERTYPE_IP    0x0008
#define ETHERTYPE_8021Q 0x0081

#define IP_PROTO_ICMP  1
#define IP_PROTO_TCP   6
#define IP_PROTO_UDP  17

#define TCP_MAX_SKIP ((1<<16)-1)

#ifndef INFINITY
#define INFINITY (1.0/0.0)
#endif
#ifndef NAN
#define NAN (0.0/0.0)
#endif

#define MAX_IP_LENGTH 15

#define DEBUG fprintf(stderr,"LINE %u\n",__LINE__);

#define errstr strerror(errno)
#define g_hash_table_exists(h,x) g_hash_table_lookup_extended(h,x,NULL,NULL)

// error handling

int warn(const char * fmt, ...);
int  die(const char * fmt, ...);

// flow & packet structures and functions

struct flow_record {
  u_int8_t  proto;
  u_int32_t src_ip;
  u_int32_t dst_ip;
  u_int16_t src_port;
  u_int16_t dst_port;
} __attribute__((packed));

struct packet_record {
  u_int32_t flow;
  u_int32_t sec;
  u_int32_t usec;
  u_int16_t size;
} __attribute__((packed));

typedef struct flow_record flow_record;
typedef struct packet_record packet_record;

void ntoh_flow(flow_record *flow);
void hton_flow(flow_record *flow);
void ntoh_packet(packet_record *packet);
void hton_packet(packet_record *packet);

void write_flow(FILE *file, flow_record *flow);
int   read_flow(FILE *file, flow_record *flow);

void write_packet(FILE *file, packet_record *packet);
int   read_packet(FILE *file, packet_record *packet);

// other utility functions

void c_unescape(char* s);
void file_cloexec(FILE *file);
FILE *cmd_read(const char *arg, ...);
FILE *open_arg(const char *arg);
char *get_line(FILE *, char **, size_t *);
