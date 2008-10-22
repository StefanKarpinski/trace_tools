/*

This program reads tcpdump files given on the command line (it will uncompress them if they're gzipped),
assuming that each one contains only data for a single flow (same IP proto, src+dst IPs, src+dst UDP/TCP
ports), and parses the flow  to find how much IP, UDP/TCP, and application data is contained in each of
the flow's packets. The output format for the data is IP protocol-dependent. Here are the formats for the
three types of flows that are handled:

TCP (proto==6):  [timestamp] [IP data size] [TCP data size] [application data size] \
          [URG] [ACK] [PSH] [RST] [SYN] [FIN] [sequence number]
UDP (proto==17): [timestamp] [IP data size] [UDP data size]
Raw IP (other):  [timestamp] [IP data size]

The handling of UDP and IP packets is fairly straightforward; the secret sauce is handling TCP flows
properly, with respect to calculating the amount of *new* application data in each packet.

Options:
  -f <libpcap filter>     provide a Berkeley Packet Filter expression to select which packets to process.
  -s <initial seqno>      set an initial sequence number for a TCP flow; allows continuing from saved state.
  -t <last timestamp>     set an initial value for the last seen timestamp; affects the algorithm that deals
                          with processing TCP flows; allows continuing from saved state.

Author: Stefan Karpinski <stefan.karpinski@gmail.com>

*/

#include <netinet/in.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <pcap.h>
#include <glib.h>

#include "ether.h"
#include "ip.h"
#include "udp.h"
#include "tcp.h"

#define ETHERTYPE_IP   0x0008
#define ETHERTYPE_ARP  0x0608
#define ETHERTYPE_RARP 0x3508

#define IP_PROTO_TCP  6
#define IP_PROTO_UDP 17

#define FLOW_TIMEOUT (60*60)
#define TCP_MAX_SKIP ((1<<16)-1)

#define errstr strerror(errno)

// error handling

int warn(const char * fmt, ...) {
  va_list args;
  va_start(args,fmt);
  vfprintf(stderr,fmt,args);
  va_end(args);
}

int die(const char * fmt, ...) {
  va_list args;
  va_start(args,fmt);
  vfprintf(stderr,fmt,args);
  va_end(args);
  exit(1);
}

#define warn(fmt,...) warn("%u: " fmt,__LINE__,__VA_ARGS__)
#define  die(fmt,...)  die("%u: " fmt,__LINE__,__VA_ARGS__)

// set the FD_CLOEXEC flag on a file descriptor

void file_cloexec(FILE *file) {
  int x,fd = fileno(file);
  x = fcntl(fd,F_GETFD,0);
  if (x < 0) die("fcntl(%u,F_GETFD,0): %s",fd,errstr);
  x = fcntl(fd,F_SETFD,x|FD_CLOEXEC);
  if (x < 0) die("fcntl(%u,F_GETFD,%u): %s",fd,x|FD_CLOEXEC,errstr);
}

// return the suffix of a file name

char *suffix(char *file, char sep) {
  char *suf = rindex(file,sep);
  return suf ? suf : "";
}

// fork a process and read it's output via returned file descriptor

FILE *cmd_read(const char *arg, ...) {
  int fd[2],pid;
  if (pipe(fd)) die("pipe: %s\n",errstr);
  if (pid = fork()) {
    FILE *rf;
    if (close(fd[1])) die("close(%u): %s\n",fd[1],errstr);
    if (!(rf = fdopen(fd[0],"r"))) die("fdopen: %s\n",errstr);
    return rf;
  }
  if (pid < 0) die("fork(): %s\n",errstr);
  if (close(0)) die("close(0): %s\n",errstr);
  if (close(fd[0])) die("close(%u): %s\n",fd[0],errstr);
  if (dup2(fd[1],1) < 0) die("dup2(%u,1): %s\n",fd[1],errstr);
  // WARNING: this is not protable!!!
  // some platforms implement varargs
  // in strange ways that would break
  execvp(arg,&arg);
  die("exec(%s,...): %s\n",arg,errstr);
}

// main processing loop

#define IP4_SIZE(ip) ntohs(ip->ip_len)
#define HAS_PORT(ip) (ip->ip_p==IP_PROTO_TCP||ip->ip_p==IP_PROTO_UDP)
#define SRC_PORT(ip) ntohs(*((u_int16_t*)(((char*)ip)+4*IP_HL(ip))))
#define DST_PORT(ip) ntohs(*((u_int16_t*)(((char*)ip)+4*IP_HL(ip)+2)))
#define UDP_SIZE(ip) ntohs(*((u_int16_t*)(((char*)ip)+4*IP_HL(ip)+4)))
#define UDP_CKSM(ip) ntohs(*((u_int16_t*)(((char*)ip)+4*IP_HL(ip)+6)))
#define TCP_SQNO(ip) ntohl(*((u_int32_t*)(((char*)ip)+4*IP_HL(ip)+4)))
#define TCP_AKNO(ip) ntohl(*((u_int32_t*)(((char*)ip)+4*IP_HL(ip)+8)))

#define TCP_URG(tcp) (tcp->th_flags & TH_URG)
#define TCP_ACK(tcp) (tcp->th_flags & TH_ACK)
#define TCP_PSH(tcp) (tcp->th_flags & TH_PUSH)
#define TCP_RST(tcp) (tcp->th_flags & TH_RST)
#define TCP_SYN(tcp) (tcp->th_flags & TH_SYN)
#define TCP_FIN(tcp) (tcp->th_flags & TH_FIN)

#define copy(x) \
  ((typeof(x)*) memcpy(malloc(sizeof(x)),&(x),sizeof(x)))

int main(int argc, char ** argv) {
  int i;
  double last_time=0;
  u_int32_t last_seqno=0;
  char *filter = NULL;
  while ((i = getopt(argc,argv,"s:t:f:")) != -1) {
    switch (i) {
      case 's':
        last_seqno = atoi(optarg);
        break;
      case 't':
        last_time = atof(optarg);
        break;
      case 'f':
        filter = optarg;
        break;
      case '?':
        if (isprint(optopt))
          fprintf(stderr,"Unknown option `-%c'.\n",optopt);
        else
          fprintf(stderr,"Strange option `\\x%x'.\n",optopt);
      default:
        return 1;
    }
  }
  for (i = optind; i < argc; i++) {
    FILE *file;
    if (0 == strcmp(suffix(argv[i],'.'),".gz")) {
        // use zcat to read gzipped file...
        file = cmd_read("zcat","-f",argv[i],NULL);
    } else if (0 == strcmp(suffix(argv[i],'.'),".bz2")) {
        // use bzcat to read gzipped file...
        file = cmd_read("bzcat","-f",argv[i],NULL);
    } else {
        // plain pcap file, just open it...
        if (!(file = fopen(argv[i],"r")))
            die("fopen(\"%s\",\"r\"): %s\n",argv[i],errstr);
        file_cloexec(file);
    }
    char error[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_fopen_offline(file,error);
    if (filter) {
      int ret;
      struct bpf_program fp;
      ret = pcap_compile(
        pcap,       // the pcap "object"
        &fp,        // filter program
        filter,     // the program argument
        1,          // do optimization
        0           // netmask (unused)
      );
      if (ret == -1) die("pcap_compile: %s\n",pcap_geterr(pcap));
      ret = pcap_setfilter(pcap,&fp);
      if (ret == -1) die("pcap_setfilter: %s\n",pcap_geterr(pcap));
      pcap_freecode(&fp);
    }
    if (pcap) {
      const u_char *x;
      struct pcap_pkthdr info;
      while (x = pcap_next(pcap,&info)) {
        double time = info.ts.tv_sec+info.ts.tv_usec*1e-6;
        struct ether_header *eth = (struct ether_header *) x;
        if (eth->ether_type != ETHERTYPE_IP) continue;
        struct ip *ip = (struct ip *) (x + sizeof(*eth));
        switch (ip->ip_p) {

          case IP_PROTO_TCP: { // TCP packet...
            struct tcphdr *tcp = (struct tcphdr *)
              (x+sizeof(*eth)+4*IP_HL(ip));

            // calculate the TCP payload data size...
            u_int32_t data_size =
              IP4_SIZE(ip)-4*(IP_HL(ip)+TH_OFF(tcp));

            // calculate the seqno of last byte in packet...
            u_int32_t seqno = ntohl(tcp->th_seq)+data_size;
            if (!(tcp->th_flags&(TH_SYN|TH_FIN|TH_RST))) seqno--;

            if (time - last_time >= FLOW_TIMEOUT) {
              last_seqno = seqno;
            } else // regular follow-up packet...
            if (data_size + TCP_MAX_SKIP >= seqno - last_seqno) {
              data_size = seqno - last_seqno;
              last_seqno = seqno;
            } else // possibly seqno wrap-around...
            if (data_size + TCP_MAX_SKIP >= seqno + abs(last_seqno)) {
              data_size = seqno + abs(last_seqno);
              last_seqno = seqno;
            } else { // or out-of-order packet, no new data.
              data_size = 0;
            }
            printf(
              "%017.6f %05u %05u %05u "
              "%c %c %c %c %c %c %010u\n",
              time,
              IP4_SIZE(ip),               // network data size
              IP4_SIZE(ip)-4*IP_HL(ip),   // transport data size
              data_size,                  // application data size
              (TCP_URG(tcp) ? '1' : '0'), // TCP control flags...
              (TCP_ACK(tcp) ? '1' : '0'),
              (TCP_PSH(tcp) ? '1' : '0'),
              (TCP_RST(tcp) ? '1' : '0'),
              (TCP_SYN(tcp) ? '1' : '0'),
              (TCP_FIN(tcp) ? '1' : '0'),
              seqno
            );
          }
          break;
              
          case IP_PROTO_UDP: // UDP packet...
            if (UDP_SIZE(ip) < IP4_SIZE(ip)) continue;
            printf(
              "%017.6f %05u %05u\n",
              time,
              IP4_SIZE(ip),      // network data size
              UDP_SIZE(ip)       // transport data size
            );
            break;
              
          default: // other packet type...
            printf(
              "%017.6f %05u\n",
              time,
              IP4_SIZE(ip)        // network data size
            );
            break;
        }
        last_time = time;
      }
    } else {
        die("pcap: %s\n",error);
    }
  }
  return 0;
}

