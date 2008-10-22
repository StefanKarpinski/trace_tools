/*

This program reads tcpdump files given on the command line and prints a parsed version of the data
contained therein.

Options:
  -f <libpcap filter>     provide a Berkeley Packet Filter expression to select which packets to process.

Author: Stefan Karpinski <stefan.karpinski@gmail.com>

*/

#include <getopt.h>
#include <netinet/in.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <pcap.h>

#include "ether.h"
#include "ip.h"
#include "udp.h"
#include "tcp.h"

#define SIZEOF_ETH  sizeof(struct ether_header)
#define SIZEOF_IP4  sizeof(struct ip)

#define ETHERTYPE_IP    0x0008
#define ETHERTYPE_ARP   0x0608
#define ETHERTYPE_RARP  0x3508

#define IP_PROTO_UDP 17
#define IP_PROTO_TCP 6

// error handling

int warn(const char *fmt, ...) {
  va_list args;
  vfprintf(stderr,fmt,args);
}

int die(const char *fmt, ...) {
  va_list args;
  vfprintf(stderr,fmt,args);
  exit(1);
}

// forward declarations

void process_eth (struct ether_header *x);
void process_ip4 (struct ip           *x);
void process_tcp (struct tcphdr       *x);
void process_udp (struct udphdr       *x);

// functions for handling various layers

void process_eth(struct ether_header *x) {
  /* printf(
    " eth.dhost=%02x:%02x:%02x:%02x:%02x:%02x"
    " eth.shost=%02x:%02x:%02x:%02x:%02x:%02x"
    " eth.type=%u",
    x->ether_dhost[0],
    x->ether_dhost[1],
    x->ether_dhost[2],
    x->ether_dhost[3],
    x->ether_dhost[4],
    x->ether_dhost[5],
    x->ether_shost[0],
    x->ether_shost[1],
    x->ether_shost[2],
    x->ether_shost[3],
    x->ether_shost[4],
    x->ether_shost[5],
    x->ether_type
  ); */
  switch (x->ether_type) {
    case ETHERTYPE_IP:
      process_ip4((struct ip *) (x+1));
      break;
  }
}

void process_ip4(struct ip *x) {
  char *payload = ((char*) x)+(IP_HL(x)<<2);
  printf(
    " ip4.hlen=%u"     // header length
    " ip4.ipver=%u"    // IP version number
    " ip4.tos=%u"      // type of service
    " ip4.len=%u"      // total packet length
    " ip4.id=%u"       // packet ID
    " ip4.flags=%s%s"  // active IP flags
    " ip4.offset=%u"   // fragment offset
    " ip4.ttl=%u"      // time to live
    " ip4.proto=%u"    // enclosed protocol
    " ip4.sum=%u",     // checksum value
    IP_HL(x),
    IP_V(x),
    x->ip_tos,
    x->ip_len,
    x->ip_id,
    (x->ip_off & IP_DF ? "D" : ""),
    (x->ip_off & IP_MF ? "M" : ""),
    x->ip_off & IP_OFFMASK,
    x->ip_ttl,
    x->ip_p,
    x->ip_sum,
    inet_ntoa(x->ip_src),
    inet_ntoa(x->ip_dst)
  );
  printf(" ip4.src=%s",inet_ntoa(x->ip_src)); // source IP address
  printf(" ip4.dst=%s",inet_ntoa(x->ip_dst)); // destination IP address
  switch (x->ip_p) {
    case IP_PROTO_TCP:
      process_tcp((struct tcphdr *) payload);
      break;
    case IP_PROTO_UDP:
      process_udp((struct udphdr *) payload);
      break;
  }
}

void process_tcp(struct tcphdr *x) {
  printf(
    " tcp.sport=%u"
    " tcp.dport=%u"
    " tcp.seq=%u"
    " tcp.ack=%u"
    " tcp.off=%u"
    " tcp.flags=%s%s%s%s%s%s%s%s"
    " tcp.win=%u"
    " tcp.sum=%u"
    " tcp.urp=%u",
    x->th_sport,
    x->th_dport,
    x->th_seq,
    x->th_ack,
    TH_OFF(x),
    (x->th_offx2 & TH_FIN     ? "F" : ""),
    (x->th_offx2 & TH_SYN     ? "S" : ""),
    (x->th_offx2 & TH_RST     ? "R" : ""),
    (x->th_offx2 & TH_PUSH    ? "P" : ""),
    (x->th_offx2 & TH_ACK     ? "A" : ""),
    (x->th_offx2 & TH_URG     ? "U" : ""),
    (x->th_offx2 & TH_ECNECHO ? "E" : ""),
    (x->th_offx2 & TH_CWR     ? "C" : ""),
    x->th_win,
    x->th_sum,
    x->th_urp
  );
}

void process_udp(struct udphdr *x) {
  printf(
    " udp.sport=%u"
    " udp.dport=%u"
    " udp.ulen=%u"
    " udp.sum=%u",
    x->uh_sport,
    x->uh_dport,
    x->uh_ulen,
    x->uh_sum
  );
}

// main processing loop

int main(int argc, char ** argv) {
  int i;
  char *filter = NULL;
  while ((i = getopt(argc,argv,"f:")) != -1) {
    switch (i) {
      case 'f':
        if (!filter) free(filter);
        filter = strdup(optarg);
        break;
                
      case '?':
        if (isprint(optopt))
          fprintf(stderr,"Unknown option `-%c'.\n",optopt);
        else
          fprintf(stderr,"Unknown option character `\\x%x'.\n",optopt);
        // fall through...

      default:
        return 1;
    }
  }
  for (i = optind; i < argc; i++) {
    char error[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(argv[i],error);
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
      const u_char * data;
      struct pcap_pkthdr info;
      while (data = pcap_next(pcap,&info)) {
        printf("cap.time=%f cap.frame=%u cap.data=%u",
          info.ts.tv_sec+info.ts.tv_usec*1e-6,
          info.len,info.caplen
        );
        process_eth((struct ether_header *) data);
        printf("\n");
      }
    } else {
      fprintf(stderr,"pcap: %s\n",error);
      return 1;
    }
  }
  return 0;
}
