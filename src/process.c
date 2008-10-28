#include "common.h"

// flow data structures

typedef struct {
  u_int8_t  proto;
  u_int32_t src_ip;
  u_int32_t dst_ip;
  u_int16_t src_port;
  u_int16_t dst_port;
} flow_key_t;

typedef struct {
  u_int32_t id;
  double    last_time;
  u_int32_t last_seqno;
} flow_data_t;

// flow hashing functions

guint flow_hash(gconstpointer a) {
  flow_key_t *f = (flow_key_t *) a;
  guint32 h = f->proto;
  h = (h<<5)-h + f->src_ip;
  h = (h<<5)-h + f->src_port;
  h = (h<<5)-h + f->dst_ip;
  h = (h<<5)-h + f->dst_port;
  return h;
}        
         
gint flow_equal(gconstpointer a, gconstpointer b) {
  flow_key_t *x = (flow_key_t *) a;
  flow_key_t *y = (flow_key_t *) b;
  return
    x->proto     == y->proto    &&
    x->src_ip    == y->src_ip   &&
    x->src_port  == y->src_port &&
    x->dst_ip    == y->dst_ip   &&
    x->dst_port  == y->dst_port ;
}

// macros for parsing packet data

#define IP4_HEADER_UNIT  4
#define TCP_HEADER_UNIT  4
#define UDP_HEADER_SIZE  8
#define ICMP_HEADER_SIZE 8

#define IP4_SIZE(ip) ntohs(ip->ip_len)
#define HAS_PORT(ip) (ip->ip_p==IP_PROTO_TCP||ip->ip_p==IP_PROTO_UDP)
#define SRC_PORT(ip) ntohs(*((u_int16_t*)(((char*)ip)+IP4_HEADER_UNIT*IP_HL(ip)+0)))
#define DST_PORT(ip) ntohs(*((u_int16_t*)(((char*)ip)+IP4_HEADER_UNIT*IP_HL(ip)+2)))
#define UDP_SIZE(ip) ntohs(*((u_int16_t*)(((char*)ip)+IP4_HEADER_UNIT*IP_HL(ip)+4)))
#define UDP_CKSM(ip) ntohs(*((u_int16_t*)(((char*)ip)+IP4_HEADER_UNIT*IP_HL(ip)+6)))
#define TCP_SQNO(ip) ntohl(*((u_int32_t*)(((char*)ip)+IP4_HEADER_UNIT*IP_HL(ip)+4)))
#define TCP_AKNO(ip) ntohl(*((u_int32_t*)(((char*)ip)+IP4_HEADER_UNIT*IP_HL(ip)+8)))

#define ICMP_TYPE(ip) (*(((char*)ip)+IP4_HEADER_UNIT*IP_HL(ip)+0))
#define ICMP_CODE(ip) (*(((char*)ip)+IP4_HEADER_UNIT*IP_HL(ip)+1))
#define ICMP_TYCO(ip) ntohs(*((u_int16_t*)(((char*)ip)+IP4_HEADER_UNIT*IP_HL(ip)+0)))
#define ICMP_CKSM(ip) ntohs(*((u_int16_t*)(((char*)ip)+IP4_HEADER_UNIT*IP_HL(ip)+2)))
#define ICMP_IDNO(ip) ntohs(*((u_int16_t*)(((char*)ip)+IP4_HEADER_UNIT*IP_HL(ip)+4)))
#define ICMP_SQNO(ip) ntohs(*((u_int16_t*)(((char*)ip)+IP4_HEADER_UNIT*IP_HL(ip)+6)))

#define TCP_URG(tcp) (tcp->th_flags & TH_URG)
#define TCP_ACK(tcp) (tcp->th_flags & TH_ACK)
#define TCP_PSH(tcp) (tcp->th_flags & TH_PUSH)
#define TCP_RST(tcp) (tcp->th_flags & TH_RST)
#define TCP_SYN(tcp) (tcp->th_flags & TH_SYN)
#define TCP_FIN(tcp) (tcp->th_flags & TH_FIN)

// macros for allocating and copying memory

#define allocate(p) ((typeof(p)) malloc(sizeof(*p)))
#define copy(x) ((typeof(x)*) memcpy(malloc(sizeof(x)),&(x),sizeof(x)))

// packet size types

#define SIZE_PACKET             1
#define SIZE_IP_PAYLOAD         2
#define SIZE_TRANSPORT_PAYLOAD  4
#define SIZE_APPLICATION_DATA   8

// output styles

#define OUTPUT_TAB 0
#define OUTPUT_CSV 1
#define OUTPUT_BIN 2

// possible actions for negative intervals

#define NEG_IVAL_DISCARD  0
#define NEG_IVAL_KEEP     1
#define NEG_IVAL_ABSOLUTE 2
#define NEG_IVAL_ZERO     3

// main processing loop

int main(int argc, char ** argv) {

  // option variables
  char *filter       = NULL;
  char *map_file     = NULL;
  u_int32_t flow_id  = 1;
  u_int8_t size_type = SIZE_PACKET;
  u_int8_t output    = OUTPUT_TAB;
  u_int8_t neg_ival  = NEG_IVAL_KEEP;

  // parse options, leave arguments
  int i;
  while ((i = getopt(argc,argv,"f:i:m:PITAtcbdkaz")) != -1) {
    switch (i) {
      case 'f':
        filter = optarg;
        break;
      case 'i':
        flow_id = atoi(optarg);
        break;
      case 'm':
        map_file = optarg;
        break;

      case 'P':
        size_type = SIZE_PACKET;
        break;
      case 'I':
        size_type = SIZE_IP_PAYLOAD;
        break;
      case 'T':
        size_type = SIZE_TRANSPORT_PAYLOAD;
        break;
      case 'A':
        size_type = SIZE_APPLICATION_DATA;
        break;

      case 't':
        output = OUTPUT_TAB;
        break;
      case 'c':
        output = OUTPUT_CSV;
        break;
      case 'b':
        output = OUTPUT_BIN;
        break;

      case 'd':
        neg_ival = NEG_IVAL_DISCARD;
        break;
      case 'k':
        neg_ival = NEG_IVAL_KEEP;
        break;
      case 'a':
        neg_ival = NEG_IVAL_ABSOLUTE;
        break;
      case 'z':
        neg_ival = NEG_IVAL_ZERO;
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
  
  // open map file for writing if requested
  
  FILE *map = NULL;
  if (map_file) {
    if (!(map = fopen(map_file,"w")))
        die("fopen(\"%s\",\"r\"): %s\n",map_file,errstr);
    file_cloexec(map);
  }

  // process each argument as a trace file

  GHashTable *flows = g_hash_table_new(flow_hash,flow_equal);

  for (i = optind; i < argc; i++) {
    fprintf(stderr,"processing %s...\n",argv[i]);
    FILE *file = open_arg(argv[i]);

    char error[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_fopen_offline(file,error);
    if (filter) {
      int ret;
      struct bpf_program fp;
      ret = pcap_compile(
        pcap,   // the pcap "object"
        &fp,    // filter program
        filter, // the program argument
        1,      // do optimization
        0       // netmask (unused)
      );
      if (ret == -1) die("pcap_compile: %s\n",pcap_geterr(pcap));
      ret = pcap_setfilter(pcap,&fp);
      if (ret == -1) die("pcap_setfilter: %s\n",pcap_geterr(pcap));
      pcap_freecode(&fp);
    }

    if (pcap) {
      const u_char *pkt;
      struct pcap_pkthdr info;
      while (pkt = pcap_next(pcap,&info)) {
        struct ether_header *eth = (struct ether_header *) pkt;
        if (eth->ether_type != ETHERTYPE_IP) continue;
        struct ip *ip = (struct ip *) (pkt + sizeof(*eth));
        double time = info.ts.tv_sec + info.ts.tv_usec*1e-6;
        
        flow_key_t key;
        key.proto  = ip->ip_p;
        key.src_ip = ip->ip_src.s_addr;
        key.dst_ip = ip->ip_dst.s_addr;
        if (HAS_PORT(ip)) {
          key.src_port = SRC_PORT(ip);
          key.dst_port = DST_PORT(ip);
        } else {
          key.src_port = ICMP_IDNO(ip);
          key.dst_port = ICMP_TYCO(ip);
        }

        flow_data_t *flow;
        if (!(flow = g_hash_table_lookup(flows,&key))) {
          flow = allocate(flow);
          flow->id = flow_id++;
          flow->last_time = -INFINITY;
          flow->last_seqno = 0;
          g_hash_table_insert(flows,copy(key),flow);
          if (map) {
            if (output != OUTPUT_BIN) {
              char src[MAX_IP_LENGTH+1], dst[MAX_IP_LENGTH+1];
              inet_ntop(AF_INET,&key.src_ip,src,sizeof(src));
              inet_ntop(AF_INET,&key.dst_ip,dst,sizeof(dst));
              char *format =
                output == OUTPUT_TAB ? "%u\t%u\t%s\t%s\t%u\t%u\n" :
                output == OUTPUT_CSV ? "%u,%u,%s,%s,%u,%u\n" : NULL;
              fprintf(map,format,
                flow->id, key.proto, src, dst, key.src_port, key.dst_port
              );
            } else {
              char data[FLOW_RECORD_SIZE];
              *((u_int32_t *) (data +  0)) = htonl(flow->id);
              *((u_int8_t  *) (data +  4)) = key.proto;
              *((u_int32_t *) (data +  5)) = key.src_ip;
              *((u_int32_t *) (data +  9)) = key.dst_ip;
              *((u_int16_t *) (data + 13)) = htons(key.src_port);
              *((u_int16_t *) (data + 15)) = htons(key.dst_port);
              if (fwrite(data,sizeof(data),1,map) != 1)
                die("fwrite: %u\n",errno);
            }
          }
        }

        double ival = time - flow->last_time;
        if (ival < 0) {
          switch (neg_ival) {
            case NEG_IVAL_DISCARD:
              continue; // discard packet
            case NEG_IVAL_KEEP:
              break; // record it as-is
            case NEG_IVAL_ABSOLUTE:
              ival = fabs(ival);
              break;
            case NEG_IVAL_ZERO:
              ival = 0.0;
              break;
          }
        }

        u_int16_t size;
        switch (size_type) {
          case SIZE_PACKET:
            size = IP4_SIZE(ip);
            break;
          case SIZE_IP_PAYLOAD:
            size = IP4_SIZE(ip) - IP4_HEADER_UNIT * IP_HL(ip);
            break;
          case SIZE_TRANSPORT_PAYLOAD:
          case SIZE_APPLICATION_DATA:
            switch (ip->ip_p) {
              case IP_PROTO_ICMP:
                size = IP4_SIZE(ip) - IP4_HEADER_UNIT * IP_HL(ip) - ICMP_HEADER_SIZE;
                break;
              case IP_PROTO_UDP:
                size = UDP_SIZE(ip) - UDP_HEADER_SIZE;
                break;
              case IP_PROTO_TCP: {
                struct tcphdr *tcp = (struct tcphdr *)
                  (pkt + sizeof(*eth) + IP4_HEADER_UNIT * IP_HL(ip));
                size = IP4_SIZE(ip) - IP4_HEADER_UNIT * (IP_HL(ip) + TH_OFF(tcp));
                if (size_type == SIZE_APPLICATION_DATA) {
                  u_int32_t last_byte_seqno = ntohl(tcp->th_seq) + size;
                  if (!(tcp->th_flags & (TH_SYN|TH_FIN|TH_RST))) last_byte_seqno--;
                  if (flow->last_time < 0) {
                    flow->last_seqno = last_byte_seqno;
                  } else // regular follow-up packet
                  if (size + TCP_MAX_SKIP >= last_byte_seqno - flow->last_seqno) {
                    size = last_byte_seqno - flow->last_seqno;
                    flow->last_seqno = last_byte_seqno;
                  } else // possible seqno wrap-around
                  if (size + TCP_MAX_SKIP >= last_byte_seqno + abs(flow->last_seqno)) {
                    // FIXME: this seems questionable.
                    size = last_byte_seqno + abs(flow->last_seqno);
                    flow->last_seqno = last_byte_seqno;
                  } else { // out-of-order packet, no new data.
                    size = 0;
                  }
                }
                break;
              }
              default:
                continue; // ignore packet
            }
            break;
        }

        switch (output) {
          case OUTPUT_TAB:
            printf("%u\t%18.6f\t%10.6f\t%u\n", flow->id, time, ival, size);
            break;
          case OUTPUT_CSV: {
            char buf[256];
            if (ival == INFINITY) *buf = '\0';
            else snprintf(buf,sizeof(buf),"%.6f",ival);
            printf("%u,%.6f,%s,%u\n", flow->id, time, buf, size);
            break;
          }
          case OUTPUT_BIN: {
            char data[PACKET_RECORD_SIZE];
            *((u_int32_t *) (data +  0)) = htonl(flow->id);
            *((u_int32_t *) (data +  4)) = htonl(info.ts.tv_sec);
            *((u_int32_t *) (data +  8)) = htonl(info.ts.tv_usec);
            *((double *)    (data + 12)) = ival;
            *((u_int16_t *) (data + 20)) = htons(size);
            if (fwrite(data,sizeof(data),1,stdout) != 1)
              die("fwrite: %u\n",errno);
          }
        }

        flow->last_time = time;
      }
    } else {
        die("pcap: %s\n",error);
    }
    fclose(file);
  }
  return 0;
}
