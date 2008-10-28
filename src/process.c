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
  u_int32_t index;
  double    last_time;
  u_int32_t last_seqno;
} flow_data_t;

// flow hashing functions

guint flow_hashf(gconstpointer a) {
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

// main processing loop

int main(int argc, char ** argv) {

  // option variables
  char *filter       = NULL;
  char *flow_file    = NULL;
  char *packet_file  = NULL;
  u_int16_t min_size = 1;
  double    max_ival = INFINITY;
  u_int8_t size_type = SIZE_PACKET;

  // parse options, leave arguments
  int i;
  while ((i = getopt(argc,argv,"f:p:F:s:i:PITA")) != -1) {
    switch (i) {
      case 'f':
        flow_file = optarg;
        break;
      case 'p':
        packet_file = optarg;
        break;

      case 'F':
        filter = optarg;
        break;

      case 's':
        min_size = atoi(optarg);
        break;
      case 'i':
        max_ival = atof(optarg);
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

      case '?':
        if (isprint(optopt))
          fprintf(stderr,"Unknown option `-%c'.\n",optopt);
        else
          fprintf(stderr,"Strange option `\\x%x'.\n",optopt);
      default:
        return 1;
    }
  }
  if (!flow_file)
    die("Please specify a flow file using -f <file>.");
  if (!packet_file)
    die("Please specify a packet file using -p <file>.");
  
  // open flow & packet files for writing
  
  FILE *flows = fopen(flow_file,"w");
  if (!flows)
      die("fopen(\"%s\",\"r\"): %s\n",flow_file,errstr);
  file_cloexec(flows);

  FILE *packets = fopen(packet_file,"w");
  if (!packets)
      die("fopen(\"%s\",\"r\"): %s\n",packet_file,errstr);
  file_cloexec(packets);

  // process each argument as a trace file

  u_int32_t flow_index = 0;
  GHashTable *flow_hash = g_hash_table_new(flow_hashf,flow_equal);

  if (optind == argc) argc++;
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

        flow_data_t *flow = g_hash_table_lookup(flow_hash,&key);
        double time = info.ts.tv_sec + info.ts.tv_usec*1e-6;
        double ival = flow ? time - flow->last_time : INFINITY;
        if (ival > max_ival) {
          if (!flow) flow = allocate(flow);
          flow->index = flow_index++;
          flow->last_time = -INFINITY;
          flow->last_seqno = 0;
          if (ival == INFINITY)
            g_hash_table_insert(flow_hash,copy(key),flow);

          char data[FLOW_RECORD_SIZE];
          *((u_int8_t  *) (data +  0)) = key.proto;
          *((u_int32_t *) (data +  1)) = key.src_ip;
          *((u_int32_t *) (data +  5)) = key.dst_ip;
          *((u_int16_t *) (data +  9)) = htons(key.src_port);
          *((u_int16_t *) (data + 11)) = htons(key.dst_port);
          if (fwrite(data,sizeof(data),1,flows) != 1)
            die("fwrite: %s\n",errstr);
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
                  // TODO: verify correctness of TCP app data logic.
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
        if (size < min_size)
          continue; // ignore packet

        char data[PACKET_RECORD_SIZE];
        *((u_int32_t *) (data +  0)) = htonl(flow->index);
        *((u_int32_t *) (data +  4)) = htonl(info.ts.tv_sec);
        *((u_int32_t *) (data +  8)) = htonl(info.ts.tv_usec);
        *((u_int16_t *) (data + 12)) = htons(size);
        if (fwrite(data,sizeof(data),1,packets) != 1)
          die("fwrite: %s\n",errstr);

        flow->last_time = time;
      }
    } else {
        die("pcap: %s\n",error);
    }
    fclose(file);
    wait(NULL);
  }
  return 0;
}
