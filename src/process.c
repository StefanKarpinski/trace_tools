const char *usage =
  "Usage:\n"
  "  process [options] -f <flow file> -p <packet file> <trace files>\n"
  "\n"
  "  Parses PCAP trace files (plain, gzipped or bzipped, detected by\n"
  "  extension) and reads the packet header data in them, producing\n"
  "  a flow file and a packet file for the trace data it reads.\n"
  "\n"
  "Options:\n"
  "  -F <string>   BPF filter expression for trace files\n"
  "\n"
  "  -s <integer>  Minimum packet size (default: 1)\n"
  "  -i <float>    Maximum inter-packet interval (default: infinity)\n"
  "\n"
  "  -P            Output raw packet sizes (default)\n"
  "  -I            Output IP payload sizes\n"
  "  -T            Output transport (TCP/UDP) payload size\n"
  "  -A            Output application data size\n"
  "\n"
  "Notes:\n"
  "  - Flow and packet outputs are packed arrays of fixed-size records.\n"
  "    All record members are stored in portable network byte-order.\n"
  "  - Flow records are packed structs with these members:\n"
  "      u_int8_t  proto;\n"
  "      u_int32_t src_ip, dst_ip;\n"
  "      u_int16_t src_port, dst_port;\n"
  "    Flows are implicitly indexed by their order of appearance in the\n"
  "    flow files, starting at zero.\n"
  "  - Packet records are packed structs with these members:\n"
  "      u_int32_t flow, sec, usec;\n"
  "      u_int16_t size;\n"
  "    The flow number is a zero-based index into the corresponding flow\n"
  "    file; the sec and usec numbers are the seconds and microseconds\n"
  "    since the epoch. The size is a number of bytes, with meaning that\n"
  "    depends on which of the flags [PITA] was given.\n"
  "  - Packets smaller than the minimum packet size are ignored.\n"
  "  - Intervals larger than the maximum interval force further packets\n"
  "    to be considered to belong to a new flow.\n"
;

#include "common.h"

// flow data structures

typedef struct {
  u_int32_t index;
  double    last_time;
  u_int32_t last_seqno;
} flow_data;

// flow hashing functions

guint flow_hashf(gconstpointer a) {
  flow_record *f = (flow_record *) a;
  guint32 h = f->proto;
  h = (h<<5)-h + f->src_ip;
  h = (h<<5)-h + f->src_port;
  h = (h<<5)-h + f->dst_ip;
  h = (h<<5)-h + f->dst_port;
  return h;
}        
         
gint flow_equal(gconstpointer a, gconstpointer b) {
  flow_record *x = (flow_record *) a;
  flow_record *y = (flow_record *) b;
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

#define SRC_PORT_RAW(ip) (*((u_int16_t*)(((char*)ip)+IP4_HEADER_UNIT*IP_HL(ip)+0)))
#define DST_PORT_RAW(ip) (*((u_int16_t*)(((char*)ip)+IP4_HEADER_UNIT*IP_HL(ip)+2)))
#define UDP_SIZE_RAW(ip) (*((u_int16_t*)(((char*)ip)+IP4_HEADER_UNIT*IP_HL(ip)+4)))
#define UDP_CKSM_RAW(ip) (*((u_int16_t*)(((char*)ip)+IP4_HEADER_UNIT*IP_HL(ip)+6)))
#define TCP_SQNO_RAW(ip) (*((u_int32_t*)(((char*)ip)+IP4_HEADER_UNIT*IP_HL(ip)+4)))
#define TCP_AKNO_RAW(ip) (*((u_int32_t*)(((char*)ip)+IP4_HEADER_UNIT*IP_HL(ip)+8)))

#define SRC_PORT(ip) ntohs(SRC_PORT_RAW(ip))
#define DST_PORT(ip) ntohs(DST_PORT_RAW(ip))
#define UDP_SIZE(ip) ntohs(UDP_SIZE_RAW(ip))
#define UDP_CKSM(ip) ntohs(UDP_CKSM_RAW(ip))
#define TCP_SQNO(ip) ntohl(TCP_SQNO_RAW(ip))
#define TCP_AKNO(ip) ntohl(TCP_AKNO_RAW(ip))

#define ICMP_TYPE_RAW(ip) (*(((char*)ip)+IP4_HEADER_UNIT*IP_HL(ip)+0))
#define ICMP_CODE_RAW(ip) (*(((char*)ip)+IP4_HEADER_UNIT*IP_HL(ip)+1))
#define ICMP_TYCO_RAW(ip) (*((u_int16_t*)(((char*)ip)+IP4_HEADER_UNIT*IP_HL(ip)+0)))
#define ICMP_CKSM_RAW(ip) (*((u_int16_t*)(((char*)ip)+IP4_HEADER_UNIT*IP_HL(ip)+2)))
#define ICMP_IDNO_RAW(ip) (*((u_int16_t*)(((char*)ip)+IP4_HEADER_UNIT*IP_HL(ip)+4)))
#define ICMP_SQNO_RAW(ip) (*((u_int16_t*)(((char*)ip)+IP4_HEADER_UNIT*IP_HL(ip)+6)))

#define ICMP_TYPE(ip) ICMP_TYPE_RAW(ip)
#define ICMP_CODE(ip) ICMP_CODE_RAW(ip)
#define ICMP_TYCO(ip) ntohs(ICMP_TYCO_RAW(ip))
#define ICMP_CKSM(ip) ntohs(ICMP_CKSM_RAW(ip))
#define ICMP_IDNO(ip) ntohs(ICMP_IDNO_RAW(ip))
#define ICMP_SQNO(ip) ntohs(ICMP_SQNO_RAW(ip))

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
  char *flow_file = NULL;
  char *packet_file = NULL;

  char *filter = NULL;
  u_int16_t min_size = 1;
  double max_ival = INFINITY;
  u_int8_t size_type = SIZE_PACKET;

  // parse options, leave arguments
  int i;
  while ((i = getopt(argc,argv,"f:p:F:s:i:PITAh")) != -1) {
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

      case 'h':
        printf(usage);
        return 0;
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
    die("Please specify a flow file using -f <file>.\n");
  if (!packet_file)
    die("Please specify a packet file using -p <file>.\n");
  
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
      int datalink_type = pcap_datalink(pcap);
      while (pkt = pcap_next(pcap,&info)) {
        struct ip *ip;
        switch (datalink_type) {
          case DLT_RAW: {
            ip = (struct ip *) pkt;
            break;
          }
          case DLT_EN10MB: {
            struct ether_header *eth = (struct ether_header *) pkt;
            if (eth->ether_type != ETHERTYPE_IP) continue;
            ip = (struct ip *) (pkt + sizeof(*eth));
            break;
          }
          // NOTE: to support a new datalink type, just add a case
          // here that correctly extracts the IP pointer from it.
          default:
            die("Trace unsupported data link type %d (%s: %s).\n",
              datalink_type,
              pcap_datalink_val_to_name(datalink_type),
              pcap_datalink_val_to_description(datalink_type)
            );
        }
        
        flow_record flow;
        flow.proto  = ip->ip_p;
        flow.src_ip = ip->ip_src.s_addr;
        flow.dst_ip = ip->ip_dst.s_addr;
        if (HAS_PORT(ip)) {
          flow.src_port = SRC_PORT_RAW(ip);
          flow.dst_port = DST_PORT_RAW(ip);
        } else {
          flow.src_port = ICMP_TYCO_RAW(ip); // ICMP_IDNO_RAW(ip);
          flow.dst_port = ICMP_TYCO_RAW(ip);
        }

        flow_data *fd = g_hash_table_lookup(flow_hash,&flow);
        double time = info.ts.tv_sec + info.ts.tv_usec*1e-6;
        double ival = fd ? time - fd->last_time : INFINITY;
        if (!fd || ival > max_ival) {
          if (!fd) fd = allocate(fd);
          fd->index = flow_index++;
          fd->last_time = -INFINITY;
          fd->last_seqno = 0;
          if (ival == INFINITY)
            g_hash_table_insert(flow_hash,copy(flow),fd);
          write_flow(flows,&flow);
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
                struct tcphdr *tcp = (struct tcphdr *) (ip + IP4_HEADER_UNIT * IP_HL(ip));
                size = IP4_SIZE(ip) - IP4_HEADER_UNIT * (IP_HL(ip) + TH_OFF(tcp));
                if (size_type == SIZE_APPLICATION_DATA) {
                  // TODO: verify correctness of TCP app data logic.
                  u_int32_t last_byte_seqno = ntohl(tcp->th_seq) + size;
                  if (!(tcp->th_flags & (TH_SYN|TH_FIN|TH_RST))) last_byte_seqno--;
                  if (fd->last_time < 0) {
                    fd->last_seqno = last_byte_seqno;
                  } else // regular follow-up packet
                  if (size + TCP_MAX_SKIP >= last_byte_seqno - fd->last_seqno) {
                    size = last_byte_seqno - fd->last_seqno;
                    fd->last_seqno = last_byte_seqno;
                  } else // possible seqno wrap-around
                  if (size + TCP_MAX_SKIP >= last_byte_seqno + abs(fd->last_seqno)) {
                    // FIXME: this seems questionable.
                    size = last_byte_seqno + abs(fd->last_seqno);
                    fd->last_seqno = last_byte_seqno;
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

        packet_record packet = {
          fd->index, info.ts.tv_sec, info.ts.tv_usec, size
        };
        if (packet.usec >= 1000000) {
          packet.sec += packet.usec / 1000000;
          packet.usec = packet.usec % 1000000;
        }
        hton_packet(&packet);
        write_packet(packets,&packet);

        fd->last_time = time;
      }
    } else {
        die("pcap: %s\n",error);
    }
    fclose(file);
    wait(NULL);
  }
  return 0;
}
