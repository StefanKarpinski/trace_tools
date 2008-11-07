#include "common.h"
#include "flow_desc.h"

// intput types

#define INPUT_UNKNOWN 0
#define INPUT_FLOWS   1
#define INPUT_PACKETS 2

// output styles

#define OUTPUT_TAB 0
#define OUTPUT_CSV 1

// main processing loop

int main(int argc, char ** argv) {

  // option variables
  u_int8_t  input  = INPUT_UNKNOWN;
  u_int8_t  output = OUTPUT_TAB;
  char     *format = NULL;
  u_int8_t  header = 0;
  u_int32_t offset = 0;

  // parse options, leave arguments
  int i;
  while ((i = getopt(argc,argv,"fptcF:ho:")) != -1) {
    switch (i) {

      case 'f':
        input = INPUT_FLOWS;
        break;
      case 'p':
        input = INPUT_PACKETS;
        break;

      case 't':
        output = OUTPUT_TAB;
        format = NULL;
        break;
      case 'c':
        output = OUTPUT_CSV;
        format = NULL;
        break;
      case 'F':
        format = optarg;
        break;
      case 'h':
        header = 1;
        break;

      case 'o':
        offset = atoi(optarg);
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
  if (input == INPUT_UNKNOWN)
    die("Please specify input type: -f for flows or -p for packets.\n");
  if (format) {
    if (header)
      die("You cannot use a custom format (-F) and output a header (-h).\n");
    format = strdup(format);
    c_unescape(format);
  }
  
  switch (input) {
    case INPUT_FLOWS: {
      if (header) {
        puts(
          output == OUTPUT_TAB ? "flow\tproto\tsrc_ip\t\tdst_ip\t\tsport\tdport,..." :
          output == OUTPUT_CSV ? "flow,proto,src_ip,dst_ip,sport,dport,..." : NULL
        );
      }
      u_int32_t index = 0;
      if (optind == argc) argc++;
      for (i = optind; i < argc; i++) {
        FILE *file = open_arg(argv[i]);
        flow_record flow;
        while (read_flow(file,&flow)) {
          ntoh_flow(&flow);
          char src[MAX_IP_LENGTH+1], dst[MAX_IP_LENGTH+1];
          inet_ntop(AF_INET,&flow.src_ip,src,sizeof(src));
          inet_ntop(AF_INET,&flow.dst_ip,dst,sizeof(dst));
          if (!format) format =
            output == OUTPUT_TAB ? "%u\t%u\t%s\t%s\t%u\t%u\t%s\t%s\n" :
            output == OUTPUT_CSV ? "%u,%u,%s,%s,%u,%u,%s,%s\n" : NULL;
          char *proto_str = proto_name(flow.proto);
          char *desc = NULL;
          switch (flow.proto) {
            case IP_PROTO_ICMP: {
              u_int8_t tyco = ntohs(flow.dst_port);
              desc = icmp_desc(tyco >> 8,tyco & 0xff);
              break;
            }
            case IP_PROTO_TCP:
            case IP_PROTO_UDP:
              desc = pair_desc(flow.proto,flow.src_port,flow.dst_port);
              break;
          }
          printf(format,
            offset+index++,
            flow.proto,
            src, dst,
            flow.src_port,
            flow.dst_port,
            proto_str ? proto_str : "",
            desc ? desc : ""
          );
        }
        fclose(file);
        wait(NULL);
      }
      break;
    }
    case INPUT_PACKETS:
      if (header) {
        puts(
          output == OUTPUT_TAB ? "flow\ttime\t\t\tsize" :
          output == OUTPUT_CSV ? "flow,time,size" : NULL
        );
      }
      if (optind == argc) argc++;
      for (i = optind; i < argc; i++) {
        FILE *file = open_arg(argv[i]);
        packet_record packet;
        while (read_packet(file,&packet)) {
          ntoh_packet(&packet);
          double time = packet.sec + packet.usec*1e-6;
          if (!format) format =
            output == OUTPUT_TAB ? "%u\t%17.6f\t%u\n" :
            output == OUTPUT_CSV ? "%u,%.6f,%u\n" : NULL;
          printf(format,offset+packet.flow,time,packet.size);
        }
        fclose(file);
        wait(NULL);
      }
      break;
  }

  return 0;
}
