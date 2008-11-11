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
  u_int8_t  input   = INPUT_UNKNOWN;
  u_int8_t  output  = OUTPUT_TAB;
  char     *prefix  = NULL;
  char     *format  = NULL;
  char     *unknown = "";
  u_int32_t offset  = 0;

  // parse options, leave arguments
  int i;
  while ((i = getopt(argc,argv,"fptcP:u:F:o:")) != -1) {
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
      case 'P':
        prefix = optarg;
        break;
      case 'u':
        unknown = optarg;
        break;
      case 'F':
        format = optarg;
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
  if (prefix && !format) {
    char *p = prefix;
    int len = strlen(p);
    prefix = malloc(len+2);
    strcpy(prefix,p);
    prefix[len] =
      output == OUTPUT_TAB ? '\t' :
      output == OUTPUT_CSV ? ','  : '\0';
    prefix[len+1] = '\0';
  }
  if (format) {
    format = strdup(format);
    c_unescape(format);
  }

  if (optind == argc) argc++;
  for (i = optind; i < argc; i++) {
    FILE *file = open_arg(argv[i]);
    if (input == INPUT_UNKNOWN) {
      char c = fgetc(file);
      input = c ? INPUT_FLOWS : INPUT_PACKETS;
      ungetc(c,file);
    }
    if (!format) {
      switch (input) {
        case INPUT_FLOWS:
          format =
            output == OUTPUT_TAB ? "%s%u\t%u\t%s\t%s\t%u\t%u\t%s\t%s\n" :
            output == OUTPUT_CSV ? "%s%u,%u,%s,%s,%u,%u,%s,%s\n" : NULL;
          break;
        case INPUT_PACKETS:
          format =
            output == OUTPUT_TAB ? "%s%u\t%u.%06u\t%u\n" :
            output == OUTPUT_CSV ? "%s%u,%u.%06u,%u\n" : NULL;
          break;
      }
    }
    switch (input) {
      case INPUT_FLOWS: {
        u_int32_t index = 0;
        flow_record flow;
        while (read_flow(file,&flow)) {
          ntoh_flow(&flow);
          char src[MAX_IP_LENGTH+1], dst[MAX_IP_LENGTH+1];
          inet_ntop(AF_INET,&flow.src_ip,src,sizeof(src));
          inet_ntop(AF_INET,&flow.dst_ip,dst,sizeof(dst));
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
            prefix ? prefix : "",
            offset+index++,
            flow.proto,
            src, dst,
            flow.src_port,
            flow.dst_port,
            proto_str ? proto_str : unknown,
            desc ? desc : unknown
          );
        }
        break;
      }
      case INPUT_PACKETS: {
        packet_record packet;
        while (read_packet(file,&packet)) {
          ntoh_packet(&packet);
          printf(format,
            prefix ? prefix : "",
            offset+packet.flow,
            packet.sec,
            packet.usec,
            packet.size
          );
        }
        break;
      }
    }
    fclose(file);
    wait(NULL);
  }

  return 0;
}
