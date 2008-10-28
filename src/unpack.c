#include "common.h"

// intput types

#define INPUT_UNKNOWN 0
#define INPUT_FLOWS   1
#define INPUT_PACKETS 2

// output styles

#define OUTPUT_TAB 0
#define OUTPUT_CSV 1
#define OUTPUT_BIN 2

// main processing loop

int main(int argc, char ** argv) {

  // option variables
  u_int8_t input = INPUT_UNKNOWN;
  u_int8_t output = OUTPUT_TAB;

  // parse options, leave arguments
  int i;
  while ((i = getopt(argc,argv,"fptc")) != -1) {
    switch (i) {

      case 'f':
        input = INPUT_FLOWS;
        break;
      case 'p':
        input = INPUT_PACKETS;
        break;

      case 't':
        output = OUTPUT_TAB;
        break;
      case 'c':
        output = OUTPUT_CSV;
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
    die("Please speficy input type: -f for flows or -p for packets.\n");
  
  switch (input) {
    case INPUT_FLOWS: {
      for (i = optind; i < argc; i++) {
        FILE *file = open_arg(argv[i]);
        char data[FLOW_RECORD_SIZE];
        while (fread(data,sizeof(data),1,file) == 1) {
          u_int32_t flow_id  = ntohl(*((u_int32_t *) (data + 0)));
          u_int8_t  proto    = *((u_int8_t  *) (data + 4));
          u_int32_t src_ip   = *((u_int32_t *) (data + 5));
          u_int32_t dst_ip   = *((u_int32_t *) (data + 9));
          u_int16_t src_port = ntohs(*((u_int16_t *) (data + 13)));
          u_int16_t dst_port = ntohs(*((u_int16_t *) (data + 15)));
          char src[MAX_IP_LENGTH+1], dst[MAX_IP_LENGTH+1];
          inet_ntop(AF_INET,&src_ip,src,sizeof(src));
          inet_ntop(AF_INET,&dst_ip,dst,sizeof(dst));
          char *format =
            output == OUTPUT_TAB ? "%u\t%u\t%s\t%s\t%u\t%u\n" :
            output == OUTPUT_CSV ? "%u,%u,%s,%s,%u,%u\n" : NULL;
          printf(format,flow_id,proto,src,dst,src_port,dst_port);
        }
        // TODO: detect trailing partial record.
        if (ferror(file))
          die("fread: %u\n",errno);
      }
      break;
    }
    case INPUT_PACKETS:
      for (i = optind; i < argc; i++) {
        FILE *file = open_arg(argv[i]);
        char data[PACKET_RECORD_SIZE];
        while (fread(data,sizeof(data),1,file) == 1) {
          u_int32_t flow_id = ntohl(*((u_int32_t *) (data + 0)));
          u_int32_t sec     = ntohl(*((u_int32_t *) (data + 4)));
          u_int32_t usec    = ntohl(*((u_int32_t *) (data + 8)));
          double    ival    = *((double *) (data + 12));
          u_int16_t size    = ntohs(*((u_int16_t *) (data + 20)));
          double time = sec + usec*1e-6;
          switch (output) {
            case OUTPUT_TAB:
              printf("%u\t%18.6f\t%10.6f\t%u\n", flow_id, time, ival, size);
              break;
            case OUTPUT_CSV: {
              char buf[256];
              if (ival == INFINITY) *buf = '\0';
              else snprintf(buf,sizeof(buf),"%.6f",ival);
              printf("%u,%.6f,%s,%u\n", flow_id, time, buf, size);
              break;
            }
          }
        }
        // TODO: detect trailing partial record.
        if (ferror(file))
          die("fread: %u\n",errno);
      }
      break;
  }

  return 0;
}
