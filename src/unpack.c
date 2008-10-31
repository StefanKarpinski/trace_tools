#include "common.h"

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
  u_int32_t offset = 0;

  // parse options, leave arguments
  int i;
  while ((i = getopt(argc,argv,"fptcF:o:")) != -1) {
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
    die("Please speficy input type: -f for flows or -p for packets.\n");
  if (format) {
    format = strdup(format);
    c_unescape(format);
  }
  
  switch (input) {
    case INPUT_FLOWS: {
      u_int32_t index = 0;
      if (optind == argc) argc++;
      for (i = optind; i < argc; i++) {
        FILE *file = open_arg(argv[i]);
        char data[FLOW_RECORD_SIZE];
        while (fread(data,sizeof(data),1,file) == 1) {
          u_int8_t  proto    =       *((u_int8_t  *) (data + 0));
          u_int32_t src_ip   =       *((u_int32_t *) (data + 1));
          u_int32_t dst_ip   =       *((u_int32_t *) (data + 5));
          u_int16_t src_port = ntohs(*((u_int16_t *) (data + 9)));
          u_int16_t dst_port = ntohs(*((u_int16_t *) (data + 11)));
          char src[MAX_IP_LENGTH+1], dst[MAX_IP_LENGTH+1];
          inet_ntop(AF_INET,&src_ip,src,sizeof(src));
          inet_ntop(AF_INET,&dst_ip,dst,sizeof(dst));
          if (!format) format =
            output == OUTPUT_TAB ? "%u\t%u\t%s\t%s\t%u\t%u\n" :
            output == OUTPUT_CSV ? "%u,%u,%s,%s,%u,%u\n" : NULL;
          printf(format,offset+index++,proto,src,dst,src_port,dst_port);
        }
        // TODO: detect trailing partial record.
        if (ferror(file))
          die("fread: %u\n",errno);
        fclose(file);
        wait(NULL);
      }
      break;
    }
    case INPUT_PACKETS:
      if (optind == argc) argc++;
      for (i = optind; i < argc; i++) {
        FILE *file = open_arg(argv[i]);
        char data[PACKET_RECORD_SIZE];
        while (fread(data,sizeof(data),1,file) == 1) {
          u_int32_t flow = ntohl(*((u_int32_t *) (data + 0)));
          u_int32_t sec  = ntohl(*((u_int32_t *) (data + 4)));
          u_int32_t usec = ntohl(*((u_int32_t *) (data + 8)));
          u_int16_t size = ntohs(*((u_int16_t *) (data + 12)));
          double time = sec + usec*1e-6;
          if (!format) format =
            output == OUTPUT_TAB ? "%u\t%18.6f\t%u\n" :
            output == OUTPUT_CSV ? "%u,%.6f,%u\n" : NULL;
          printf(format,offset+flow,time,size);
        }
        // TODO: detect trailing partial record.
        if (ferror(file))
          die("fread: %u\n",errno);
        fclose(file);
        wait(NULL);
      }
      break;
  }

  return 0;
}
