const char *usage =
  "Usage:\n"
  "  stats [options] <packet files>\n"
  "  \n"
  "  Generates a CSV matrix of statistics about flows based\n"
  "  on their packet behavior, given in packet files. Each\n"
  "  output line contains the first P powersums of sizes and\n"
  "  inter-packet intervals:\n"
  "  \n"
  "Options:\n"
  "  -Z [<integer>]  Output N size powersums (default: 2).\n"
  "  -V [<integer>]  Output N interval powersums (default: 2).\n"
  "\n"
  "Notes:\n"
  "  The first column is always the packet count for a flow,\n"
  "  then size powersums followed by interval powersums.\n"
;

#include "common.h"

int size_max = 2;
int ival_max = 2;

char *delimiter = ",";

void parse_opts(int argc, char **argv) {

  static struct option longopts[] = {
    { "sizes",     required_argument, 0, 'Z' },
    { "intervals", required_argument, 0, 'V' },
    { "csv",       no_argument,       0, 'c' },
    { "tab",       no_argument,       0, 't' },
    { "delimiter", required_argument, 0, 'd' },
    { "help",      no_argument,       0, 'h' },
    { 0, 0, 0, 0 }
  };

  int c;
  while ((c = getopt_long(argc,argv,"Z::V::ctd:h",longopts,0)) != -1) {
    switch (c) {
      case 'Z':
        size_max = atoi(optarg);
        break;
      case 'V':
        ival_max = atoi(optarg);
        break;

      case 'c':
        delimiter = ",";
        break;
      case 't':
        delimiter = "\t";
        break;
      case 'd':
        delimiter = optarg;
        break;

      case 'h':
        printf(usage);
        return;
      case '?':
        if (isprint(optopt))
          die("Unknown option `-%c'.\n",optopt);
        else
          die("Strange option `\\x%x'.\n",optopt);
      default:
        die("getopt default.\n");
    }
  }
}

packet_record packet;
double packet_time;
uint last_flow = 0xffff;
double last_time = -INFINITY;

long long packets;
unsigned long long *size_ps;
long double *ival_ps;

#define power(x,y) (y==1 ? x : pow(x,y))

void update() {
  int i;
  packets++;
  for (i = 0; i < size_max; i++)
    size_ps[i] += power(packet.size,i+1);
  if (packet.flow != last_flow) return;
  double interval = packet_time - last_time;
  for (i = 0; i < ival_max; i++)
    ival_ps[i] += power(interval,i+1);
}

#define delim(more) (more ? delimiter : "")

void flush() {
  if (size_ps && ival_ps) {
    int i;
    printf("%llu%s",packets,delim(size_max || ival_max));
    for (i = 0; i < size_max; i++)
      printf("%llu%s",size_ps[i],delim(i+1 < size_max || ival_max));
    for (i = 0; i < ival_max; i++)
      printf("%Le%s",ival_ps[i],delim(i+1 < ival_max));
    printf("\n");

    memset(size_ps,0,size_max*sizeof(*size_ps));
    memset(ival_ps,0,ival_max*sizeof(*ival_ps));
  } else {
    size_ps = (typeof(size_ps)) calloc(size_max,sizeof(*size_ps));
    ival_ps = (typeof(ival_ps)) calloc(ival_max,sizeof(*ival_ps));
  }
  packets = 0;
}

int main(int argc, char ** argv) {
  parse_opts(argc,argv);
  if (optind == argc) argc++;
  int i;
  for (i = optind; i < argc; i++) {
    FILE *file = open_arg(argv[i]);

    while (read_packet(file,&packet)) {
      ntoh_packet(&packet);
      packet_time = packet.sec + packet.usec*1e-6;
      if (packet.flow != last_flow) flush();
      update();
      last_flow = packet.flow;
      last_time = packet_time;
    }
    flush();
    fclose(file);
    wait(NULL);
  }
  return 0;
}
