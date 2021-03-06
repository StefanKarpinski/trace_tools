const char *usage =
  "Usage:\n"
  "  stats [options] <packet files>\n"
  "\n"
  "  Generates a CSV matrix of statistics about flows based\n"
  "  on their packet behavior, given in packet files. The\n"
  "  first column is the packet count for a flow; then size\n"
  "  powersums followed by interval powersums.\n"
  "\n"
  "Options:\n"
  "  -Z <integer>   Maximum size powersum (default: 2).\n"
  "  -V <integer>   Maximum interval powersum (default: 2).\n"
  "  -N <integer>   Shortcut for -Z<N> -V<N>.\n"
  "\n"
  "  -m <integer>   Only output flows with minimum packets.\n"
  "\n"
  "  -I             Print flow indices.\n"
  "  -R             Reindex flows (imples -I).\n"
  "  -o <integer>   Flow index offset (default: 0).\n"
  "\n"
  "  -c             CSV output.\n"
  "  -t             Tab-delimited output.\n"
  "  -d <string>    Custom-delimited output.\n"
  "\n"
;

#include "common.h"

int size_ps_max = 2;
int ival_ps_max = 2;

int min_packets = 1;

int indices = 0;
int reindex = 0;
int offset  = 0;

char *const comma = ",";
char *const tab = "\t";

char *delimiter;

void parse_opts(int argc, char **argv) {

  delimiter = comma;

  static struct option longopts[] = {
    { "sizes",       required_argument, 0, 'Z' },
    { "intervals",   required_argument, 0, 'V' },
    { "number",      required_argument, 0, 'N' },
    { "min-packets", required_argument, 0, 'm' },
    { "indices",     no_argument,       0, 'I' },
    { "reindex",     no_argument,       0, 'R' },
    { "offset",      required_argument, 0, 'o' },
    { "csv",         no_argument,       0, 'c' },
    { "tab",         no_argument,       0, 't' },
    { "delimiter",   required_argument, 0, 'd' },
    { "help",        no_argument,       0, 'h' },
    { 0, 0, 0, 0 }
  };

  int c;
  while ((c = getopt_long(argc,argv,"Z:V:N:m:IRo:ctd:h",longopts,0)) != -1) {
    switch (c) {
      case 'Z':
        size_ps_max = atoi(optarg);
        break;
      case 'V':
        ival_ps_max = atoi(optarg);
        break;
      case 'N':
        size_ps_max = ival_ps_max = atoi(optarg);
        break;

      case 'm':
        min_packets = atoi(optarg);
        break;

      case 'I':
        indices = 1;
        break;
      case 'R':
        indices = 1;
        reindex = 1;
        break;
      case 'o':
        offset = atoi(optarg);
        break;

      case 'c':
        delimiter = comma;
        break;
      case 't':
        delimiter = tab;
        break;
      case 'd':
        delimiter = optarg;
        break;

      case 'h':
        printf("%s",usage);
        exit(0);

      case '?':
        if (isprint(optopt))
          die("Unknown option `-%c'.\n",optopt);
        else
          die("Strange option `\\x%x'.\n",optopt);

      default:
        die("ERROR: getopt badness.\n");
    }
  }
}

packet_record packet;
double packet_time;
long long last_flow = -1;
double last_time = -INFINITY;

long long packets, flow;
long double *size_ps;
long double *ival_ps;

void update() {
  int i;
  packets++;
  for (i = 0; i < size_ps_max; i++)
    size_ps[i] += powl(packet.size,i+1);
  if (packet.flow != last_flow) return;
  double interval = packet_time - last_time;
  for (i = 0; i < ival_ps_max; i++)
    ival_ps[i] += powl(interval,i+1);
}

#define delim(more) (more ? delimiter : "")

void flush() {
  if (size_ps && ival_ps) {
    if (packets >= min_packets) {
      int i;
      if (indices)
        printf("%lld%s",offset + (reindex ? flow++ : packet.flow),delim(1));
      printf("%llu%s",packets,delim(size_ps_max || ival_ps_max));
      for (i = 0; i < size_ps_max; i++)
        printf("%Le%s",size_ps[i],delim(i+1 < size_ps_max || ival_ps_max));
      for (i = 0; i < ival_ps_max; i++)
        printf("%Le%s",ival_ps[i],delim(i+1 < ival_ps_max));
      printf("\n");
    }
    memset(size_ps,0,size_ps_max*sizeof(*size_ps));
    memset(ival_ps,0,ival_ps_max*sizeof(*ival_ps));
  } else {
    size_ps = (typeof(size_ps)) calloc(size_ps_max,sizeof(*size_ps));
    ival_ps = (typeof(ival_ps)) calloc(ival_ps_max,sizeof(*ival_ps));
  }
  packets = 0;
}

int main(int argc, char **argv) {
  int i;
  parse_opts(argc,argv);
  if (optind == argc) argc++;
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
