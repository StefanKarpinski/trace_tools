const char *usage =
  "Usage:\n"
  "  enumerate [-Z|-V] [options] <packet files>\n"
  "\n"
  "  Prints a list of values for each flow; either packet\n"
  "  sizes or inter-packet intervals, for a given number\n"
  "  of initial packets, or all packets if N = zero or no\n"
  "  value is given.\n"
  "\n"
  "Options:\n"
  "  -Z [<integer>]  Output sizes of first N packets.\n"
  "  -V [<integer>]  Output intervals between first N packets.\n"
  "\n"
  "  -c              CSV output (default).\n"
  "  -t              Tab-delimited output.\n"
  "  -d <string>     Custom-delimited output.\n"
  "\n"
;

#include "common.h"

int sizes = 0;
int intervals = 0;
int packets = 0;

char *const comma = ",";
char *const tab = "\t";

char *delimiter;

void parse_opts(int argc, char **argv) {

  delimiter = comma;

  static struct option longopts[] = {
    { "sizes",     optional_argument, 0, 'Z' },
    { "intervals", optional_argument, 0, 'V' },
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
        sizes = 1;
        if (optarg)
          packets = atoi(optarg);
        break;
      case 'V':
        intervals = 1;
        if (optarg)
          packets = atoi(optarg);
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

  if (sizes && intervals)
    die("You must choose to enumerate sizes or intervals.\n");
  if (!sizes && !intervals)
    die("You can enumerate sizes or intervals, not both.\n");
}

int main(int argc, char **argv) {
  int i;
  parse_opts(argc,argv);
  if (optind == argc) argc++;
  for (i = optind; i < argc; i++) {
    FILE *file = open_arg(argv[i]);

    int packet_no;
    packet_record packet;
    long long last_flow = -1;
    double last_time = -INFINITY;

    while (read_packet(file,&packet)) {
      ntoh_packet(&packet);
      if (packet.flow != last_flow) packet_no = 0;
      packet_no++;
      if (!packets || packet_no <= packets) {
        if (sizes) {
          if (last_flow >= 0)
            printf("%s", packet.flow != last_flow ? "\n" : delimiter);
          printf("%hu",packet.size);
        } else if (intervals) {
          double time = packet.sec + packet.usec*1e-6;
          if (packet.flow != last_flow) {
            if (last_flow >= 0) putchar('\n');
          } else {
            if (packet_no > 2) printf("%s", delimiter);
            printf("%e", time - last_time);
          }
          last_time = time;
        }
      }
      last_flow = packet.flow;
    }
    putchar('\n');

    fclose(file);
    wait(NULL);
  }
  return 0;
}
