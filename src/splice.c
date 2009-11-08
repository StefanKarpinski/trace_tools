const char *usage =
  "Usage:\n"
  "  splice [-Z|-V] [options] <packet file> <values...>\n"
  "\n"
  "  Splice new packet size or inter-packet intervals into an\n"
  "  existing packet trace file. Modifies packet file in place.\n"
  "\n"
  "Options:\n"
  "  -Z            Splice in packet sizes.\n"
  "  -V            Splice in inter-packet intervals.\n"
  "\n"
;

#include <sys/stat.h>
#include <sys/mman.h>

#include "common.h"

int sizes = 0;
int intervals = 0;

void parse_opts(int argc, char **argv) {

  static struct option longopts[] = {
    { "sizes",     optional_argument, 0, 'Z' },
    { "intervals", optional_argument, 0, 'V' },
    { "help",      no_argument,       0, 'h' },
    { 0, 0, 0, 0 }
  };

  int c;
  while ((c = getopt_long(argc,argv,"ZVh",longopts,0)) != -1) {
    switch (c) {

      case 'Z':
        sizes = 1;
        break;
      case 'V':
        intervals = 1;
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
    die("You can enumerate sizes or intervals, not both.\n");
  if (!sizes && !intervals)
    die("You must choose to enumerate sizes or intervals.\n");

  if (!argv[optind])
    die("First argument must be a packets file.\n");
}

int main(int argc, char **argv) {
  parse_opts(argc,argv);
  if (optind == argc-1) argc++;
  int i = optind;

  char *packets_file = argv[i++];
  FILE *file = fopen(packets_file,"r+");
  if (!file)
    die("fopen(\"%s\",\"r\"): %s\n",packets_file,errstr);
  struct stat fs;
  fstat(fileno(file),&fs);
  u_int32_t n = fs.st_size / sizeof(packet_record);

  packet_record *packets = mmap(
    0,
    fs.st_size,
    PROT_READ | PROT_WRITE,
    MAP_SHARED,
    fileno(file),
    0
  );
  long long p = 0;

  while (i < argc) {
    FILE *values = open_arg(argv[i++]);
    char *line, *buffer = NULL;
    size_t length;
    if (sizes) {
      while (line = get_line(values,&buffer,&length)) {
        for (;;) {
          line += strcspn(line,"+-0123456789\n");
          if (*line == '\n' || *line == '\0') break;
          long z = strtol(line,&line,10);
          if (!z || z & 0xffff0000)
            die("Invalid packet size: %f\n",z);

          if (p >= n) goto too_many_values;
          packets[p++].size = htons((u_int16_t) z);
        }
      }
    }
    if (intervals) {
      long long flow = -1;
      double time = -INFINITY;
      while (line = get_line(values,&buffer,&length)) {
        for (;;) {
          if (flow != packets[p].flow) {
            time = ntohl(packets[p].sec) + ntohl(packets[p].usec)*1e-6;
            flow = packets[p].flow;
            p++;
          }

          line += strcspn(line,"+-0123456789.\n");
          if (*line == '\n' || *line == '\0') break;
          double v = strtod(line,&line);
          time += v;
          u_int32_t sec = (u_int32_t) floorl(time);
          u_int32_t usec = lroundl((time-sec)*1e6);

          if (p >= n) goto too_many_values;
          packets[p].sec  = htonl(sec);
          packets[p].usec = htonl(usec);
          p++;
        }
      }
    }
    fclose(values);
    wait(NULL);
  }
  if (p < n)
    die("Too few splice values.\n");

  munmap(packets,fs.st_size);
  fclose(file);
  return 0;

too_many_values:
  die("Too many splice values.\n");
}
