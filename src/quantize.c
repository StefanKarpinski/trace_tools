const char *usage =
  "Usage:\n"
  "  quantize [options] <data files>\n"
  "\n"
  "  Map numeric values to discrete indices from 0 to N-1.\n"
  "\n"
  "Options:\n"
  "  -n <integer>   Number of quanization bins (default: 100).\n"
  "  -m <float>     Input range minimum (default: 0).\n"
  "  -M <float>     Input range maximum.\n"
  "  -p <float>     Power transform parameter (default: 1).\n"
  "  -o <integer>   Output index offset (default: 0).\n"
  "\n"
;

#include "common.h"

int n = 0;
long double min = 0;
long double max = NAN;
int offset = 0;
double power = 1;

long long (*quantize)(long double) = NULL;

long long quantize_floor(long double);
long long quantize_power(long double);

void parse_opts(int argc, char **argv) {

  static struct option longopts[] = {
    { "bins",   required_argument, 0, 'n' },
    { "min",    required_argument, 0, 'm' },
    { "max",    required_argument, 0, 'M' },
    { "power",  required_argument, 0, 'p' },
    { "offset", required_argument, 0, 'o' },
    { "help",   no_argument,       0, 'h' },
    { 0, 0, 0, 0 }
  };

  int c;
  while ((c = getopt_long(argc,argv,"n:m:M:p:o:h",longopts,0)) != -1) {
    switch (c) {

      case 'n':
        n = atoi(optarg);
        if (n <= 0)
          die("Bin count must be positive.\n");
        break;
      case 'm':
        min = atof(optarg);
        break;
      case 'M':
        max = atof(optarg);
        break;
      case 'p':
        quantize = quantize_power;
        power = atof(optarg);
        break;
      case 'o':
        offset = atoi(optarg);
        break;

      case 'h':
        printf(usage);
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

  if (!quantize)
    quantize = n > 0 ? quantize_power : quantize_floor;

  if (quantize != quantize_floor) {
    if (!n)
      die("You must specify the number of quantization bins.\n");
    // TODO: better cross-platfrom finiteness test...
    if (max == NAN)
      die("You must specify finite min and max values.\n");
    if (min >= max)
      die("Min value must be strictly less than max value.\n");
  }
}

long long quantize_floor(long double v) {
  long long q = floorl(v);
  if (0 < n && n <= q)
    q = n-1;
  return q;
}

long long quantize_power(long double v) {
  long long q = floorl(n*powl((v-min)/(max-min),power));
  if (q >= n) q = n-1;
  if (q < 0) q = 0;
  return q;
}

int main(int argc, char **argv) {
  int i;
  parse_opts(argc,argv);
  if (optind == argc) argc++;
  for (i = optind; i < argc; i++) {
    FILE *file = open_arg(argv[i]);
    char *line;
    size_t length;
    while (line = fgetln(file,&length)) {
      for (;;) {
        int j, n = strcspn(line,"+-0123456789\n");
        for (j = 0; j < n; j++) putchar(*line++);
        if (*line == '\n' || *line == '\0') {
          if (*line) putchar('\n');
          break;
        }
        long double v = strtold(line,&line);
        long long q = quantize(v);
        printf("%lld",offset+q);
      }
    }
    fclose(file);
    wait(NULL);
  }
  return 0;
}
