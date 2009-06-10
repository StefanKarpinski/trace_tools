const char *usage =
  "Usage:\n"
  "  quantize [options] <data files>\n"
  "\n"
  "  Map numeric values to discrete indices from 0 to N-1.\n"
  "\n"
  "Options:\n"
  "  -L [<float>]   Stepped log quantization (base <b>, default: 10).\n"
  "\n"
  "  -n <integer>   Number of quanization bins.\n"
  "  -m <float>     Input range minimum (default: 0).\n"
  "  -M <float>     Input range maximum.\n"
  "  -l             Apply logarithm before range mapping.\n"
  "  -p <float>     Power transform parameter (default: 1).\n"
  "\n"
  "  -o <integer>   Output index offset (default: 1).\n"
  "\n"
;

#include "common.h"

int n = 0;
long double min = 0;
long double max = NAN;
int log_transform = 0;
int offset = 1;
double power = 1;
double base = 10;

long long (*quantize)(double) = NULL;

long long quantize_floor(double);
long long quantize_power(double);
long long quantize_steplog(double);

void parse_opts(int argc, char **argv) {

  static struct option longopts[] = {
    { "bins",    required_argument, 0, 'n' },
    { "min",     required_argument, 0, 'm' },
    { "max",     required_argument, 0, 'M' },
    { "power",   required_argument, 0, 'p' },
    { "log",     no_argument,       0, 'l' },
    { "steplog", optional_argument, 0, 'L' },
    { "offset",  required_argument, 0, 'o' },
    { "help",    no_argument,       0, 'h' },
    { 0, 0, 0, 0 }
  };

  int c;
  while ((c = getopt_long(argc,argv,"n:m:M:p:lL::o:h",longopts,0)) != -1) {
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
      case 'l':
        log_transform = 1;
        break;
      case 'L':
        quantize = quantize_steplog;
        if (optarg)
          base = atof(optarg);
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

  if (quantize != quantize_power) return;

  if (!n)
    die("You must specify the number of quantization bins.\n");
  // TODO: better cross-platfrom finiteness test...
  if (max == NAN)
    die("You must specify finite min and max values.\n");
  if (min >= max)
    die("Min value must be strictly less than max value.\n");
  if (log_transform) {
    if (min <= 0)
      die("Min value must be positive for log transform.\n");
    min = log(min);
    max = log(max);
  }
}

long long quantize_floor(double v) {
  long long q = floorl(v);
  return q;
}

long long quantize_power(double v) {
  if (log_transform) v = log(v);
  long long q = floorl(n*powl((v-min)/(max-min),power));
  if (q >= n) q = n-1;
  if (q < 0) q = 0;
  return q;
}

long long quantize_steplog(double v) {
  long long m = floorl(log(v)/log(base));
  long long d = floorl(v/pow(base,m));
  long long q = m*(base-1)+d-1;
  return q;
}

int main(int argc, char **argv) {
  int i;
  parse_opts(argc,argv);
  if (optind == argc) argc++;
  for (i = optind; i < argc; i++) {
    FILE *file = open_arg(argv[i]);
    char *line, *buffer = NULL;
    size_t length;
    while (line = get_line(file,&buffer,&length)) {
      for (;;) {
        int j, n = strcspn(line,"+-0123456789\n");
        for (j = 0; j < n; j++) putchar(*line++);
        if (*line == '\n' || *line == '\0') {
          if (*line) putchar('\n');
          break;
        }
        double v = strtod(line,&line);
        long long q = quantize(v);
        printf("%lld",offset+q);
      }
    }
    fclose(file);
    wait(NULL);
  }
  return 0;
}
