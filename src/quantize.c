const char *usage =
  "Usage:\n"
  "  quantize [options] <data files>\n"
  "\n"
  "  Map numeric values to discrete indices from 1 to n.\n"
  "  Strictly, the range is [0+offset,n+offset-1] but the\n"
  "  offset value is 1 by default.\n"
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
double min = 0;
double max = NAN;
int log_transform = 0;
int offset = 1;
double power = 1;
double base = 10;

#define TRANS_QUANTIZE   0
#define TRANS_DEQUANTIZE 1
#define TRANS_FUZZ       2

int transform = TRANS_QUANTIZE;

int (*quantize)(double) = NULL;
double (*dequantize)(int) = NULL;

int quantize_floor(double);
int quantize_power(double);
int quantize_steplog(double);

double dequantize_floor(int);
double dequantize_power(int);
double dequantize_steplog(int);

unsigned seed = 0;

void parse_opts(int argc, char **argv) {

  static struct option longopts[] = {
    { "bins",       required_argument, 0, 'n' },
    { "min",        required_argument, 0, 'm' },
    { "max",        required_argument, 0, 'M' },
    { "power",      required_argument, 0, 'p' },
    { "log",        no_argument,       0, 'l' },
    { "steplog",    optional_argument, 0, 'L' },
    { "offset",     required_argument, 0, 'o' },
    { "dequantize", no_argument,       0, 'd' },
    { "fuzz",       no_argument,       0, 'f' },
    { "seed",       required_argument, 0, 's' },
    { "help",       no_argument,       0, 'h' },
    { 0, 0, 0, 0 }
  };

  int c;
  while ((c = getopt_long(argc,argv,"n:m:M:p:lL::o:dfs:h",longopts,0)) != -1) {
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
        dequantize = dequantize_power;
        power = atof(optarg);
        break;
      case 'l':
        log_transform = 1;
        break;
      case 'L':
        quantize = quantize_steplog;
        dequantize = dequantize_steplog;
        if (optarg)
          base = atof(optarg);
        break;
      case 'o':
        offset = atoi(optarg);
        break;

      case 'd':
        transform = TRANS_DEQUANTIZE;
        break;
      case 'f':
        transform = TRANS_FUZZ;
        break;
      case 's':
        seed = atol(optarg);
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

  if (!quantize) {
    if (n > 0) {
      quantize = quantize_power;
      dequantize = dequantize_power;
    } else {
      quantize = quantize_floor;
      dequantize = dequantize_floor;
    }
  }
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

  if (!seed) {
    srandomdev();
    seed = random();
  }
  srand48(seed);
}

int quantize_floor(double v) {
  return floor(v);
}

double dequantize_floor(int q) {
  return ((double) q) + drand48();
}

int quantize_power(double v) {
  if (log_transform) v = log(v);
  int q = floor(n*pow((v-min)/(max-min),power));
  if (q >= n) q = n-1;
  if (q < 0) q = 0;
  return q;
}

double dequantize_power(int q) {
  if (q >= n) q = n-1;
  if (q < 0) q = 0;
  double d = ((double) q) + drand48();
  double v = min+pow(d/n,1/power)*(max-min);
  if (log_transform) v = exp(v);
  return v;
}

int quantize_steplog(double v) {
  int m = floor(log(v)/log(base));
  int d = floor(v/pow(base,m));
  int q = m*(base-1)+d-1;
  return q;
}

double dequantize_steplog(int q) {
  die("Steplog dequantization not implemented.\n");
}

int main(int argc, char **argv) {
  int i;
  parse_opts(argc,argv);
  if (optind == argc) argc++;
  char *numerics = transform == TRANS_DEQUANTIZE ?
    "+-0123456789\n" : "+-0123456789.\n";

  for (i = optind; i < argc; i++) {
    FILE *file = open_arg(argv[i]);
    char *line, *buffer = NULL;
    size_t length;
    while (line = get_line(file,&buffer,&length)) {
      for (;;) {
        size_t j, n = strcspn(line,"+-0123456789.\n");
        for (j = 0; j < n; j++) putchar(*line++);
        if (*line == '\n' || *line == '\0') {
          if (*line) putchar('\n');
          break;
        }
        switch (transform) {
          case TRANS_QUANTIZE: {
            double v = strtod(line,&line);
            int q = quantize(v);
            printf("%d",q+offset);
            break;
          }
          case TRANS_DEQUANTIZE: {
            int q = strtol(line,&line,10);
            double v = dequantize(q-offset);
            printf("%0.7f",v);
            break;
          }
          case TRANS_FUZZ: {
            double v = strtod(line,&line);
            int q = quantize(v);
            double w = dequantize(q);
            printf("%0.7f",w);
            break;
          }
          default:
            die("ERROR: Invalid transform badness.\n");
        }
      }
    }
    fclose(file);
    wait(NULL);
  }
  return 0;
}
