const char *usage =
  "Usage:\n"
  "  quantize [options] <data files>\n"
  "\n"
  "  Map field values onto discrete indices from 1 to N.\n"
  "\n"
  "Options:\n"
  "  -f <integer>   Field number to quantize.\n"
  "  -c             CSV data (default).\n"
  "  -t             Tab-delimited data.\n"
  "\n"
  "  -n <integer>   Number of quanization bins (default: 100).\n"
  "\n"
  "  -f             Floor quantization.\n"
  "  -r <float>     Radical quantization.\n"
  "  -l             Logarithmic quantization.\n"
  "\n"
;

#include "common.h"

int field = 1;

char *const comma = ",";
char *const tab = "\t";

char *delimiter;

int n = 0;
long double min = NAN;
long double max = NAN;
int offset = 1;
double power = 1;

long long (*quantize)(long double) = NULL;

long long quantize_floor(long double);
long long quantize_power(long double);
long long quantize_log(long double);

void parse_opts(int argc, char **argv) {

  delimiter = comma;

  static struct option longopts[] = {
    { "field",  required_argument, 0, 'f' },
    { "csv",    no_argument,       0, 'c' },
    { "tab",    no_argument,       0, 't' },
    { "bins",   required_argument, 0, 'n' },
    { "min",    required_argument, 0, 'a' },
    { "max",    required_argument, 0, 'b' },
    { "offset", required_argument, 0, 'o' },
    { "power",  required_argument, 0, 'p' },
    { "log",    no_argument,       0, 'g' },
    { "help",   no_argument,       0, 'h' },
    { 0, 0, 0, 0 }
  };

  int c;
  while ((c = getopt_long(argc,argv,"f:ctn:o:a:b:fp:lh",longopts,0)) != -1) {
    switch (c) {
      case 'f':
        field = atoi(optarg);
        if (field <= 0)
          die("Field number must be positive.\n");
        break;
      case 'c':
        delimiter = comma;
        break;
      case 't':
        delimiter = tab;
        break;

      case 'n':
        n = atoi(optarg);
        if (n <= 0)
          die("Bin count must be positive.\n");
        break;
      case 'o':
        offset = atoi(optarg);
        break;
      case 'a':
        min = atof(optarg);
        break;
      case 'b':
        max = atof(optarg);
        break;

      case 'p':
        power = atof(optarg);
        quantize = quantize_power;
        break;
      case 'l':
        quantize = quantize_log;
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
    quantize = n || isfinite(min) || isfinite(max) ?
      quantize_power : quantize_floor;

  if (quantize != quantize_floor) {
    if (!n)
      die("You must specify the number of quantization bins.\n");
    if (!isfinite(min) || !isfinite(max))
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

long long quantize_log(long double v) {
  return lroundl(v);
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
      int f;
      char *a = line, *b = line + length, *p;
      for (f = 1; f < field && a != NULL + 1 && a < b; f++)
        a = strpbrk(a,delimiter) + 1;
      if (a == NULL + 1 || a >= b) {
        for (p = line; p < line + length; p++) putchar(*p);
        continue;
      }
      b = strpbrk(a,delimiter);
      if (b == NULL)
        b = line + length;

      long double v = strtold(a,&b);
      long long q = quantize(v);

      for (p = line; p < a; p++) putchar(*p);
      printf("%lld",offset+q);
      for (p = b; p < line + length; p++) putchar(*p);
    }
    fclose(file);
    wait(NULL);
  }
  return 0;
}
