const char *usage =
  "Usage:\n"
  "  histogram -n<cols> [-i<inc>] <data files>\n"
  "\n"
  "  Take row-oriented integer data and construct histograms\n"
  "  out of the values observed.\n"
  "\n"
  "Options:\n"
  "  -n <integer>   The number of columns.\n"
  "  -o <integer>   Offset to subtract (default: 1).\n"
  "  -i <integer>   Per-item increment (default: 0).\n"
  "  -x <integer>   Set <n> to <x> times the <i> value.\n"
  "  -m             Map values to [0,n-1] by modulo operation.\n"
  "  -t             Map values to [0,n-1] by truncation.\n"
  "  -D             Print dimensions in last row (zero value).\n"
  "\n"
;

#include "common.h"

#define REDUCE_ERROR    0
#define REDUCE_MODULO   1
#define REDUCE_TRUNCATE 2

int n = 0;
int offset = 1;
int inc = 0;
int print_dims = 0;
int reduce = REDUCE_ERROR;

void parse_opts(int argc, char **argv) {

  static struct option longopts[] = {
    { "columns",    required_argument, 0, 'n' },
    { "offset",     required_argument, 0, 'o' },
    { "increment",  required_argument, 0, 'i' },
    { "iterate",    required_argument, 0, 'x' },
    { "modulo",     no_argument,       0, 'm' },
    { "truncate",   no_argument,       0, 't' },
    { "dimensions", no_argument,       0, 'D' },
    { "help",       no_argument,       0, 'h' },
    { 0, 0, 0, 0 }
  };

  int c;
  while ((c = getopt_long(argc,argv,"n:o:i:x:mtDh",longopts,0)) != -1) {
    switch (c) {

      case 'n':
        n = atoi(optarg);
        if (n <= 0)
          die("Column number must be positive.\n");
        break;
      case 'o':
        offset = atoi(optarg);
        break;
      case 'i':
        inc = atoi(optarg);
        break;
      case 'x':
        n = inc * atoi(optarg);
        break;
      case 'm':
        reduce = REDUCE_MODULO;
        break;
      case 't':
        reduce = REDUCE_TRUNCATE;
        break;
      case 'D':
        print_dims = 1;
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
  
  if (!n)
    die("You must specify column number.\n");
}

int main(int argc, char **argv) {
  int i;
  long long r = 0;
  parse_opts(argc,argv);
  if (optind == argc) argc++;
  long long *hist = calloc(sizeof(long long),n);
  for (i = optind; i < argc; i++) {
    FILE *file = open_arg(argv[i]);
    char *line, *buffer = NULL;
    size_t length;
    while (line = get_line(file,&buffer,&length)) {
      long long j = -offset;
      for (;;) {
        line += strcspn(line,"+-0123456789\n");
        if (*line == '\n' || *line == '\0') {
          int c;
          for (c = 0; c < n; c++)
            if (hist[c])
              printf("%llu,%u,%u\n",r+1,c+1,hist[c]);
          memset(hist,0,n*sizeof(*hist));
          break;
        }
        long long c = strtoll(line,&line,10);
        long long k = c + j;
        if (k < 0) {
          switch (reduce) {
            case REDUCE_MODULO:
              k = n - (-k % n);
              if (k == n) k = 0;
              break;
            case REDUCE_TRUNCATE:
              k = 0;
              break;
            default:
              die("Value too small: %lld = %lld + %lld.\n",k,c,j);
          }
        }
        else if (n <= k) {
          switch (reduce) {
            case REDUCE_MODULO:
              k = k % n;
              break;
            case REDUCE_TRUNCATE:
              k = n - 1;
              break;
            default:
              die("Value too large: %lld = %lld + %lld.\n",k,c,j);
          }
        }
        hist[k]++;
        j += inc;
      }
      r++;
    }
    if (print_dims)
      printf("%llu,%u,0\n",r,n);
    fclose(file);
    wait(NULL);
  }
  return 0;
}
