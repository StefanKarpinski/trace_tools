const char *usage =
  "Usage:\n"
  "\n"
;

#include "common.h"

int n = 0;
int inc = 0;

void parse_opts(int argc, char **argv) {

  static struct option longopts[] = {
    { "columns",   required_argument, 0, 'n' },
    { "increment", required_argument, 0, 'i' },
    { "help",      no_argument,       0, 'h' },
    { 0, 0, 0, 0 }
  };

  int c;
  while ((c = getopt_long(argc,argv,"n:i:h",longopts,0)) != -1) {
    switch (c) {

      case 'n':
        n = atoi(optarg);
        if (n <= 0)
          die("Column number must be positive.\n");
        break;
      case 'i':
        inc = atoi(optarg);
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
    char *line;
    size_t length;
    while (line = fgetln(file,&length)) {
      int offset = 0;
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
        hist[(offset + c) % n]++;
        offset += inc;
      }
      r++;
    }
    fclose(file);
    wait(NULL);
  }
  return 0;
}
