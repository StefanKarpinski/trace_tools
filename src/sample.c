const char *usage =
  "Usage:\n"
  "  sample <values...>\n"
  "\n"
  "  Sample from delimted values on a line of input.\n"
  "  By default splits on comma or whitespace.\n"
  "\n"
  "Options:\n"
  "  -s <integer>    Random seed value.\n"
  "\n"
  "  -c              CSV.\n"
  "  -t              Tab-delimited output.\n"
  "  -d [<string>]   Delimit on custom chars.\n"
  "                  Without arg restores default.\n"
  "\n"
;

#include <stdlib.h>
#include <stdio.h>

#include "common.h"

char *const defsep = " ,\t\n";
char *const comma = ",\n";
char *const tab = "\t\n";

char *delimiters = NULL;

unsigned seed = 0;

void parse_opts(int argc, char **argv) {

  static struct option longopts[] = {
    { "seed",       required_argument, 0, 's' },
    { "csv",        no_argument,       0, 'c' },
    { "tab",        no_argument,       0, 't' },
    { "delimiters", required_argument, 0, 'd' },
    { "help",       no_argument,       0, 'h' },
    { 0, 0, 0, 0 }
  };

  int c;
  while ((c = getopt_long(argc,argv,"s:ctd:h",longopts,0)) != -1) {
    switch (c) {

      case 's':
        seed = atol(optarg);
        break;

      case 'c':
        delimiters = comma;
        break;
      case 't':
        delimiters = tab;
        break;
      case 'd':
        delimiters = optarg ? optarg : defsep;
        // TODO: ensure that \n is included!!!
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

  if (!delimiters) delimiters = defsep;
  if (!seed) {
    srandomdev();
    seed = random();
  }
  srand48(seed);
}

int main(int argc, char **argv) {
  parse_opts(argc,argv);
  if (optind == argc) argc++;
  int i = optind;

  size_t buffer_size = 4096;
  char **d = malloc(buffer_size*sizeof(char*));
  while (i < argc) {
    FILE *values = open_arg(argv[i++]);
    char *line, *buffer = NULL;
    size_t length;
    while (line = get_line(values,&buffer,&length)) {
      unsigned long j, k;
      d[0] = line-1;
      for (j = 1;; j++) {
        if (j >= buffer_size) {
          buffer_size *= 2;
          d = (char**) realloc(d,buffer_size*sizeof(char*));
        }
        char *p = d[j-1]+1;
        d[j] = p + strcspn(p,delimiters);
        if (*d[j] == '\n' || *d[j] == '\0') break;
      }
      for (k = 1; k <= j; k++) {
        unsigned long l = (unsigned long) floor(j*drand48());
        fwrite(d[l]+1, d[l+1]-d[l]-1, 1, stdout);
        if (*d[k]) putchar(*d[k]);
      }
    }
    fclose(values);
    wait(NULL);
  }

  return 0;
}
