#include <sys/stat.h>
#include <sys/mman.h>

#include "common.h"
#include "smoothsort.c"

void swap_packets(void *m, size_t a, size_t b) {
  packet_record *p = (packet_record *) m;
  packet_record t = p[a];
  p[a] = p[b];
  p[b] = t;
}

#define cmp(a,b,c1,f1,c2,f2,c3,f3,c4,f4)     \
  c1(a.f1) <  c1(b.f1) ||  \
  c1(a.f1) == c1(b.f1) &&( \
  c2(a.f2) <  c2(b.f2) ||  \
  c2(a.f2) == c2(b.f2) &&( \
  c3(a.f3) <  c3(b.f3) ||  \
  c3(a.f3) == c3(b.f3) &&  \
  c4(a.f4) <  c4(b.f4) ));

#define declare_sorter(name,c1,f1,c2,f2,c3,f3,c4,f4) \
  int name(void *m, size_t a, size_t b) { \
    struct packet_record *p = (struct packet_record *) m; \
    return cmp(p[a],p[b],c1,f1,c2,f2,c3,f3,c4,f4); \
  }

declare_sorter(lt_flow_time,htonl,flow,htonl,sec ,htonl,usec,htons,size)
declare_sorter(lt_flow_size,htonl,flow,htons,size,htonl,sec ,htonl,usec)
declare_sorter(lt_time_flow,htonl,sec ,htonl,usec,htonl,flow,htons,size)
declare_sorter(lt_time_size,htonl,sec ,htonl,usec,htons,size,htonl,flow)
declare_sorter(lt_size_flow,htons,size,htonl,flow,htonl,sec ,htonl,usec)
declare_sorter(lt_size_time,htons,size,htonl,sec ,htonl,usec,htonl,flow)

#define SORT_NONE 0
#define SORT_FLOW 1
#define SORT_TIME 2
#define SORT_SIZE 3

#define SORT_ORDER(major,minor) ((SORT_SIZE+1)*major+minor)

#define SET_SORT(m,f) \
  switch (m) { \
    case 1: major = f; break; \
    case 0: minor = f; break; \
    default: \
      die("You can only specify two sort fields.\n"); \
  }

int main(int argc, char ** argv) {

  int m = 1;
  int major = SORT_FLOW;
  int minor = SORT_NONE;
  int parallel = 0;

  int i;
  while ((i = getopt(argc,argv,"ftsp")) != -1) {
    switch (i) {

      case 'f': SET_SORT(m--,SORT_FLOW); break;
      case 't': SET_SORT(m--,SORT_TIME); break;
      case 's': SET_SORT(m--,SORT_SIZE); break;

      case 'p': parallel = 1; break;

      case '?':
        if (isprint(optopt))
          fprintf(stderr,"Unknown option `-%c'.\n",optopt);
        else
          fprintf(stderr,"Strange option `\\x%x'.\n",optopt);
      default:
        return 1;
    }
  }
  if (major == minor)
    die("Major and minor sort fields must differ.\n");
  if (minor == SORT_NONE)
    minor = (major != SORT_FLOW) ? SORT_FLOW : SORT_TIME;

  char *desc;
  int (*lt)(void *m, size_t a, size_t b);
  switch (SORT_ORDER(major,minor)) {
    case SORT_ORDER(SORT_FLOW,SORT_TIME):
      desc = "flow, time then size";
      lt = lt_flow_time;
      break;
    case SORT_ORDER(SORT_FLOW,SORT_SIZE):
      desc = "flow, size then time";
      lt = lt_flow_size;
      break;
    case SORT_ORDER(SORT_TIME,SORT_FLOW):
      desc = "time, flow then size";
      lt = lt_time_flow;
      break;
    case SORT_ORDER(SORT_TIME,SORT_SIZE):
      desc = "time, size then flow";
      lt = lt_time_size;
      break;
    case SORT_ORDER(SORT_SIZE,SORT_FLOW):
      desc = "size, flow then time";
      lt = lt_size_flow;
      break;
    case SORT_ORDER(SORT_SIZE,SORT_TIME):
      desc = "size, time then flow";
      lt = lt_size_time;
      break;
  }

  if (optind == argc) argc++;
  for (i = optind; i < argc; i++) {
    if (optind != argc)
      fprintf(stderr,"sorting %s by %s...\n",argv[i],desc);
    if (parallel && fork()) continue;

    FILE *file = fopen(argv[i],"r+");
    if (!file)
      die("fopen(\"%s\",\"r\"): %s\n",argv[i],errstr);
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

    su_smoothsort(packets,0,n,lt,swap_packets);

    munmap(packets,fs.st_size);
    fclose(file);
    if (parallel) {
      fprintf(stderr,"done [%s].\n",argv[i]);
      return 0;
    }
  }
  if (parallel)
    while (wait(NULL) != -1) ;
  return 0;
}
