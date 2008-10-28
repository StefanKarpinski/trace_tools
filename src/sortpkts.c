#include <sys/stat.h>
#include <sys/mman.h>

#include "common.h"
#include "smoothsort.c"

struct packet_record {
  u_int32_t flow;
  u_int32_t sec;
  u_int32_t usec;
  u_int16_t size;
} __attribute__((packed));

int less(void *m, size_t a, size_t b) {
  struct packet_record *p = (struct packet_record *) m;
  return
    htonl(p[a].flow) <  htonl(p[b].flow) ||
    htonl(p[a].flow) == htonl(p[b].flow) &&(
    htonl(p[a].sec)  <  htonl(p[b].sec)  ||
    htonl(p[a].sec)  == htonl(p[b].sec)  &&(
    htonl(p[a].usec) <  htonl(p[b].usec) ));
}

void swap(void *m, size_t a, size_t b) {
  struct packet_record *p = (struct packet_record *) m;
  struct packet_record t = p[a];
  p[a] = p[b];
  p[b] = t;
}

int main(int argc, char ** argv) {
  int i;
  if (optind == argc) argc++;
  for (i = optind; i < argc; i++) {
    FILE *file = fopen(argv[i],"r+");
    if (!file)
      die("fopen(\"%s\",\"r\"): %s\n",argv[i],errstr);
    struct stat fs;
    fstat(fileno(file),&fs);
    u_int32_t n = fs.st_size / PACKET_RECORD_SIZE;

    struct packet_record *packets = mmap(
      0,
      fs.st_size,
      PROT_READ | PROT_WRITE,
      MAP_SHARED,
      fileno(file),
      0
    );

    su_smoothsort(packets,0,n,less,swap);

    munmap(packets,fs.st_size);
    fclose(file);
  }
  return 0;
}
