const char *usage =
  "Usage:\n"
  "  reindex <packet file>\n"
  "\n"
  "  Sequentially reindex flows reference by packet file.\n"
  "\n"
;

#include <sys/stat.h>
#include <sys/mman.h>

#include "common.h"

int parallel = 0;

int main(int argc, char ** argv) {

  int i;
  for (i = 1; i < argc; i++) {
    if (argc != 2)
      fprintf(stderr,"sorting %s...\n",argv[i]);

    if (parallel && fork()) continue;

    FILE *file = fopen(argv[i],"r+");
    if (!file)
      die("fopen(\"%s\",\"r\"): %s\n",argv[i],errstr);
    struct stat fs;
    fstat(fileno(file),&fs);
    u_int32_t n = fs.st_size / sizeof(packet_record);
    if (n > 0) {

      packet_record *packets = mmap(
        0,
        fs.st_size,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        fileno(file),
        0
      );

      u_int32_t index = 0;
      u_int32_t index_n = htonl(index);
      u_int32_t last_flow = packets[0].flow;
      u_int32_t j;

      for (j = 0; j < n; j++) {
        if (last_flow != packets[j].flow) {
          last_flow = packets[j].flow;
          index_n = htonl(++index);
        }
        packets[j].flow = index_n;
      }

      munmap(packets,fs.st_size);
      fclose(file);

      if (parallel) {
        fprintf(stderr,"done [%s].\n",argv[i]);
        return 0;
      }

    }
  }
  if (parallel)
    while (wait(NULL) != -1) ;
  return 0;
}
