#include "common.h"
#undef SIZE_MAX

#define SIZE_MIN 24
#define SIZE_MAX 1500
#define SIZE_DIM (SIZE_MAX-SIZE_MIN+1)

#define IVAL_MIN 0
#define IVAL_MAX 600
#define IVAL_DIM SIZE_DIM
#define IVAL_EXP 0.3610533021031545

#define DIM (SIZE_DIM+IVAL_DIM)

inline u_int16_t ival_index(double v) {
  if (v < IVAL_MIN) return 0;
  if (v > IVAL_MAX) return IVAL_DIM - 1;
  double x = pow((v - IVAL_MIN)/(IVAL_MAX - IVAL_MIN), IVAL_EXP);
  u_int16_t k = ceil(IVAL_DIM * x);
  if (k > IVAL_DIM) return IVAL_DIM - 1;
  if (k < 1) return 0;
  return k - 1;
}

inline u_int16_t size_index(u_int16_t size) {
  u_int16_t k = size - SIZE_MIN + 1;
  if (k > SIZE_DIM-1) return IVAL_DIM + SIZE_DIM - 1;
  if (k < 1) return IVAL_DIM;
  return IVAL_DIM + k - 1;
}

inline void flush_row(int *empty, u_int32_t flow, u_int32_t *row) {
  if (*empty) return;
  int col;
  for (col = 0; col < DIM; col++) {
    if (row[col])
      printf("%u,%u,%u\n",flow,col+1,row[col]);
  }
  memset(row,0,DIM*sizeof(*row));
  *empty = 1;
}

int main(int argc, char ** argv) {
  int i;
  for (i = optind; i < argc; i++) {
    u_int32_t last_flow = 0xffff;
    FILE *file = open_arg(argv[i]);
    char data[PACKET_RECORD_SIZE];
    u_int32_t row[DIM];
    memset(row,0,DIM*sizeof(*row));
    int empty = 1;
    while (fread(data,sizeof(data),1,file) == 1) {
      u_int32_t flow = ntohl(*((u_int32_t *) (data + 0)));
      if (flow != last_flow)
        flush_row(&empty,last_flow,row);
      double ival = *((double *) (data + 12));
      u_int16_t size = ntohs(*((u_int16_t *) (data + 20)));
      if (ival < INFINITY)
        row[ival_index(ival)]++;
      row[size_index(size)]++;
      last_flow = flow;
      empty = 0;
    }
    flush_row(&empty,last_flow,row);
    if (ferror(file))
      die("fread: %u\n",errno);
    fclose(file);
  }
  return 0;
}
