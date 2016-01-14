#include "common.h"

// error handling

int warn(const char * fmt, ...) {
  va_list args;
  va_start(args,fmt);
  vfprintf(stderr,fmt,args);
  va_end(args);
}

int die(const char * fmt, ...) {
  va_list args;
  va_start(args,fmt);
  vfprintf(stderr,fmt,args);
  va_end(args);
  exit(1);
}

// flow & packet processing functions

void ntoh_flow(flow_record *flow) {
  flow->src_port = ntohs(flow->src_port);
  flow->dst_port = ntohs(flow->dst_port);
}
void hton_flow(flow_record *flow) {
  flow->src_port = htons(flow->src_port);
  flow->dst_port = htons(flow->dst_port);
}

void ntoh_packet(packet_record *packet) {
  packet->flow = ntohl(packet->flow);
  packet->sec  = ntohl(packet->sec );
  packet->usec = ntohl(packet->usec);
  packet->size = ntohs(packet->size);
}
void hton_packet(packet_record *packet) {
  packet->flow = htonl(packet->flow);
  packet->sec  = htonl(packet->sec );
  packet->usec = htonl(packet->usec);
  packet->size = htons(packet->size);
}

void write_flow(FILE *file, flow_record *flow) {
  if (fwrite(flow,sizeof(flow_record),1,file) != 1)
    die("fwrite: %s\n",errstr);
}
int read_flow(FILE *file, flow_record *flow) {
  if (fread(flow,sizeof(flow_record),1,file) != 1)
    if (ferror(file))
      die("fwrite: %s\n",errstr);
  return feof(file) ? 0 : 1;
}

void write_packet(FILE *file, packet_record *packet) {
  if (fwrite(packet,sizeof(packet_record),1,file) != 1)
    die("fwrite: %s\n",errstr);
}
int read_packet(FILE *file, packet_record *packet) {
  if (fread(packet,sizeof(packet_record),1,file) != 1)
    if (ferror(file))
      die("fwrite: %s\n",errstr);
  return feof(file) ? 0 : 1;
}

// unescape a C-style quoted string

void c_unescape(char* s) {
  while (*s) {
    if (*s++ == '\\') {
      switch (*s++) {
      case 'n':
        s[-2] = '\n';
        memmove(s-1, s, strlen(s)+1);
        break;
      case 'r':
        s[-2] = '\r';
        memmove(s-1, s, strlen(s)+1);
        break;
      case 't':
        s[-2] = '\t';
        memmove(s-1, s, strlen(s)+1);
        break;
      case 'v':
        s[-2] = '\v';
        memmove(s-1, s, strlen(s)+1);
        break;
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
        {
          long val;
          char tmp[4];
          memcpy(tmp, s-1, 3);
          tmp[3] = '\0';
          val = strtol(tmp, NULL, 8);
          s[-2] = (char)val;
          memmove(s-1, s+2, strlen(s+2)+1);
        }
        break;
      default:
        s[-2] = s[-1];
        memmove(s-1, s, strlen(s)+1);
      }
      --s;
    }
  }
}
// STOLEN FROM:
// http://prdownloads.sourceforge.net/boxp/bo2k1-3_beta5_src.zip [GPL]

// return the suffix of a file name

static char *suffix(const char *file, const char sep) {
  char *suf = rindex(file,sep);
  return suf ? suf : "";
}

// fork a process and read its output via returned file descriptor

FILE *cmd_read(const char *arg, ...) {
  int fd[2],pid;
  if (pipe(fd)) die("pipe: %s\n",errstr);
  if (pid = fork()) {
    FILE *rf;
    if (close(fd[1])) die("close(%u): %s\n",fd[1],errstr);
    if (!(rf = fdopen(fd[0],"r"))) die("fdopen: %s\n",errstr);
    return rf;
  }
  if (pid < 0) die("fork(): %s\n",errstr);
  if (close(0)) die("close(0): %s\n",errstr);
  if (close(fd[0])) die("close(%u): %s\n",fd[0],errstr);
  if (dup2(fd[1],1) < 0) die("dup2(%u,1): %s\n",fd[1],errstr);

  va_list var;
  va_start(var,arg);
  char *args[256];
  args[0] = (char *) arg;
  int i;
  for (i = 1; i <= sizeof(args); i++) {
    args[i] = va_arg(var, char *);
    if (!args[i]) break;
  }
  if (args[i])
    die("Too many command-line arguments: %s\n",arg);
  execvp(arg,args);
  va_end(var);

  die("exec(%s,...): %s\n",arg,errstr);
}

void file_cloexec(FILE *file) {
  int x,fd = fileno(file);
  x = fcntl(fd,F_GETFD,0);
  if (x < 0) die("fcntl(%u,F_GETFD,0): %s",fd,errstr);
  x = fcntl(fd,F_SETFD,x|FD_CLOEXEC);
  if (x < 0) die("fcntl(%u,F_GETFD,%u): %s",fd,x|FD_CLOEXEC,errstr);
}

FILE *open_arg(const char *arg) {
  FILE *file;
  if (!arg || !strcmp(arg,"-")) {
    return stdin;
  } else if (!strcmp(suffix(arg,'.'),".gz")) {
      file = cmd_read("gzcat","-f",arg,NULL);
  } else if (!strcmp(suffix(arg,'.'),".bz2")) {
      file = cmd_read("bzcat","-f",arg,NULL);
  } else {
      if (!(file = fopen(arg,"r")))
          die("fopen(\"%s\",\"r\"): %s\n",arg,errstr);
      file_cloexec(file);
  }
  return file;
}

char *get_line(FILE *fh, char **pbuffer, size_t *plen) {
#if defined(__MACOSX__) || defined(__APPLE__)
  *pbuffer = fgetln(fh,plen);
  if (ferror(fh))
    die("Error reading line.\n");
  return *pbuffer;
#else
  int r = getline(pbuffer,plen,fh);
  if (r != -1) return *pbuffer;
  if (feof(fh)) {
    if (pbuffer) free(*pbuffer);
    return *pbuffer = NULL;
  } else if (ferror(fh)) {
    die("Error reading line.\n");
  }
#endif
  die("ERROR: get_line badness.\n");
}
