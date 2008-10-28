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
  execvp(arg,&arg);
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
      file = cmd_read("zcat","-f",arg,NULL);
  } else if (!strcmp(suffix(arg,'.'),".bz2")) {
      file = cmd_read("bzcat","-f",arg,NULL);
  } else {
      if (!(file = fopen(arg,"r")))
          die("fopen(\"%s\",\"r\"): %s\n",arg,errstr);
      file_cloexec(file);
  }
  return file;
}

