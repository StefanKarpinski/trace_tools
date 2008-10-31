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

