/*

This program reads tcpdump files given on the command line (it will uncompress them if they're gzipped),
and splits them into a whole directory tree of (uncompressed) individual tcpdump files, each containing
only the packets for a single flow of data (same IP proto, src+dst IPs, src+dst UDP/TCP ports). It uses
a hash structure to cache the files handles it has written to recently, and closes a portion of them at
random when it has too many files open.

Options:
  -f <libpcap filter>     provide a Berkeley Packet Filter expression to select which packets to process.
  -d <flows directory>    the root directory where the flow files will be produces. default: "flows".
  -m <max open files>     the maximum number of open file handles to keep. default: 1000.
  -c <cleanup factor>     fraction of the open file handles which will be closed when the max is reached.
                          default: 1.0 (all of them).

Author: Stefan Karpinski <stefan.karpinski@gmail.com>

*/

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <pcap.h>
#include <glib.h>

#include "ether.h"
#include "ip.h"
#include "udp.h"
#include "tcp.h"

#define ETHERTYPE_IP   0x0008
#define ETHERTYPE_ARP  0x0608
#define ETHERTYPE_RARP 0x3508

#define IP_PROTO_TCP  6
#define IP_PROTO_UDP 17

#define DEBUG fprintf(stderr,"LINE %u\n",__LINE__);

#define errstr strerror(errno)
#define g_hash_table_exists(h,x) g_hash_table_lookup_extended(h,x,NULL,NULL)

// global parameters with default values...

char *flows_dir = "flows";
u_int32_t max_files = 1000;
double cleanup_factor = 1.00;
u_int32_t split_ips = 0;

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

#define warn(fmt,...) warn("[%u] " fmt,__LINE__,__VA_ARGS__)
#define  die(fmt,...)  die("[%u] " fmt,__LINE__,__VA_ARGS__)

// really random seeding

void seed_random() {
  unsigned short seed[3];
  char *devrand = "/dev/urandom";
  FILE *f = fopen(devrand,"r");
  if (!f) die("fopen(\"%s\",\"r\"): %s\n",devrand,errstr);
  if (fread(seed,1,sizeof(seed),f) <= 0)
    die("fread: %s\n",errstr);
  if (fclose(f)) die("fclose(\"%s\"): %s\n",devrand,errstr);
  seed48(seed);
}

// set the FD_CLOEXEC flag on a file descriptor

void file_cloexec(FILE *file) {
  int x,fd = fileno(file);
  x = fcntl(fd,F_GETFD,0);
  if (x < 0) die("fcntl(%u,F_GETFD,0): %s",fd,errstr);
  x = fcntl(fd,F_SETFD,x|FD_CLOEXEC);
  if (x < 0) die("fcntl(%u,F_GETFD,%u): %s",fd,x|FD_CLOEXEC,errstr);
}

// flow data structures

typedef struct {
  u_int8_t  proto;
  u_int32_t src_ip;
  u_int16_t src_port;
  u_int32_t dst_ip;
  u_int16_t dst_port;
} flow_key_t;

// flow hashing functions

guint flow_hash(gconstpointer a) {
  flow_key_t *f = (flow_key_t *) a;
  guint32 h = f->proto;
  h = (h<<5)-h + f->src_ip;
  h = (h<<5)-h + f->src_port;
  h = (h<<5)-h + f->dst_ip;
  h = (h<<5)-h + f->dst_port;
  return h;
}        
         
gint flow_equal(gconstpointer a, gconstpointer b) {
  flow_key_t *x = (flow_key_t *) a;
  flow_key_t *y = (flow_key_t *) b;
  return
    x->proto    == y->proto    &&
    x->src_ip   == y->src_ip   &&
    x->src_port == y->src_port &&
    x->dst_ip   == y->dst_ip   &&
    x->dst_port == y->dst_port ;
}

// output file management

char *flow_path(flow_key_t *key) {
  int x = 0;
  static char path[1024];
  x += snprintf(path+x,sizeof(path)-x,"%s/",flows_dir);
  x += snprintf(path+x,sizeof(path)-x,"%s/",inet_ntoa(key->src_ip));
  x += snprintf(path+x,sizeof(path)-x,"%s/",inet_ntoa(key->dst_ip));
  x += snprintf(path+x,sizeof(path)-x,"%u_%u_%u",
    key->proto,key->src_port,key->dst_port
  );
  if (split_ips) {
    char *c;
    while (c = strchr(path,'.')) *c = '/';
  }
  return path;
}

void create_dirs(char *path) {
  char *x = path;
  while (x = index(x+1,'/')) {
    *x = 0;
    if (mkdir(path,0755) && errno!=EEXIST)
        die("mkdir(\"%s\",0775): %s\n",path,errstr);
    *x = '/';
  }
}

// return the suffix of a file name

char *suffix(char *file, char sep) {
  char *suf = rindex(file,sep);
  return suf ? suf : "";
}

// use stat to get the size of a file

int file_size(const char *path) {
  struct stat sb;
  if (stat(path,&sb)) {
    if (errno == ENOENT) return -1;
    die("stat(\"%s\"): %s\n",path,errstr);
  }
  return sb.st_size;
}

// fork a process and read it's output via returned file descriptor

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
  // WARNING: this is not portable!!!
  // some platforms implement varargs
  // in strange ways that would break
  execvp(arg,&arg);
  die("exec(%s,...): %s\n",arg,errstr);
}

// cleanup callback for closing open file handles...

#define CLEANUP ((cleanup_factor >= 1)||(drand48() < cleanup_factor))

gboolean cleanup_cb(gpointer k, gpointer f, gpointer n) {
  if (!CLEANUP) return 0;
  free((flow_key_t *) k);
  if (fclose(f)) die("fclose: %s\n",errstr);
  int *files = (int *) n;
  (*files)--;
  return 1;
}

// main processing loop...

#define HAS_PORT(ip) (ip->ip_p==IP_PROTO_TCP||ip->ip_p==IP_PROTO_UDP)
#define SRC_PORT(ip) ntohs(*((u_int16_t*)(((char*)ip)+4*IP_HL(ip))))
#define DST_PORT(ip) ntohs(*((u_int16_t*)(((char*)ip)+4*IP_HL(ip)+2)))

#define copy(x) \
  ((typeof(x)*) memcpy(malloc(sizeof(x)),&(x),sizeof(x)))

int main(int argc, char **argv) {
  int i;
  int files=0;
  char *filter = NULL;
  while ((i = getopt(argc,argv,"d:m:c:f:s")) != -1) {
    switch (i) {
      case 'd':
        flows_dir = optarg;
        break;
      case 'm':
        max_files = atoi(optarg);
        break;
      case 'c':
        cleanup_factor = atof(optarg);
        break;
      case 'f':
        filter = optarg;
        break;
      case 's':
        split_ips = 1;
        break;
      case '?':
        if (isprint(optopt))
          fprintf(stderr,"Unknown option `-%c'.\n",optopt);
        else
          fprintf(stderr,"Strange option `\\x%x'.\n",optopt);
      default:
        return 1;
      }
  }
  seed_random();
  setvbuf(stdout,(char*)NULL,_IONBF,0);
  GHashTable *flows = g_hash_table_new(flow_hash,flow_equal);
  for (i = optind; i < argc; i++) {
    FILE *file;
    printf("processing '%s' ",argv[i]);
    if (0 == strcmp(suffix(argv[i],'.'),".gz")) {
      // use zcat to read gzipped file...
      file = cmd_read("zcat","-f",argv[i],NULL);
    } else if (0 == strcmp(suffix(argv[i],'.'),".bz2")) {
      // use bzcat to read gzipped file...
      file = cmd_read("bzcat","-f",argv[i],NULL);
    } else {
      // plain pcap file, just open it...
      if (!(file = fopen(argv[i],"r")))
        die("fopen(\"%s\",\"r\"): %s\n",argv[i],errstr);
      file_cloexec(file);
    }
    char error[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_fopen_offline(file,error);
    if (filter) {
      int ret;
      struct bpf_program fp;
      ret = pcap_compile(
        pcap,       // the pcap "object"
        &fp,        // filter program
        filter,     // the program argument
        1,          // do optimization
        0           // netmask (unused)
      );
      if (ret == -1) die("pcap_compile: %s\n",pcap_geterr(pcap));
      ret = pcap_setfilter(pcap,&fp);
      if (ret == -1) die("pcap_setfilter: %s\n",pcap_geterr(pcap));
      pcap_freecode(&fp);
    }
    if (pcap) {
      const u_char *data;
      struct pcap_pkthdr info;
      while (data = pcap_next(pcap,&info)) {
        struct ether_header *eth = (struct ether_header *) data;
        if (eth->ether_type != ETHERTYPE_IP) continue;

        flow_key_t key;
        struct ip *ip = (struct ip *) (data + sizeof(*eth));
        
        key.proto  = ip->ip_p;
        key.src_ip = ip->ip_src.s_addr;
        key.dst_ip = ip->ip_dst.s_addr;
        if (HAS_PORT(ip)) {
          key.src_port = SRC_PORT(ip);
          key.dst_port = DST_PORT(ip);
        } else {
          key.src_port = 0;
          key.dst_port = 0;
        }

        FILE *file;
        if (!(file = g_hash_table_lookup(flows,&key))) {
          while (files >= max_files) {
            g_hash_table_foreach_remove(flows,cleanup_cb,&files);
            printf(".");
          }
          char *path = flow_path(&key);
          if (file_size(path) <= 0) {
            create_dirs(path);
            if (!(file = (FILE *) pcap_dump_open(pcap,path)))
              die("pcap_dump_open(pcap,\"%s\"): %s\n",
                path,pcap_geterr(pcap)
              );
          } else {
            if (!(file = fopen(path,"a")))
              die("fopen(\"%s\",\"a\"): %s\n",path,errstr);
          }
          g_hash_table_insert(flows,copy(key),file);
          files++;
        }
        pcap_dump((u_char *) file,&info,data);
      }
    } else {
      die("pcap: %s\n",error);
    }
    if (fclose(file)) die("fclose: %s\n",errstr);
    printf("\n");
  }
  return 0;
}
