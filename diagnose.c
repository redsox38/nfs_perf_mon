#include <getopt.h>
#include <string.h>
#include <pcap.h>
#include <errno.h>
#include <sys/types.h>
#include "packet.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <byteswap.h>
#include <json-c/json.h>
#include <netdb.h>

typedef struct diag_elt {
  struct diag_elt *next;
  unsigned long   count;
  unsigned long   bytes;
  unsigned long   iops;
  struct in_addr  addr;
} diag_elt_t;

/* array of command line options */
static struct option long_options[] = {
  {"interface", 1, 0, 'i'},
  {"time", 1, 0, 't'},
  {"pbsnodes", 1, 0, 'p'},
  {"quiet", 1, 0, 'q'},
  {"readfile", 1, 0, 'r'},
  {"sort", 1, 0, 's'},
  {0,0,0,0}
};

char           *dev = NULL;
char           *readfile = NULL;
char           *nodefile = NULL;
char           *sort = NULL;
int            captime = 300;
int            quiet = 0;
pcap_t         *pcap_handle = NULL;
char           errbuf[PCAP_ERRBUF_SIZE];
diag_elt_t     *list_head; /* list in descending order of ip addresses */
struct in_addr my_ip;

char *read_node_file()
{
  char *buf = 0;
  long len;
  FILE *fp;

  if ((fp = fopen(nodefile, "rb")) != NULL) {
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    buf = (char *)malloc(len);
    if (buf) {
      fread(buf, 1, len, fp);
    }
    fclose(fp);
  }

  return(buf);
}

void term_handler(int signum)
{
  if (pcap_handle)
    pcap_close(pcap_handle);
}

void alarm_handler(int signum)
{
  if (pcap_handle) {
    pcap_breakloop(pcap_handle);
    pcap_close(pcap_handle);
  }
}

struct in_addr get_my_addr() {
  int fd;
  struct ifreq ifr;

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  /* I want to get an IPv4 IP address */
  ifr.ifr_addr.sa_family = AF_INET;

  /* I want IP address attached to dev */
  strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

  ioctl(fd, SIOCGIFADDR, &ifr);

  close(fd);

  /* return result */
  return(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

void usage() 
{
  fprintf(stderr, "find_io_killer [-i|--interface interface]|[-r|--readfile pcap file to read from] [-t|--time seconds to run capture for] [-q|--quiet] [--pbsnodes|-p path to file containing output of pbsnodes -a -F json] -s|--sort bandwidth|packets|iops\n");
 
  exit(0);
}

/* 
  function to insert a new_node in a list. Note that this
  function expects a pointer to head_ref as this can modify the
  head of the input linked list 
*/
void sorted_insert(diag_elt_t **head_ref, diag_elt_t *new_node)
{
  diag_elt_t *current;

  if (!strcmp(sort, "bandwidth")) {
    /* Special case for the head end */
    if (*head_ref == NULL || (*head_ref)->bytes <= new_node->bytes) {
      new_node->next = *head_ref;
      *head_ref = new_node;
    } else {
      /* Locate the node before the point of insertion */
      current = *head_ref;

      while (current->next != NULL && current->next->bytes > new_node->bytes)
        current = current->next;

      new_node->next = current->next;
      current->next = new_node;
    }
  }

  if (!strcmp(sort, "packets")) {
    /* Special case for the head end */
    if (*head_ref == NULL || (*head_ref)->count <= new_node->count) {
      new_node->next = *head_ref;
      *head_ref = new_node;
    } else {
      /* Locate the node before the point of insertion */
      current = *head_ref;

      while (current->next != NULL && current->next->count > new_node->count)
        current = current->next;

      new_node->next = current->next;
      current->next = new_node;
    }
  }

  if (!strcmp(sort, "iops")) {
    /* Special case for the head end */
    if (*head_ref == NULL || (*head_ref)->iops <= new_node->iops) {
      new_node->next = *head_ref;
      *head_ref = new_node;
    } else {
      /* Locate the node before the point of insertion */
      current = *head_ref;

      while (current->next != NULL && current->next->iops > new_node->iops)
        current = current->next;

      new_node->next = current->next;
      current->next = new_node;
    }
  }

}

diag_elt_t *sort_list()
{
  diag_elt_t *l, *n, *sorted = NULL;

  l = list_head;

  /* best case, nothing to sort */
  if ((l == NULL) || (l->next == NULL)) 
    return;

  while(l != NULL) {
    n = l->next;
    sorted_insert(&sorted, l);
    l = n;
  }

  return(sorted);
}

void print_list(struct json_object *nodes)
{
  diag_elt_t         *l;
  struct json_object *n, *tmp, *jobs;
  int                i, r;
  struct sockaddr_in sa;
  struct in_addr     zero;
  char               hostname[NI_MAXHOST], *p;
  char               j[64];

  /* grab the node object from the pbsnodes file json */
  json_object_object_get_ex(nodes, "nodes", &n);

  l = list_head;

  if (!quiet) {
    printf("%-17s %8s %7s %8s", "Host", "Bytes", "Packets", "IOPS(NFS)");
    if (nodefile != NULL) 
      printf(" %s", "Jobs");

    printf("\n---------------------------------------------\n");
  }

  while(l != NULL) {
    /* throw out 0.0.0.0 placeholder */
    zero = inet_makeaddr(0, 0);
    if(!memcmp((void *)&zero, (void *)&l->addr, sizeof(struct in_addr))) {
      l = l->next;
      continue;
    }

    /* resolve to short host name */
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, inet_ntoa(l->addr), &sa.sin_addr);    
    r = getnameinfo((struct sockaddr*)&sa, sizeof(sa),
                    hostname, NI_MAXHOST,
                    NULL, 0, NI_NAMEREQD);
    if (!r) {
      p = strchr(hostname, '.');
      *p = '\0';

      printf("%-17s ", hostname);
    } else {
      printf("%-17s ", inet_ntoa(l->addr));
    }

    printf("%-8d %-7d %-8d ", l->bytes, l->count, l->iops);

    if (!r && nodefile != NULL) {
      /* see if there's an entry in pbsnodes for this host if we got a host name */
      if (json_object_object_get_ex(n, hostname, &tmp)) {
        if (json_object_object_get_ex(tmp, "jobs", &jobs)) {
          for (i = 0; i < json_object_array_length(jobs); i++) {
	    // Set in tmp the json_object of the job at index i
    	    tmp = json_object_array_get_idx(jobs, i);
            p = json_object_to_json_string(tmp);

            sprintf(j, "%s", (p + 1));
            p = strchr(j, '.');
            *p = '\0';
            printf("%s ", j);
   	  }
        }
      }
    }
    printf("\n");

    l = l->next;
  }
}

void update_list(struct in_addr ip, int size, int iop_flag)
{
  diag_elt_t *l, *n, *p = NULL;
  int        i, done = 0;

  l = list_head;

  while(l != NULL) {
    /* compare addr with this element */
    /* (struct sockaddr_in *)&ifr.ifr_addr)->sin_addr */
    i = memcmp((void *)&ip, (void *)&l->addr, sizeof(struct in_addr));
    
    if (i < 0) {
      /* ip is less than this list element address, keep going */
      p = l;
      l = l->next;
    } else if (i == 0) {
      /* we have a match, update this element */
      l->bytes += size;
      l->count++;
      if (iop_flag)
        l->iops++;
      done = 1;
      break; 
    } else {
      /* i > 0 meaning ip is greater than this address in the list
         so we insert a new element at the previous position */
      n = (diag_elt_t *)malloc(sizeof(diag_elt_t));
      if (n == NULL) {
        fprintf(stderr, "malloc failed\n");
        exit(-1);
      }

      n->bytes = size;
      n->count = 1;
      n->iops = 0;
      n->addr = ip;
      if (p == NULL) {
        /* inserting at the head of the list */
        n->next = list_head;
        list_head = n;
      } else {
        p->next = n;
        n->next = l;
      }
      done = 1;
      break; 
    }
  }

  /* append to the end if we haven't already inserted it */
  if (!done) {
 
    n = (diag_elt_t *)malloc(sizeof(diag_elt_t));
    if (n == NULL) {
      fprintf(stderr, "malloc failed\n");
      exit(-1);
    }
  
    n->bytes = size;
    n->addr = ip;
    n->count = 1;
    n->next = NULL;
    p->next = n;
  }

  return;
}

/* 
   function passed to pcap_loop to read processed packets
   that match the filter.
   sends matched packets to database for later interactive
   processing.
 */
void read_packet(u_char *args, const struct pcap_pkthdr *hdr,
                 const u_char *packet)
{
  const struct sniff_ethernet *eth;
  const struct sniff_ip       *ip;
  const struct sniff_tcp      *tcp;
  const struct sniff_udp      *udp;
  const struct sniff_rpc      *rpc;
  char                        *payload;
  struct in_addr              addr;
  int                         size_ip, size, iop = 0;
  uint                        data_len;

  eth      = (struct sniff_ethernet*)(packet);
  ip       = (struct sniff_ip *)(packet + SIZE_ETHER);
  size_ip  = IP_HL(ip)*4;
  
  if (ip->ip_p == IPPROTO_TCP) {
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHER + size_ip);
    size = TH_OFF(tcp)*4;
    payload = (char *)(packet + SIZE_ETHER + size_ip + size);
  } else if (ip->ip_p == IPPROTO_UDP) {
    udp = (struct sniff_udp*)(packet + SIZE_ETHER + size_ip);
    size = udp->uh_len;
    payload = (char *)(packet + SIZE_ETHER + size_ip + size);
  }

  addr = ip->ip_src;
  if (!memcmp((void *)&addr, (void *)&my_ip, sizeof(struct in_addr)))
    addr = ip->ip_dst;

  data_len = ip->ip_len - (SIZE_ETHER + size_ip + size);
  /* see if this looks like it might be an rpc call */
  if (data_len > 28) {
    /* it's big enough */
    rpc = (struct sniff_rpc*)(payload + 4);

    /* data arrives is in network byte order, flip it 
       to host order before evaluating */

    /* we only care about incoming calls */
    if (!bswap_32(rpc->type)) {
      /* if it is rpc, it's a call */

      if ((bswap_32(rpc->rpc_vers) == 2) && (bswap_32(rpc->prog_id) == 100003)) {
        /* safe to say it's an nfs rpc call */
        if ((bswap_32(rpc->prog_proc) > 0) && (bswap_32(rpc->prog_proc) < 22)) {
          /* it counts as an iop */
          iop = 1;
        }
      }
    }
  }

  update_list(addr, hdr->len, iop);
 
  return;
}

/* 
   function to read packets if we were given a device
   to read from.  Also the default if no pcap file
   was given
*/

int init_packet_capture_live(char *dev) 
{  
  if (dev) {
    pcap_handle = pcap_open_live(dev, 9000, 1, 1000, errbuf);
  }

  if (!pcap_handle) {
    return(-1);
  }

  return(0);
}

/* 
   function called to read packets if we were given a previous pcap file 
   to read from
*/
int init_packet_capture_from_file(char *file)
{
  if (file) {
    pcap_handle = pcap_open_offline(file, errbuf);
  }

  if (!pcap_handle) {
    return(-1);
  }

  return(0);
}

/* 
   set up filter and start capture
   if reading from device,
   function will not return
*/
void run_packet_capture() 
{
  struct bpf_program filter;
  char               filter_ex[] = "(tcp or udp) and not ip multicast";

  if (pcap_handle) {
    /* compile filter */
    if (pcap_compile(pcap_handle, &filter, filter_ex, 0, 0) < 0) {
      fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_ex, pcap_geterr(pcap_handle));
    } else {
      if (pcap_setfilter(pcap_handle, &filter) < 0) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_ex, pcap_geterr(pcap_handle));
      }
    }
  }

  /* device ready, filter compiled.  Here we go... */
  if (pcap_handle) {
    pcap_loop(pcap_handle, -1, read_packet, NULL);
  }
  pcap_freecode(&filter);
}


int main(int argc, char *argv[]) {
  extern char        *optarg;
  extern int         optind, optopt, opterr;
  int                c, option_index;
  struct json_object *nodes;
  char               *nodefile_str;
  
  /* process command line */

  while ((c = getopt_long(argc, argv, "i:p:qr:s:t:", long_options, 
                          &option_index)) != -1) {
    switch (c) {
    case 'i':
      dev = strdup(optarg);
      break;
    case 'p':
      nodefile = strdup(optarg);
      break;
    case 'q':
      quiet = 1;
      break;
    case 'r':
      readfile = strdup(optarg);
      break;
    case 's':
      sort = strdup(optarg);
      if (!strcmp(sort, "bandwidth") &&
          !strcmp(sort, "iops") &&
          !strcmp(sort, "packets"))
        usage();
      break;
    case 't':
      captime = atoi(optarg);
      break;
    case '?':
      usage();
      break;
    }
  }

  /* parse node file so we can map workloads to jobs */
  if (nodefile != NULL) {
    nodefile_str = read_node_file();
    if (nodefile_str == NULL) {
      fprintf(stderr, "unable to read %s\n", nodefile);
      exit(-1);
    }
    nodes = json_tokener_parse(nodefile_str);
    free(nodefile_str);
  }

  list_head = (diag_elt_t *)malloc(sizeof(diag_elt_t));

  if (list_head == NULL) {
    fprintf(stderr, "malloc failed\n");
    exit(-1);
  }
 
  list_head->next = NULL;
  list_head->addr = inet_makeaddr(0, 0);
  list_head->bytes = 0;
  list_head->count = 0;

  alarm(captime);

  /* install signal handler(s) */
  signal(SIGTERM, term_handler);
  signal(SIGALRM, alarm_handler);

  /* get our ip so we know how to categorize traffic we capture */
  my_ip = get_my_addr();

  /* 
     start pcap from live interface or pcap file depending on command line settings
   */
  if (dev) {
    if (init_packet_capture_live(dev) < 0) {
      exit(-1);
    }
  } else  if (readfile) {
    if (init_packet_capture_from_file(readfile) < 0) {
      exit(-1);
    }
  }

  /* 
     loop reading packets.  If run from a live interface, this function will never return     
  */

  run_packet_capture();

  /*
     sig alarm handler has been caught and capture stopped
     dump out content of list
   */

  /* sort list if we were provided a sort parameter */
  if (sort) {
    list_head = sort_list();
  }

  print_list(nodes);
}
