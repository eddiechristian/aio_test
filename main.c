#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/select.h>
#include <inttypes.h>
#include <sys/syscall.h>
#include <linux/aio_abi.h>

int g_max_file_sz = 10000; //10 meg
int g_wrt_sz = 65536; //10 meg

#define MAX_PACKETS (100*2)
struct iovec g_staged_packets[MAX_PACKETS];

struct ed_pcap_pkthdr {
     uint32_t ts_sec;         /* timestamp seconds */
     uint32_t ts_usec;        /* timestamp microseconds */
     uint32_t caplen;
     uint32_t len;
 };

void usage()
{
	fprintf(stderr,
		"Usage: aio_test [-z maxfilesize default 10M] [-b wrtsize default 65k]\n");

	exit(1);
}

inline int io_setup(unsigned nr, aio_context_t *ctxp)
{
	return syscall(__NR_io_setup, nr, ctxp);
}

inline int io_destroy(aio_context_t ctx)
{
	return syscall(__NR_io_destroy, ctx);
}

inline int io_submit(aio_context_t ctx, long nr,  struct iocb **iocbpp)
{
	return syscall(__NR_io_submit, ctx, nr, iocbpp);
}

inline int io_getevents(aio_context_t ctx, long min_nr, long max_nr,
		struct io_event *events, struct timespec *timeout)
{
	return syscall(__NR_io_getevents, ctx, min_nr, max_nr, events, timeout);
}

uint64_t create_iocb_array_from_pkt(
        int fd,
        unsigned char* pkt,
        struct ed_pcap_pkthdr* pcap_pkt_hdr,
        uint64_t start_offset,
        struct iocb ** pcap_hdr_cb,
        struct iocb ** pcap_pkt_cb
      )
{
    *pcap_hdr_cb = malloc(sizeof(struct iocb));
    memset(*pcap_hdr_cb, 0, sizeof(struct iocb));
    // *pcap_pkt_cb = malloc(sizeof(struct iocb));
    // memset(*pcap_pkt_cb, 0, sizeof(struct iocb));

    g_staged_packets[0].iov_base = pcap_pkt_hdr;
    g_staged_packets[1].iov_len = 16;
    g_staged_packets[2].iov_base = pkt;
    g_staged_packets[3].iov_len = pcap_pkt_hdr->len;

    (*pcap_hdr_cb)->aio_fildes = fd;
    (*pcap_hdr_cb)->aio_lio_opcode = IOCB_CMD_PWRITEV; //IOCB_CMD_PWRITEV
    (*pcap_hdr_cb)->aio_buf = (uint64_t)&g_staged_packets[0];
    (*pcap_hdr_cb)->aio_offset = start_offset;
    (*pcap_hdr_cb)->aio_nbytes = 2 * sizeof(struct iovec); //2 writes per packet


    // (*pcap_pkt_cb)->aio_fildes = fd;
    // (*pcap_pkt_cb)->aio_lio_opcode = IOCB_CMD_PWRITE;//IOCB_CMD_PWRITEV
    // (*pcap_pkt_cb)->aio_buf = (uint64_t)pkt;
    // (*pcap_pkt_cb)->aio_offset = start_offset+16;
    // (*pcap_pkt_cb)->aio_nbytes = pcap_pkt_hdr->len;
    return start_offset + 16 + pcap_pkt_hdr->len;
}

int main(int argc, char *argv[])
{
  extern char *optarg;
  extern int optind, opterr, optopt;
  int c;
  int ret;
  aio_context_t  myctx;
  struct iocb cb;
  struct iocb *cbs[1000];
  struct io_event events[1000];
  char data[4096];
  struct ed_pcap_pkthdr pcap_pkt_hdr;
  pcap_pkt_hdr.ts_sec = 0;
  pcap_pkt_hdr.ts_usec = 0;
  pcap_pkt_hdr.caplen = 1345;
  pcap_pkt_hdr.len = 1345;
  memset(data,3,4096);
  memset(g_staged_packets,0,sizeof(g_staged_packets));

  while ((c = getopt(argc, argv, "hz:b:")) != -1) {
    char *endp;

    switch (c) {
      case 'z':	/* alignment of data buffer */
        g_max_file_sz = strtol(optarg, &endp, 0);
        break;
      case 'b':	/* alignment of data buffer */
        g_wrt_sz = strtol(optarg, &endp, 0);
        break;
      case 'h':
       usage();
       break;
    }
  }

  printf("g_max_file_sz %d\n", g_max_file_sz);
  printf("g_wrt_sz %d\n", g_wrt_sz);

  int fd = open("foo", O_WRONLY|O_CREAT, 0777);
  if (fd) {
       int mode = 0;
      //  ret = fallocate(fd,mode,0,g_max_file_sz);
      //  if (ret < 0) {
      //     perror("fallocate failed");
      //     return -1;
      //  }
       memset(&myctx, 0, sizeof(myctx));
       ret = io_setup(1, &myctx);
       if (ret < 0) {
         perror("io_setup error");
         return -1;
       }

      uint64_t offset = create_iocb_array_from_pkt(fd, data, &pcap_pkt_hdr, 0, &cbs[0],&cbs[1]);

       ret = io_submit(myctx, 1, &cbs[0]);
       if (ret != 1) {
         if (ret < 0)
           perror("io_submit error");
         else
           fprintf(stderr, "could not sumbit IOs");
         return  -1;
       }
       printf("io_submit ret %d\n", ret);

       /* get the reply */
       ret = io_getevents(myctx, 1, 2, events, NULL);
       printf("io_getevents ret %d\n", ret);
       printf("events[0].res %d events[1].res %d \n", events[0].res,events[1].res);
       printf("events[0].res2  %d events[1].res2  %d \n", events[0].res2,events[1].res2);
       ret = io_destroy(myctx);
       if (ret < 0) {
         perror("io_destroy error");
         return -1;
       }

  }
  return 0;
  close(fd);
}
