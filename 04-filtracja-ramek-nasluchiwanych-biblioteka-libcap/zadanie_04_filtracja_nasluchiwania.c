/*  
* Compile: gcc -Wall ./zadanie_04_filtracja_nasluchiwania.c -o zadanie_04
* Run ./zadanie_04 INTERFACE
* e.g: ./zadanie_04_filtracja_nasluchiwania.c eth0
* 
*
*
*
*/

#include <arpa/inet.h>
#include <ctype.h>
#include <linux/filter.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define ETH_P_CUSTOM ETH_P_ALL //0x8888
#define FILTER dns_out_filter 

int sfd;
struct ifreq ifr;

struct sock_filter dns_out_filter[] = {  /* tcpdump -dd -i eth0 -Q out port 53 */
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 8, 0x000086dd },
    { 0x30, 0, 0, 0x00000014 },
    { 0x15, 2, 0, 0x00000084 },
    { 0x15, 1, 0, 0x00000006 },
    { 0x15, 0, 17, 0x00000011 },
    { 0x28, 0, 0, 0x00000036 },
    { 0x15, 14, 0, 0x00000035 },
    { 0x28, 0, 0, 0x00000038 },
    { 0x15, 12, 13, 0x00000035 },
    { 0x15, 0, 12, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 2, 0, 0x00000084 },
    { 0x15, 1, 0, 0x00000006 },
    { 0x15, 0, 8, 0x00000011 },
    { 0x28, 0, 0, 0x00000014 },
    { 0x45, 6, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x0000000e },
    { 0x15, 2, 0, 0x00000035 },
    { 0x48, 0, 0, 0x00000010 },
    { 0x15, 0, 1, 0x00000035 },
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 },
};

struct sock_fprog bpf = 
{
    .len=(sizeof(FILTER)/sizeof(FILTER[0])),
    .filter =FILTER
};

void cleanup()
{
    ifr.ifr_flags &= ~IFF_PROMISC;
    ioctl(sfd,SIOCSIFFLAGS,&ifr);
    close(sfd);
}

void stop(int signo)
{
    exit(EXIT_SUCCESS);
}


int main(int argc, char** argv) {
  
  int  i;
  ssize_t len;
  char* frame;
  char* fdata;
  struct ethhdr* fhead;
  socklen_t sl;
  struct sockaddr_ll sall;
  atexit(cleanup);
  signal(SIGINT,stop);
  sfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_CUSTOM));
  setsockopt(sfd,SOL_SOCKET,SO_ATTACH_FILTER,&bpf,sizeof(bpf));
  strncpy(ifr.ifr_name, argv[1], IFNAMSIZ);
  ioctl(sfd, SIOCGIFFLAGS, &ifr);
  ifr.ifr_flags |= IFF_PROMISC;
  ioctl(sfd, SIOCSIFFLAGS, &ifr);
  memset(&sall, 0, sizeof(struct sockaddr_ll));
  sall.sll_family = AF_PACKET;
  sall.sll_protocol = htons(ETH_P_CUSTOM);
  sall.sll_ifindex = ifr.ifr_ifindex;
  sall.sll_hatype = ARPHRD_ETHER;
  sall.sll_pkttype = PACKET_HOST;
  sall.sll_halen = ETH_ALEN;
  bind(sfd, (struct sockaddr*) &sall, sizeof(struct sockaddr_ll));
  while(1) {
    frame = malloc(ETH_FRAME_LEN);
    memset(frame, 0, ETH_FRAME_LEN);
    fhead = (struct ethhdr*) frame;
    fdata = frame + ETH_HLEN;
    sl = sizeof(struct sockaddr_ll);
    len = recvfrom(sfd, frame, ETH_FRAME_LEN, 0, (struct sockaddr*)&sall, &sl);
    printf("[%dB] %02x:%02x:%02x:%02x:%02x:%02x -> ", (int)len,
           fhead->h_source[0], fhead->h_source[1], fhead->h_source[2],
           fhead->h_source[3], fhead->h_source[4], fhead->h_source[5]);
    printf("%02x:%02x:%02x:%02x:%02x:%02x | ",
           fhead->h_dest[0], fhead->h_dest[1], fhead->h_dest[2],
           fhead->h_dest[3], fhead->h_dest[4], fhead->h_dest[5]);
    printf("Packet type: %d \n",sall.sll_pkttype); 
    printf("Ether type: %x\n",ETH_P_CUSTOM); 
    printf("%s\n", fdata);
    for (i = 0; i < len ; i++) {
      printf("%02x ", (unsigned char) frame[i]);
      if ((i + 1) % 16 == 0)
        printf("\n");
    }
    printf("\n\n");
    free(frame);
  }
}