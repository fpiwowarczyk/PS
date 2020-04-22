/*
*
*Compile: gcc -Wall ./zadanie_04_erherdwa.c -o zad4
*Run: ./zad4 INTERFACE
*
*
*
*/

#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/route.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define ETH_P_CUSTOM 0x8888

#define IRI_T_ADDRESS 0
#define IRI_T_ROUTE   1 

struct ifrtinfo
{
  int iri_type;                 /*   msg type    */
  char iti_iname[16];           /* if name       */
  struct sockaddr_in iri_iaddr; /* IP address    */
  struct sockaddr_in iri_rtdst; /*dst. IP address*/
  struct sockaddr_in iri_rtmsk; /*dst. netmask   */
  struct sockaddr_in iri_rtgip; /* gateway IP    */
};



int main(int argc, char** argv)
{
  int sfd;
  ssize_t len;
  char* frame;
  char* fdata;
  struct ethhdr* fhead;
  struct ifreq ifr;
  struct sockaddr_ll sall;
  struct ifrtinfo* iri;

  

  sfd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_CUSTOM));
  strncpy(ifr.ifr_name,argv[1],IFNAMSIZ);
  ioctl(sfd,SIOCGIFINDEX,&ifr);
  memset(&sall,0,sizeof(struct sockaddr_ll));

  sall.sll_family = AF_PACKET;
  sall.sll_protocol = htons(ETH_P_CUSTOM);
  sall.sll_ifindex = ifr.ifr_ifindex;
  sall.sll_hatype = ARPHRD_ETHER;
  sall.sll_pkttype = PACKET_HOST;
  sall.sll_halen = ETH_ALEN;

  bind(sfd, (struct sockaddr*) &sall, sizeof(struct sockaddr_ll));
  while(1)
  {
    frame = malloc(ETH_FRAME_LEN);
    memset(frame,0,ETH_FRAME_LEN);
    fhead = (struct ethhdr*) frame;
    fdata = frame+ ETH_HLEN;
    len = recvfrom(sfd,frame,ETH_FRAME_LEN,0,NULL,NULL);
    printf("[%dB] %02x:%02x:%02x:%02x:%02x:%02x ->",(int)len,
            fhead->h_source[0],fhead->h_source[1],fhead->h_source[2],
            fhead->h_source[3],fhead->h_source[4],fhead->h_source[5]);
    printf("%02x:%02x:%02x:%02x:%02x:%02x |",
            fhead->h_dest[0],fhead->h_dest[1],fhead->h_dest[2],
            fhead->h_dest[3],fhead->h_dest[4],fhead->h_dest[5]);
    printf("%s\n",fdata);
    printf("\n\n");
    iri=(struct ifrtinfo*)fdata;
    if(iri->iri_type==IRI_T_ADDRESS)
    {
      int cfd;
      struct ifreq ifrv2;
      struct sockaddr_in* sin;
      cfd = socket(PF_INET, SOCK_DGRAM, 0);
      strncpy(ifrv2.ifr_name, argv[1], strlen(argv[1]) + 1);
      sin = (struct sockaddr_in*) &ifrv2.ifr_addr;
      memset(sin, 0, sizeof(struct sockaddr_in));
      sin->sin_family = AF_INET;
      sin->sin_port = 0;
      sin->sin_addr.s_addr = iri->iri_iaddr.sin_addr.s_addr;
      ioctl(cfd, SIOCSIFADDR, &ifrv2);
      ioctl(cfd, SIOCGIFFLAGS, &ifrv2);
      ifrv2.ifr_flags |= IFF_UP | IFF_RUNNING;
      ioctl(cfd, SIOCSIFFLAGS, &ifrv2);
      close(cfd);
    }
    else if(iri->iri_type==IRI_T_ROUTE)
    {
      int cfd;
      struct rtentry route;
      struct sockaddr_in* addr;

      cfd = socket(PF_INET, SOCK_DGRAM, 0);
      memset(&route, 0, sizeof(route));

      addr = (struct sockaddr_in*) &route.rt_gateway;
      addr->sin_family = AF_INET;
      addr->sin_addr.s_addr = iri->iri_rtdst.sin_addr.s_addr;
      addr = (struct sockaddr_in*) &route.rt_dst;
      addr->sin_family = AF_INET;
      addr->sin_addr.s_addr = iri->iri_rtmsk.sin_addr.s_addr;
      addr = (struct sockaddr_in*) &route.rt_genmask;
      addr->sin_family = AF_INET;
      addr->sin_addr.s_addr = iri->iri_rtgip.sin_addr.s_addr;
      route.rt_flags = RTF_UP | RTF_GATEWAY;
      route.rt_metric = 0;
      ioctl(cfd, SIOCADDRT, &route);
      close(cfd);
    }
    free(frame);
  }
  close(sfd);
  return EXIT_SUCCESS;
}