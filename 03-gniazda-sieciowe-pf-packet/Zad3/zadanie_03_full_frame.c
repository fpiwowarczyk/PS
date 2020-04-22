/*
 * Copyright (C) 2020 Michal Kalewski <mkalewski at cs.put.poznan.pl>
 *
 * Compilation:  gcc -Wall ./zadanie_03_full_frame.c -o ./ethrecv
 * Usage:        ./ethrecv INTERFACE
 * NOTE:         This program requires root privileges.
 *
 * Bug reports:  https://gitlab.cs.put.poznan.pl/mkalewski/ps-2020/issues
 *
 */

#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define ETH_P_CUSTOM 0x8888

int main(int argc, char** argv) {
  
  int sfd, i;
  ssize_t len;
  char* frame;
  char* fdata;
  struct ethhdr* fhead;
  struct ifreq ifr;
  struct sockaddr_ll sall;
  
  sfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_CUSTOM));
  strncpy(ifr.ifr_name, argv[1], IFNAMSIZ);
  ioctl(sfd, SIOCGIFINDEX, &ifr);
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
    len = recvfrom(sfd, frame, ETH_FRAME_LEN, 0, NULL, NULL);
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
  close(sfd);
  return EXIT_SUCCESS;
}
