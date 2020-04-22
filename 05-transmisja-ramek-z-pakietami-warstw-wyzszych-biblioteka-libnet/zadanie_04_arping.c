/*
*
*Compile gcc -Wall -g zadanie_04_arping.c -o zad5 -lnet -lpcap
*Run ./zad5 IFNAME HOST
*e.g: ./zad5 eth0 10.0.2.2
*10.0.2.2
*/

#include <pcap.h>
#include <libnet.h>


#include <arpa/inet.h>
#include <ctype.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/if_packet.h>
#include <linux/types.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#define SIZE_ETHERNET 14
#define nr_pck 100


struct arphdr 
{
    u_int16_t ftype;
    u_int16_t ptype;
    u_int8_t flen;
    u_int8_t plen;
    u_int16_t opcode;
    u_int8_t sender_mac_addr[6];
    u_int8_t sender_ip_addr[4];
    u_int8_t target_mac_addr[6];
    u_int8_t target_it_addr[4];
};
char* errbuf;
pcap_t* handle;
libnet_t *ln;
void cleanup()
{
    pcap_close(handle);
    free(errbuf);
}

void stop(int signo) 
{
  exit(EXIT_SUCCESS);
}
void trap(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    clock_t t;
    struct ethhdr *ethh=(struct ethhdr*)(bytes);
    struct arphdr *arph=(struct arphdr*)(bytes +sizeof(struct ethhdr));
    libnet_write(ln);
    t=clock();
    if(ntohs(ethh->h_proto)==0x0806)  //ARP
    {
        
        if((arph->opcode/256)==2)
        {
            printf("Reply from %d.%d.%d.%d [%02x:%02x:%02x:%02x:%02x:%02x] \t %f sec\n",
            arph->sender_ip_addr[0],arph->sender_ip_addr[1],arph->sender_ip_addr[2],
            arph->sender_ip_addr[3],arph->sender_mac_addr[0],arph->sender_mac_addr[1],
            arph->sender_mac_addr[2],arph->sender_mac_addr[3],arph->sender_mac_addr[4],
            arph->sender_mac_addr[5],(double)(clock()-t)/CLOCKS_PER_SEC);
        }
    } 
}


int main(int argc,char** argv)
{


    char *dev=argv[1];
     atexit(cleanup);
    signal(SIGINT,stop);
    errbuf = malloc(PCAP_ERRBUF_SIZE);
    handle = pcap_create(dev,errbuf);
    pcap_set_promisc(handle,1);
    pcap_set_snaplen(handle,65535);
    pcap_activate(handle);



    u_int32_t target_ip_addr, src_ip_addr;
    u_int8_t bcast_hw_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
             zero_hw_addr[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    struct libnet_ether_addr* src_hw_addr;
    char errbuf[LIBNET_ERRBUF_SIZE];
    ln = libnet_init(LIBNET_LINK,dev,errbuf);
    src_ip_addr = libnet_get_ipaddr4(ln);
    src_hw_addr=libnet_get_hwaddr(ln);
    target_ip_addr = libnet_name2addr4(ln, argv[2], LIBNET_RESOLVE);

  libnet_autobuild_arp(
    ARPOP_REQUEST,                   /* operation type       */
    src_hw_addr->ether_addr_octet,   /* sender hardware addr */
    (u_int8_t*) &src_ip_addr,        /* sender protocol addr */
    zero_hw_addr,                    /* target hardware addr */
    (u_int8_t*) &target_ip_addr,     /* target protocol addr */
    ln); 

    libnet_autobuild_ethernet(
        bcast_hw_addr,
        ETHERTYPE_ARP,
        ln);

    printf("Device: %s\n",dev); 
    printf("Number of packets: %d\n",nr_pck);  

    pcap_loop(handle,nr_pck,trap,NULL);
    libnet_destroy(ln);


    pcap_close(handle);
    

}
