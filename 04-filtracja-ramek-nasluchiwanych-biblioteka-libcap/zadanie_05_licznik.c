/*
*
* Compile : gcc -Wall -g zadanie_05_licznik.c -o licznik -lpcap
* Run : ./licznik INTERFACE
* e.g: ./licznik eth0
* ARP,IP.IP/UDP.IP/TCP other po SIGINT
*/
#include <pcap.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <linux/filter.h>
#include <linux/if_arp.h>
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


#define nr_pck 10 // If -1 ---> INF
/* Ethernet header size*/
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6 

int ARP=0,IP=0,IP_UDP=0,IP_TCP=0,OTHER=0;
char* errbuf;
pcap_t* handle;

void cleanup()
{
    pcap_close(handle);
    free(errbuf);
}

void stop(int signo) 
{
  exit(EXIT_SUCCESS);
}

void sig_handler(int signo)
{
    if(signo==SIGINT)
    {
        pcap_breakloop(handle);
    }
}

void trap(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    struct ethhdr *ethh=(struct ethhdr*)(bytes);
    struct iphdr *iph =(struct iphdr*)(bytes+sizeof(struct ethhdr));
    //printf("IP came protcol:%s\n",iph->protocol);
    switch(ntohs(ethh->h_proto))
    {
        case 0x0800:  //IPv4
            ++IP;
            switch(iph->protocol)
            {
                case 6: //TCP
                    ++IP_TCP;
                    break;
                case 17: //UDP
                    ++IP_UDP;
                    break;
                default:
                    ++OTHER;
                    break;
            }
            break;
        case 0x0806:  //ARP
            ++ARP;
            break;
        default:
            ++OTHER;
            break;
    } 
    printf("[%dB of %dB]\n", h->caplen, h->len);
    if(signal(SIGINT,sig_handler)==SIG_ERR){}
}

int main (int argc,char** argv)
{
    char *dev=argv[1];
    atexit(cleanup);
    signal(SIGINT,stop);
    errbuf = malloc(PCAP_ERRBUF_SIZE);
    handle = pcap_create(dev,errbuf);
    // Capture info
    printf("Device: %s\n",dev);
    printf("Number of packets: %d\n",nr_pck);
    pcap_set_promisc(handle,1);
    pcap_set_snaplen(handle,65535);
    pcap_activate(handle);
    pcap_loop(handle,nr_pck,trap,NULL);
    printf("ARP:%d IP:%d IP/UDP:%d IP/TCP:%d OTHER:%d TOTAL:%d \n",ARP,IP_UDP+IP_TCP,IP_UDP,IP_TCP,OTHER,ARP+IP_UDP+IP_TCP+OTHER);
    // cleanup
    pcap_close(handle);
}