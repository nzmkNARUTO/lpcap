#include <ncurses.h>

#include <locale.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>

int main(void){
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr pkthdr;
    pcap_t *device = pcap_open_live("ens33", 65536, 1, 100, errbuf);
    u_char *packet;
    packet = pcap_next(device, &pkthdr);
    printf("%d\n", pkthdr.len);
    packet = pcap_next(device, &pkthdr);
    printf("%d\n", pkthdr.len);
}