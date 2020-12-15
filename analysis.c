#include <stdio.h>
#include <stdlib.h>

#include "analysis.h"

void packetProcess(u_char * userarg, const struct pcap_pkthdr * pkthdr, const u_char * packet){
    static int x = 1;
    printf("No:%d\n",x++);
    pcap_dump(userarg, pkthdr, packet);
    for(int i=0;i<pkthdr->len;i++)
    {
        printf(" %02x",packet[i]);
        if((i+1)%16==0) printf("\n");
    }
    printf("\n\n");
}