#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>

#include "analysis.h"

void packetProcess(struct pcap_pkthdr* pkthdr, u_char* packet, int count){
    printf("count:%d\n",count);
    printf("Packet len:%d, Bytes:%d, Received time:%s\n", pkthdr->len, pkthdr->caplen, ctime((const time_t *)&pkthdr->ts.tv_sec));
    for(int i=0; i < pkthdr->len; ++i)
    {
        printf(" %02x", packet[i]);
        if ((i + 1) % 16 == 0)
        {
            printf("\n");
        }
    }
}