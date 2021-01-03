#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <string.h>
#include <ncurses.h>

#include "capture.h"
#include "analysis.h"

pcap_if_t* getDevices(){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devices;
    int n;
    n = pcap_findalldevs(&devices, errbuf);
    if(n == -1)
        logStatus("Get devices error!");
    return devices;
}

pcap_t* openDevice(pcap_if_t *device_name){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *device = pcap_open_live(device_name, MAXSIZE, 1, 100, errbuf);
    if(!device){
        printf("Error:pcap_open_live error, %s", errbuf);
        exit(1);
    }
    logStatus("open device:");
    logStatus(device_name);
    return device;
}

pcap_t *openDeviceOffline(char *file){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *device = pcap_open_offline(file, errbuf);
    if(!device){
        printf("Error:pcap_open_live error, %s", errbuf);
        exit(1);
    }
    return device;
}

void setFilter(pcap_t *device, char *filter){
    struct bpf_program bpf;
    pcap_compile(device, &bpf, filter, 1, 0);
    pcap_setfilter(device, &bpf);
    logStatus("set filter:");
    logStatus(filter);
}

u_char* capturePacket(pcap_t *device, struct pcap_pkthdr *pkthdr){
    u_char *packet;
    packet = pcap_next(device, pkthdr);
    if (!packet)
    {
        perror("did not capture a packet!\n");
        return 0;
    }
    u_char *output = (u_char*)malloc(pkthdr->len);
    memcpy(output, packet, pkthdr->len);


    return output;
}

void savePacket(pcap_t *device, NList *n, char* file){
    pcap_dumper_t *out = pcap_dump_open_append(device, file);
    if(!out) {
        printf("Error on opening output file\n");
        exit(1);
    }
    pNode temp = n->_pHead;
    while(temp){
        pcap_dump((u_char*)out, &temp->pkthdr, temp->packet);
        temp = temp->next;
    }
    pcap_dump_flush(out);
    pcap_dump_close(out);
}