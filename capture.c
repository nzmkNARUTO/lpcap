#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <string.h>
#include <ncurses.h>

#include "capture.h"
#include "analysis.h"
#include "util.h"

pcap_if_t* getDevices(){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devices;
    int n;
    n = pcap_findalldevs(&devices, errbuf);
    if(n == -1)
        log("Get devices error!");
    return devices;
}

u_char* capturePacket(pcap_if_t *device_name, struct pcap_pkthdr *pkthdr, char* filter){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *device = pcap_open_live(device_name, MAXSIZE, 1, 100, errbuf);
    if(!device){
        printf("Error:pcap_open_live error, %s", errbuf);
        exit(1);
    }

    struct bpf_program bpf;
    pcap_compile(device, &bpf, filter, 1, 0);
    pcap_setfilter(device, &bpf);

    u_char *packet;
    packet = pcap_next(device, pkthdr);
    u_char *output = (u_char*)malloc(pkthdr->len);
    memcpy(output, packet, pkthdr->len);

    if (!packet)
    {
        printf("did not capture a packet!\n");
        exit(1);
    }

    pcap_dumper_t *out = pcap_dump_open_append(device, "./temp.pcap");
    if(!out) {
        printf("Error on opening output file\n");
        exit(1);
    }

    pcap_dump((u_char*)out, pkthdr, packet);
    pcap_dump_flush(out);
    pcap_dump_close(out);
    pcap_close(device);

    return output;
}