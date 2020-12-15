#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
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

void capturePacket(pcap_if_t *device_name){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *device = pcap_open_live(device_name, MAXSIZE, 1, 0, errbuf);
    if(!device){
        //log("Error:pcap_open_live error");
        //log(errbuf);
        printf("Error:pcap_open_live error, %s", errbuf);
        exit(1);
    }
    pcap_dumper_t *out;
    out = pcap_dump_open(device, "/tmp/pcap/temp.pcap");
    if(!out) {
        printf("Error on opening output file\n");
        exit(-1);
    }
    pcap_loop(device, 10, packetProcess, (u_char *)out);
    pcap_dump_flush(out);
    pcap_dump_close(out);
    pcap_close(device);
}