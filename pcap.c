#include <stdio.h>
#include <stdlib.h>

#include "pcap.h"

int createSocket(){
    int sock;
    if((sock = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_ALL))) < 0){
        perror("Socket created failed");
        exit(1);
    }
    return sock;
}

int capturePacket(int sock, char* buffer, int maxsize){
    int n;
    if((n = recvfrom(sock, buffer, maxsize, 0, NULL, NULL)) < 0){
        perror("Packet captured failed");
        exit(1);
    }
    return n;
}