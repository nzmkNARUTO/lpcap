#include <stdio.h>
#include <stdlib.h>

#include "app.h"
#include "pcap.h"
#include "ppro.h"
#include "pcot.h"
#include "util.h"

int main(){
    char buffer[MAXSIZE];
    int sock;
    sock = createSocket();
    int len;
    len = capturePacket(sock, buffer, MAXSIZE);
    printf("Capture a packet of %d length\n", len);
    return 0;
}