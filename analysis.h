#include <pcap.h>

void packetProcess(struct pcap_pkthdr* pkthdr, u_char* packet, int count);