#include <pcap.h>

void packetProcess(u_char * userarg, const struct pcap_pkthdr * pkthdr, const u_char * packet);