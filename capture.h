#define MAXSIZE 65535

pcap_if_t* getDevices();

u_char* capturePacket(pcap_if_t *device_name, struct pcap_pkthdr *pkthdr);
