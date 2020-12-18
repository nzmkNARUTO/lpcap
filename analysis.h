
void packetProcess(struct pcap_pkthdr* pkthdr, u_char* packet, int count);
void macNtoa(u_char *macaddr, char* mac_string);
u_short printEthernet(u_char* packet);
uint8_t printIP(u_char *packet);
void printICMP(u_char *packet, int len);
void printTCP(u_char *packet, int len);

void macNtoa(u_char *macaddr, char* mac_string);
void ipFtoa(u_char *ipaddr, char* ip_string);
void ipTtos(uint8_t tos, char* tos_string);

void dumpPacket(const u_char* payload,int len);