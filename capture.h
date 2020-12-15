#define MAXSIZE 65535

pcap_if_t* getDevices();

void capturePacket(pcap_if_t *device_name);
