#pragma once
#define MAXSIZE 8000
#include "util.h"

/**
 * @brief Get the Devices object
 * 
 * @return pcap_if_t* a pointer
 */
pcap_if_t* getDevices();

/**
 * @brief capture a packet
 * 
 * @param device_name capture using which device
 * @param pkthdr the struct to store pkthdr
 * @param filter filter string
 * @return u_char* packet connent
 */
u_char* capturePacket(pcap_t *device, struct pcap_pkthdr *pkthdr);

void setFilter(pcap_t *device, char *filter);

pcap_t* openDevice(pcap_if_t *device_name);

pcap_t *openDeviceOffline(char *file);

void savePacket(pcap_t *device, NList *n, char* file);
