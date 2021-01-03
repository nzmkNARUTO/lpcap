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

/**
 * @brief Set the Filter
 * 
 * @param device device to use
 * @param filter filter boolean string
 */
void setFilter(pcap_t *device, char *filter);

/**
 * @brief open a device to capture packet
 * 
 * @param device_name which device to use
 * @return pcap_t* pcap device description symble
 */
pcap_t* openDevice(pcap_if_t *device_name);

/**
 * @brief open a file offline
 * 
 * @param file path to file
 * @return pcap_t* pcap device description symble
 */
pcap_t *openDeviceOffline(char *file);

/**
 * @brief save packet to a file
 * 
 * @param device capture device
 * @param n packet list
 * @param file path to save file
 */
void savePacket(pcap_t *device, NList *n, char* file);
