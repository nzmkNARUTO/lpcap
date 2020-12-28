#pragma once
#include "util.h"

struct args
{
    pcap_t *device;
    pcap_if_t *devices;
    NList packets;
    struct pcap_pkthdr pkthdr;
};

void *capturePacketThread(void *arg);

void initCurses();
int scrollMenu(WINDOW **devices, int count);
WINDOW **drawDevices(int start_row, int start_col, int count, pcap_if_t *devices);
void deleteMenus(WINDOW **items, int count);
WINDOW **drawMenu();
void drawMenuBar();