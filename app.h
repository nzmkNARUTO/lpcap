#pragma once
#include "util.h"

struct args
{
    pcap_t *device;
    pcap_if_t *devices;
    NList packets;
    pid_t pid;
    struct pcap_pkthdr pkthdr;
};

void *capturePacketThread(void *arg);
void sigProcess();
WINDOW *initPacketWindow();
WINDOW *initStatisticWindow();
WINDOW *initDumpWindow();

void initCurses();
int scrollMenu(WINDOW **devices, int count);
WINDOW **drawDevices(int start_row, int start_col, int count, pcap_if_t *devices);
void deleteMenus(WINDOW **items, int count);
WINDOW **drawMenu();
void drawMenuBar();