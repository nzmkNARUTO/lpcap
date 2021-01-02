#pragma once
#include "util.h"

#define MAXSIZE 8000

struct packets{
    int id;
    u_char packet[MAXSIZE];
    struct pcap_pkthdr pkthdr;
};

struct args{
    pcap_t *device;
    pcap_if_t *devices;
    NList packets;
    pid_t pid;
    int msgid;
    WINDOW *packet_window;
    WINDOW *statistic_window;
};

struct msg{
    long int msg_type;
    struct packets packet;
};

void *capturePacketThread(void *arg);
void sigProcess();
void msgProcess();
WINDOW *initPacketWindow();
WINDOW *initStatisticWindow();
WINDOW *initDumpWindow();

void initCurses();
int scrollMenu(WINDOW **devices, int count);
WINDOW **drawDevices(int start_row, int start_col, int count, pcap_if_t *devices);
void deleteMenus(WINDOW **items, int count);
WINDOW **drawMenu();
void drawMenuBar();