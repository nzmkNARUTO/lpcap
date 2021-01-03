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

/**
 * @brief subprocess signal process function
 * 
 */
void sigProcess();

/**
 * @brief parent process signal process function
 * 
 */
void msgProcess();

/**
 * @brief init packet window
 * 
 * @return WINDOW* packet window
 */
WINDOW *initPacketWindow();

/**
 * @brief init statistic window
 * 
 * @return WINDOW* statistic window
 */
WINDOW *initStatisticWindow();

/**
 * @brief init dump window
 * 
 * @return WINDOW* dump window
 */
WINDOW *initDumpWindow();

/**
 * @brief init stdscr
 * init some color pairs
 */
void initCurses();

/**
 * @brief make menu scroll
 * 
 * @param devices devices window
 * @param count devices conut
 * @return int which number user choose
 */
int scrollMenu(WINDOW **devices, int count);

/**
 * @brief draw devices window
 * 
 * @param start_row start at which row
 * @param start_col start at which colume
 * @param count divices count
 * @param devices all devices description symbel
 * @return WINDOW** devices window
 */
WINDOW **drawDevices(int start_row, int start_col, int count, pcap_if_t *devices);

/**
 * @brief delete devices window
 * 
 * @param items window to delete
 * @param count devices count
 */
void deleteMenus(WINDOW **items, int count);

/**
 * @brief draw menu
 * 
 * @return WINDOW** menu window
 */
WINDOW **drawMenu();

/**
 * @brief draw menu bar
 * 
 */
void drawMenuBar();