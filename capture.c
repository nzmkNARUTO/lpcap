#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <ncurses.h>

#include "capture.h"

pcap_if_t* getDevices(){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devices;
    int n;
    initscr();
    refresh();
    WINDOW *win_devices;
    win_devices = newwin(10, 100, 1, 1);
    box(win_devices, ACS_VLINE, ACS_HLINE);
    n = pcap_findalldevs(&devices, errbuf);
    if(n != -1){
        mvwprintw(win_devices, 1, 1, "Get devices success!");
        for(int i=2;devices;i++){
        //printf("1\n");
            mvwprintw(win_devices, i, 1, devices->name);
            devices=devices->next;
        }
    }else{
        //printf("2\n");
        mvwprintw(win_devices, 1, 1, "Get devices failed!");
        mvwprintw(win_devices, 2, 1, errbuf);
    }
    wrefresh(win_devices);
    getch();
    delwin(win_devices);
    endwin();
    return devices;
}