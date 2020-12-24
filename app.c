#include <stdio.h>
#include <pcap.h>
#include <ncurses.h>
#include <termios.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <locale.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include "app.h"
#include "capture.h"
#include "analysis.h"
#include "statistic.h"

#define ENTER 10
#define ESCAPE 27
#define TAB 9

#define WIN

int main(){
    setlocale(LC_ALL,"");
    #ifdef WIN
    init_curses();
    #endif

    pcap_if_t *devices = getDevices();
    pcap_if_t *p = devices;
    int device_count = 0;
    for(int i = 0; p; i++){
    #ifndef WIN
        printf("[%d] %s\n", i, p->name);
    #endif
        p = p->next;
        device_count++;
    }
    p = devices;

    int x,y;
    getmaxyx(stdscr, y, x);
    int c = scroll_devices(draw_menu(y/2-device_count/2, x/2-15, device_count, devices), device_count);
    getch();
    for(; c>0; c--)
        devices = devices->next;
    setTime();
    pcap_t *device = openDevice(devices->name);
    //pcap_t *device = openDeviceOffline("temp.pcap");
    struct pcap_pkthdr pkthdr;
    NList packets;
    init(&packets);
    for(int i=1;i<=10;i++){
        u_char *packet = capturePacket(device, &pkthdr, "tcp");
        if(packet == 0)
            break;
        //printf("%d\n",i);
        add(&packets, i, &pkthdr, packet);
        //packetProcess(&pkthdr, packet, i);
        //printf("----------------------------------------------------------\n");
    }
    savePacket(device, &packets, "./temp.pcap");
    pcap_close(device);
    setTime();
    showInfo();

    #ifdef WIN
    endwin();
    #endif

    //show(&packets);
    return 0;
}

void init_curses(){
    initscr();
    box(stdscr, ACS_VLINE, ACS_HLINE);
    int x,y;
    getmaxyx(stdscr, y, x);
    mvwprintw(stdscr, y/2, x/2-12, "WELCOME TO mySNIFFER!!!");
    wrefresh(stdscr);
    start_color();
    init_pair(1, COLOR_WHITE, COLOR_BLACK);
    init_pair(2, COLOR_BLACK, COLOR_WHITE);
    init_pair(3, COLOR_GREEN, COLOR_RED);
    init_pair(4, COLOR_WHITE, COLOR_BLUE);
    init_pair(5, COLOR_BLUE, COLOR_WHITE);
    curs_set(0);
    noecho();
    keypad(stdscr, TRUE);
    getch();
}

int scroll_devices(WINDOW **devices, int count){
    int key;
    int selected = 0;
    while(1){
        key=getch();
        switch(key){
            case KEY_DOWN:
            case KEY_UP:
                wbkgd(devices[selected+1], COLOR_PAIR(5));
                wnoutrefresh(devices[selected+1]);
                if(key == KEY_DOWN){
                    selected = (selected+1) % count;
                }else{
                    selected = (selected+count-1) % count;
                }
                wbkgd(devices[selected+1], COLOR_PAIR(4));
                wnoutrefresh(devices[selected+1]);
                doupdate();
                break;
            case ESCAPE:
                return -1;
            case ENTER:
                return selected;
        }
    }
}

WINDOW **draw_menu(int start_row, int start_col, int count, pcap_if_t *devices){
    int i;
    WINDOW **items;
    items = (WINDOW **)malloc(sizeof(WINDOW *)*(count+1));
    items[0]=newwin(count+1, 30, start_row, start_col);
    wbkgd(items[0], COLOR_PAIR(5));
    box(items[0], ACS_VLINE, ACS_HLINE);
    for(int i=1; i<=count; i++){
        items[i] = subwin(items[0], 1, 28, start_row+i, start_col+1);
    }
    for(int i=1; i<count; i++){
        wprintw(items[i], "[%d]%s", i, devices->name);
        devices=devices->next;
    }
    wbkgd(items[1], COLOR_PAIR(4));
    wrefresh(items[0]);
    return items;
}