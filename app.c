#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <ncurses.h>
#include <termios.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <locale.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include "app.h"
#include "capture.h"
#include "analysis.h"
#include "statistic.h"

#define ENTER 10
#define ESCAPE 27
#define TAB 9


int main(){
    setlocale(LC_ALL,"");
    initCurses();
    struct pcap_pkthdr pkthdr;
    NList packets;
    pcap_t *device = NULL;
    init(&packets);
    struct args args;
    args.device = NULL;
    args.pkthdr = &pkthdr;
    args.packets = &packets;
    pthread_t thread;

    drawMenuBar();
    while(1){
        int key;
        key = getch();
        if(key == KEY_F(1)){
            WINDOW **menu = drawMenu();
            key = scrollMenu(menu, 5);
            deleteMenus(menu, 5);
            if(key == 4){
                endwin();
                return 0;
            }else if(key == 0){
                pcap_if_t *devices = getDevices();
                pcap_if_t *p = devices;

                int device_count = 0;
                for(int i = 0; p; i++){
                    p = p->next;
                    device_count++;
                }

                int x,y;
                getmaxyx(stdscr, y, x);
                WINDOW **device_menu = drawDevices(y/2-device_count/2, x/2-15, device_count, devices);
                key = scrollMenu(device_menu, device_count);
                deleteMenus(device_menu, device_count);

                for(; key>0; key--)
                    devices = devices->next;

                setTime();
                device = openDevice(devices->name);
                int ret = pthread_create(&thread, NULL, capturePacketThread, &args);
                if(ret != 0){
                    log("Create thread error\n");
                    exit(1);
                }
                //packetProcess(&pkthdr, packet, i);
            }else if(key == 1){

            }else if(key == 2){

            }else if(key == 3){

            }else{
                continue;
            }
        }else{
            continue;
        }


        //pcap_t *device = openDeviceOffline("temp.pcap");


        savePacket(device, &packets, "./temp.pcap");
        pcap_close(device);
        setTime();
        endwin();

        //showInfo();
        //show(&packets);
    }
    return 0;
}

void *capturePacketThread(void *arg){
    struct args *args = (struct args *)arg;
    for(int i=0;;i++)
    {
        u_char *packet = capturePacket(args->device, args->pkthdr, "");
        log("inside\n");
        if(packet == 0)
            break;
        add(args->packets, i, args->pkthdr, packet);
    }
}

void initCurses(){
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
    init_pair(6, COLOR_RED, COLOR_WHITE);
    bkgd(COLOR_PAIR(1));
    curs_set(0);
    noecho();
    keypad(stdscr, TRUE);
    getch();
}

int scrollMenu(WINDOW **devices, int count){
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

WINDOW **drawDevices(int start_row, int start_col, int count, pcap_if_t *devices){
    WINDOW **items;
    items = (WINDOW **)malloc(sizeof(WINDOW *)*(count+1));
    items[0]=newwin(count+2, 30, start_row, start_col);
    wbkgd(items[0], COLOR_PAIR(5));
    box(items[0], ACS_VLINE, ACS_HLINE);
    for(int i=1; i<=count; i++){
        items[i] = subwin(items[0], 1, 28, start_row+i, start_col+1);
    }
    for(int i=1; i<=count; i++){
        wprintw(items[i], "[%d]%s", i, devices->name);
        devices=devices->next;
    }
    wbkgd(items[1], COLOR_PAIR(4));
    wrefresh(items[0]);
    return items;
}

void deleteMenus(WINDOW **items, int count){
    for(int i=0; i<count; i++){
        //werase(items[i]);
        delwin(items[i]);
    }
    free(items);
    touchwin(stdscr);
    refresh();
}

WINDOW **drawMenu(){
    WINDOW **items;
    items = (WINDOW **)malloc(sizeof(WINDOW *)*6);
    int x,y;
    getmaxyx(stdscr, y, x);
    items[0] = newwin(7, 25, 1, 1);
    wbkgd(items[0], COLOR_PAIR(2));
    box(items[0], ACS_VLINE, ACS_HLINE);
    items[1] = subwin(items[0], 1, 20, 2, 2);
    wprintw(items[1], "Open device");
    items[2] = subwin(items[0], 1, 20, 3, 2);
    wprintw(items[2], "Open file");
    items[3] = subwin(items[0], 1, 20, 4, 2);
    wprintw(items[3], "Set filter");
    items[4] = subwin(items[0], 1, 20, 5, 2);
    wprintw(items[4], "Save as");
    items[5] = subwin(items[0], 1, 20, 6, 2);
    wprintw(items[5], "Exit");
    wbkgd(items[1], COLOR_PAIR(1));
    wrefresh(items[0]);
    return items;
}

void drawMenuBar(){
    WINDOW *menu_bar;
    int x, y;
    getmaxyx(stdscr, y, x);
    menu_bar = subwin(stdscr, 1, x, 0, 0);
    wbkgd(menu_bar, COLOR_PAIR(5));
    waddstr(menu_bar, "Menu");
    wattron(menu_bar, COLOR_PAIR(6));
    waddstr(menu_bar, "(F1)");
    wrefresh(menu_bar);
}



