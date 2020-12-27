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

struct args args;

int main(){
    int ppid = getpid();
    setlocale(LC_ALL,"");
    /*
    struct pcap_pkthdr pkthdr;
    NList packets;
    pcap_t *device = NULL;
    */
    init(&args.packets);
    args.device = NULL;
    pthread_t thread;

    while(1){
        initCurses();
        drawMenuBar();
        int key;
        key = getch();
        if(key == KEY_F(1)){
            log("F1\n");
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
                args.device = openDevice(devices->name);
                int pid = fork();
                if(pid == -1){
                    log("Creat sub process failed\n");
                }
                if(pid > 0){
                    continue;
                }
                setTime();
                for(int i=0;i<100;i++)
                {
                    u_char *packet = capturePacket(args.device, &args.pkthdr);
                    //log("inside\n");
                    if(packet == 0){
                        log("packet is 0\n");
                        break;
                    }
                    add(&args.packets, i, &args.pkthdr, packet);
                }
                pcap_close(args.device);
                setTime();
                log("finish\n");
                printf("fork size%d\n", getSize(&args.packets));
                if(pid == 0){
                    exit(0);
                }
                //packetProcess(&pkthdr, packet, i);
            }else if(key == 1){
                pcap_t *device = openDeviceOffline("temp.pcap");
            }else if(key == 2){
                setFilter(args.device, "tcp");
            }else if(key == 3){
                log("3\n");
                printf("savesize%d\n", getSize(&args.packets));
                savePacket(args.device, &args.packets, "./temp.pcap");
            }else{
                continue;
            }
        }else{
            continue;
        }




        //pcap_close(args.device);
        endwin();

        //showInfo();
        //show(&packets);
    }
    return 0;
}

/*
void *capturePacketThread(void *arg){
    struct args *args = (struct args *)arg;
    log(args->device);
    for(int i=0;;i++)
    {
        u_char *packet = capturePacket(device, &args->pkthdr, "");
        log("inside\n");
        if(packet == 0){
            log("packet is 0\n");
            break;
        }
        add(&args->packets, i, &args->pkthdr, packet);
    }
    pcap_close(device);
}
*/

void initCurses(){
    initscr();
    erase();
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
    //getch();
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



