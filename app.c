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
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/msg.h>
#include <errno.h>

#include "app.h"
#include "capture.h"
#include "analysis.h"
#include "statistic.h"

#define ENTER 10
#define ESCAPE 27
#define TAB 9

struct args args;
struct packets packets;

int main(){
    setlocale(LC_ALL,"");
    init(&args.packets);
    args.device = NULL;
    args.pid = 0;
    args.msgid = -1;
    pthread_t thread;
    initCurses();
    int x,y;
    getmaxyx(stdscr, y, x);
    mvwprintw(stdscr, y/2, x/2-12, "WELCOME TO mySNIFFER!!!");
    getch();
    args.msgid = msgget((key_t)1234, 0666|IPC_CREAT);
    if(args.msgid == -1){
        perror("msgget failed!\n");
        exit(-1);
    }
    initCurses();
    drawMenuBar();
    args.packet_window = initPacketWindow();
    args.statistic_window = initStatisticWindow();
    //WINDOW *dump_window = initDumpWindow();
    while(1){
        int key;
        key = getch();
        if(key == KEY_F(1)){
            logStatus("F1\n");
            WINDOW **menu = drawMenu();
            key = scrollMenu(menu, 5);
            deleteMenus(menu, 5);
            if(key == 4){
                if(args.pid > 0){
                logStatus("kill\n");
                kill(args.pid, SIGINT);
                }else{
                    logStatus("can not kill self\n");
                }
                pcap_close(args.device);
                remove("./temp.pcap");
                break;
            }else if(key == 0){
                args.devices = getDevices();
                pcap_if_t *p = args.devices;

                int device_count = 0;
                for(int i = 0; p; i++){
                    p = p->next;
                    device_count++;
                }

                int x,y;
                getmaxyx(stdscr, y, x);
                WINDOW **device_menu = drawDevices(y/2-device_count/2, x/2-15, device_count, args.devices);
                key = scrollMenu(device_menu, device_count);
                deleteMenus(device_menu, device_count);
                if(key == -1)
                    continue;
                for(; key>0; key--)
                    args.devices = args.devices->next;
                //args.device = openDevice(args.devices->name);
            }else if(key == 1){
                args.device = openDeviceOffline("./test.pcap");
            }else if(key == 2){
                setFilter(args.device, "icmp");
            }else if(key == 3){
                logStatus("3\n");
                int p = vfork();
                if(p == -1){
                    logStatus("Save subprocess failed\n");
                }
                if(p > 0){
                    continue;
                }
                logStatus("Save as test.pcap\n");
                if(execlp("mv","mv", "./temp.pcap","./test.pcap",NULL) == -1){
                    logStatus("Execlp error\n");
                }
            }else{
                continue;
            }
        }else if(key == KEY_F(2)){
            logStatus("F2\n");
            signal(SIGCHLD, SIG_IGN);
            args.device = openDevice(args.devices->name);//TODO:共享文件描述符的问题还未解决
            args.pid = fork();
            if(args.pid == -1){
                logStatus("Creat sub process failed\n");
                pcap_close(args.device);
            }
            if(args.pid > 0){
                signal(SIGUSR1, msgProcess);
                setTime();
                continue;
            }
            logStatus("Start\n");
            signal(SIGINT, sigProcess);
            struct msg message;
            message.msg_type = 1;
            for(int i=0;;i++)
            {
                memset(&message.packet, 0, sizeof(message.packet));
                u_char *packet = capturePacket(args.device, &packets.pkthdr);
                if(packet == 0){
                    logStatus("packet is 0\n");
                    break;
                }
                message.packet.id = i;
                memcpy(&message.packet.pkthdr, &packets.pkthdr, sizeof(struct pcap_pkthdr));
                memcpy(message.packet.packet, packet, packets.pkthdr.caplen);
                if (msgsnd(args.msgid, (void *)&message, sizeof(struct packets), IPC_NOWAIT) == -1){
                    logStatus("msgsnd failed\n");
                }else{
                    logStatus("msgsnd success\n");
                }
                kill(getppid(), SIGUSR1);
                logStatus("kill sigusr1\n");
            }
        }else if(key == KEY_F(3)){
            logStatus("F3\n");
            if(args.pid > 0){
                logStatus("kill\n");
                kill(args.pid, SIGINT);
            }else{
                logStatus("can not kill self\n");
            }
            pcap_close(args.device);
            savePacket(args.device, &args.packets, "./temp.pcap");
        }else{
            continue;
        }
    }
    endwin();
    if(msgctl(args.msgid, IPC_RMID, 0) == -1){
        perror("msgctl(IPC_RMID) failed!\nresource has not been release!\nplease try \"ipcs -q\" and \"ipcrm -q\" mannually\n");
        exit(-1);
    }
    return 0;
}


void sigProcess(){

    logStatus("finish\n");
    exit(0);
}

void msgProcess(){
    logStatus("get sigusr1\n");
    struct msg message;
    if(msgrcv(args.msgid, (void *)&message, sizeof(struct packets), 1, 0) == -1){
        logStatus("msgrcv failed\n");
        //kill(args.pid, SIGINT);
    }else{
        logStatus("msgrcv success\n");
    }
    add(&args.packets, message.packet.id, &message.packet.pkthdr, message.packet.packet);
    packetProcess(&message.packet.pkthdr, message.packet.packet, message.packet.id, args.packet_window);
    setTime();
    args.statistic_window = initStatisticWindow();
    showInfo(args.statistic_window);
    logStatus("new signal\n");
    signal(SIGUSR1, msgProcess);
}

void initCurses(){
    initscr();
    erase();
    box(stdscr, ACS_VLINE, ACS_HLINE);
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

WINDOW *initPacketWindow(){
    int x,y;
    getmaxyx(stdscr, y, x);
    WINDOW *packet_window_box = subwin(stdscr, y-2, x/3*2-1, 1, x/3);
    box(packet_window_box, ACS_VLINE, ACS_HLINE);
    wbkgd(packet_window_box ,COLOR_PAIR(1));
    getmaxyx(packet_window_box, y, x);
    WINDOW *packet_window = derwin(packet_window_box, y-2, x-2, 1, 1);
    scroll(packet_window);
    scrollok(packet_window, TRUE);
    wsetscrreg(packet_window, 0, y-2);
    wrefresh(packet_window);
    wrefresh(packet_window_box);
    logStatus("init packet window\n");
    return packet_window;
}

WINDOW *initStatisticWindow(){
    int x,y;
    getmaxyx(stdscr,y,x);
    //printf("x:%d,y:%d\n", x, y);
    WINDOW *statistic_window_box = subwin(stdscr, y-2, x/3, 1, 1);
    box(statistic_window_box, ACS_VLINE, ACS_HLINE);
    wbkgd(statistic_window_box, COLOR_PAIR(1));
    getmaxyx(statistic_window_box, y, x);
    WINDOW *statistic_window = derwin(statistic_window_box, y-2, x-2, 1, 1);
    wrefresh(statistic_window);
    wrefresh(statistic_window_box);
    logStatus("init statistic window\n");
    return statistic_window;
}

WINDOW *initDumpWindow(){//TODO:dump window还没完成
    int x,y;
    getmaxyx(stdscr, y, x);
    WINDOW *dump_window = subwin(stdscr, y/2, x/2-1, y/2, x/2);
    box(dump_window, ACS_VLINE, ACS_HLINE);
    wbkgd(dump_window, COLOR_PAIR(1));
    wrefresh(dump_window);
    return dump_window;
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
    refresh();
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
    wattroff(menu_bar, COLOR_PAIR(6));
    wmove(menu_bar, 0, 20);
    waddstr(menu_bar, "Start");
    wattron(menu_bar, COLOR_PAIR(6));
    waddstr(menu_bar, "(F2)");
    wattroff(menu_bar, COLOR_PAIR(6));
    wmove(menu_bar, 0, 40);
    waddstr(menu_bar, "Stop");
    wattron(menu_bar, COLOR_PAIR(6));
    waddstr(menu_bar, "(F3)");
    wattroff(menu_bar, COLOR_PAIR(6));
    wrefresh(menu_bar);
}



