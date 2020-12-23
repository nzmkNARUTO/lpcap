#include <stdio.h>
#include <pcap.h>
#include <ncurses.h>
#include <termios.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include "app.h"
#include "capture.h"
#include "analysis.h"
#include "statistic.h"

//#define WIN

int main(){
    #ifdef WIN
    struct winsize size;//get windows size
    ioctl(STDIN_FILENO,TIOCGWINSZ,&size);
    initscr();
    box(stdscr, ACS_VLINE,ACS_HLINE);
    refresh();
    WINDOW* main_window;
    main_window = newwin(size.ws_row-2, size.ws_col-2, 1, 1);
    box(main_window, ACS_VLINE, ACS_HLINE);
    wrefresh(main_window);
    refresh();
    #endif

    pcap_if_t *devices = getDevices();
    pcap_if_t *p = devices;
    int device_count = 0;
    for(int i = 0; p; i++){
        printf("[%d] %s\n", i, p->name);
        p = p->next;
        device_count++;
    }

    #ifdef WIN
        WINDOW* interactor;
        interactor = derwin(main_window, device_count+2, 30, 1, 1);
        box(interactor, ACS_VLINE, ACS_HLINE);
        p = devices;
        for(int i = 0; p; i++){
            mvwprintw(interactor, i+1, 1, "[%d]%s", i, p->name);
            p=p->next;
        }
        wrefresh(interactor);
        getch();
        wrefresh(main_window);
        refresh();
        getch();
    #endif


    printf("Please choice a device:\n");
    int c;
    scanf("%d", &c);
    printf("----------------------------------------------------------\n");
    for(; c>0; c--)
        devices = devices->next;
    setTime();
    pcap_t *device = openDevice(devices->name);
    struct pcap_pkthdr pkthdr;
    NList packets;
    init(&packets);
    for(int i=1;i<=100;i++){
        u_char *packet = capturePacket(device, &pkthdr, "");
        add(&packets, i, &pkthdr, packet);
        packetProcess(&pkthdr, packet, i);
        printf("----------------------------------------------------------\n");
    }
    savePacket(device, &packets);
    pcap_close(device);
    setTime();
    showInfo();

    #ifdef WIN
    endwin();
    #endif

    //show(&packets);
    return 0;
}