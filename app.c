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

#define WIN

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
    WINDOW *welcome;
    welcome = derwin(main_window, 1, 24, size.ws_row/2, size.ws_col/2-12);
    mvwprintw(welcome, 0, 0, "WELCOME TO mySNIFFER!!!");
    wrefresh(welcome);
    getch();
    werase(welcome);
    delwin(welcome);
    wrefresh(main_window);
    
    #endif

    /*
    */
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

    #ifdef WIN
        WINDOW* interactor;
        interactor = derwin(main_window, device_count+3, 30, 1, 1);
        box(interactor, ACS_VLINE, ACS_HLINE);
        p = devices;
        mvwprintw(interactor, 1, 1, "Please choose an interface:");
        for(int i = 0; p; i++){
            mvwprintw(interactor, i+2, 1, "[%d]%s", i, p->name);
            p=p->next;
        }
        wrefresh(interactor);
        int c = 0;
        c = getch()-'0';
        werase(interactor);
        delwin(interactor);
        touchwin(main_window);
        wrefresh(main_window);
        refresh();
        //getch();
    #endif

    /*
    printf("Please choice a device:\n");
    int c;
    scanf("%d", &c);
    printf("----------------------------------------------------------\n");
    */
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