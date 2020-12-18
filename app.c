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

int main(){
    /*
    struct winsize size;
    ioctl(STDIN_FILENO,TIOCGWINSZ,&size);
    initscr();
    box(stdscr, ACS_VLINE,ACS_HLINE);
    refresh();
    WINDOW* main_window;
    main_window = newwin(size.ws_row-2, size.ws_col-2, 1, 1);
    box(main_window, ACS_VLINE, ACS_HLINE);
    wrefresh(main_window);
    WINDOW* interactor;
    interactor = derwin(stdscr, 5, 10, 1, 1);
    box(interactor, ACS_VLINE, ACS_HLINE);
    wrefresh(interactor);
    refresh();
    getch();
    endwin();
    */
    pcap_if_t *devices = getDevices();
    pcap_if_t *p = devices;
    for(int i = 0; p; i++){
        printf("[%d] %s\n", i, p->name);
        p = p->next;
    }
    printf("Please choice a device:\n");
    int c;
    scanf("%d", &c);
    printf("----------------------------------------------------------\n");
    for(; c>0; c--)
        devices = devices->next;
    pcap_t *device = openDevice(devices->name);
    struct pcap_pkthdr pkthdr;
    for(int i=1;i<=100;i++){
        u_char *packet = capturePacket(device, &pkthdr, "ip");
        packetProcess(&pkthdr, packet, i);
        printf("----------------------------------------------------------\n");
        printf("%d\n",i);
    }
    pcap_close(device);
    return 0;
}