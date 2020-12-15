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
    while(p){
        printf("%s\n",p->name);
        p = p->next;
    }
    struct pcap_pkthdr pkthdr;
    u_char *packet = capturePacket("ens33", &pkthdr);
    packetProcess(&pkthdr, packet, 1);
    printf("\n");
    return 0;
}