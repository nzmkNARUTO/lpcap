#include <ncurses.h>

#include <locale.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>

int main(){
    initscr();
    int c;
    c=getch();
    getch();
    endwin();
    //printf("%c\n",c);
    return 0;
}