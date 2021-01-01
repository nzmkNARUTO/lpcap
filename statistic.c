#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ncurses.h>

#include "util.h"

static time_t start;
static time_t finish;
static int flag = 1;
static int packet_count = 0;
static double packet_length = 0;
static int ip_packet = 0;
static double ip_length = 0;
static int icmp_packet = 0;
static double icmp_length = 0;
static int unknow_packet = 0;
static double unknow_length = 0;

void setTime(){
    if(flag){
        start = time(0);
        flag = 0;
    }else{
        finish = time(0);
    }
}

void newPacket(int length, int type){
    if(type == 1){
        ip_packet++;
        ip_length+=length;
        packet_count++;
        packet_length+=length;
    }else if(type == 2){
        icmp_packet++;
        icmp_length+=length;
        packet_count++;
        packet_length+=length;
    }else{
        unknow_packet++;
        unknow_length+=length;
        packet_count++;
        packet_length+=length;
    }
}

void showInfo(WINDOW *statistic_window){
    char time[64];
    strftime(time, sizeof(time), "%Y-%m-%d %H:%M:%S", localtime(&start));
    wprintw(statistic_window, "Start at: %s\n", time);
    strftime(time, sizeof(time), "%Y-%m-%d %H:%M:%S", localtime(&finish));
    wprintw(statistic_window, "Finish at: %s\n", time);
    wprintw(statistic_window, "Total packet: %d\n", packet_count);
    wprintw(statistic_window, "Total size: %.0lf bytes\n", packet_length);
    wprintw(statistic_window, "Speed: %.0lf bytes/s\n", packet_length/(finish-start));
    wprintw(statistic_window, "IP packet: %d\n", ip_packet);
    wprintw(statistic_window, "IP packet size %.0lf bytes\n", ip_length);
    wprintw(statistic_window, "ICMP packet: %d\n", icmp_packet);
    wprintw(statistic_window, "ICMP packet size: %.0lf bytes\n", icmp_length);
    wprintw(statistic_window, "Unknow packet: %d\n", unknow_packet);
    wprintw(statistic_window, "Unknow packet size: %.0lf bytes\n", unknow_length);
    //log("show info\n");
    wrefresh(statistic_window);
}



