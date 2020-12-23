#include <stdio.h>
#include <stdlib.h>
#include <time.h>

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

void showInfo(){
    char time[64];
    strftime(time, sizeof(time), "%Y-%m-%d %H:%M:%S", localtime(&start));
    printf("Start at: %s\n", time);
    strftime(time, sizeof(time), "%Y-%m-%d %H:%M:%S", localtime(&finish));
    printf("Finish at: %s\n", time);
    printf("Total packet: %d\n", packet_count);
    printf("Total size: %.0lf bytes\n", packet_length);
    printf("Speed: %.0lf bytes/s\n", packet_length/(finish-start));
    printf("IP packet: %d\n", ip_packet);
    printf("IP packet size %.0lf bytes\n", ip_length);
    printf("ICMP packet: %d\n", icmp_packet);
    printf("ICMP packet size: %.0lf bytes\n", icmp_length);
    printf("Unknow packet: %d\n", unknow_packet);
    printf("Unknow packet size: %.0lf bytes\n", unknow_length);
}



