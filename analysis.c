#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <ncurses.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "analysis.h"
#include "statistic.h"
#include "util.h"

void packetProcess(struct pcap_pkthdr* pkthdr, u_char* packet, int count, WINDOW *packet_window){
    wattron(packet_window, COLOR_PAIR(2));
    wprintw(packet_window, "Count:%d\n", count);
    wattroff(packet_window, COLOR_PAIR(2));
    wprintw(packet_window, "Packet len:%d, Bytes:%d\nReceived time:%s", pkthdr->len, pkthdr->caplen, ctime((const time_t *)&pkthdr->ts.tv_sec));
    logStatus("process packet\n");
    u_short type = printEthernet(packet, packet_window);
    switch (type)
    {
    case ETHERTYPE_IP:
        wprintw(packet_window, "Ethernet protocol is IP protocol\n");
        uint8_t ip_type = printIP(packet, packet_window);
        switch(ip_type){
            case 1:
                wprintw(packet_window, "Transport protocol is ICMP protocol\n");
                newPacket(pkthdr->caplen, 2);
                printICMP(packet, pkthdr->len, packet_window);
                break;
            case 6:
                wprintw(packet_window, "Transport protocol is TCP protocol\n");
                newPacket(pkthdr->caplen, 1);
                printTCP(packet, pkthdr->len, packet_window);
                break;
            case 17:
                wprintw(packet_window, "Transport protocol is UDP protocol\n");
                newPacket(pkthdr->caplen, 1);
                printUDP(packet, pkthdr->len, packet_window);
                break;
            default:
                newPacket(pkthdr->caplen, 1);
                wprintw(packet_window, "Known protocol\n");
                break;
        }
        break;
    case ETHERTYPE_ARP:
        wprintw(packet_window, "Ethernet protocol is ARP protocol\n");
        newPacket(pkthdr->caplen, 3);
        printARP(packet, pkthdr->len, packet_window);
        break;
    case ETHERTYPE_REVARP:
        wprintw(packet_window, "Ethernet protocol is RARP protocol\n");
        newPacket(pkthdr->caplen, 3);
        printARP(packet, pkthdr->len, packet_window);
        break;
    default:
        wprintw(packet_window, "Unkown protocol\n");
        newPacket(pkthdr->caplen, 3);
        break;
    }
    wrefresh(packet_window);
}

u_short printEthernet(u_char* packet, WINDOW *packet_window){
    struct ether_header *ethhdr;
    u_short ether_type;
    char mac[18];
    ethhdr = (struct ether_header *)packet;
    wprintw(packet_window, "Source mac address:");
    macNtoa(ethhdr->ether_shost, mac);
    wprintw(packet_window, "%s\n",mac);
    wprintw(packet_window, "Destination mac address:");
    macNtoa(ethhdr->ether_dhost, mac);
    wprintw(packet_window, "%s\n",mac);
    ether_type = ntohs(ethhdr->ether_type);
    wprintw(packet_window, "Ethernet type:");
    wprintw(packet_window, "%04X\n",ether_type);
    return ether_type;
}

uint8_t printIP(u_char *packet, WINDOW *packet_window){
    struct ip *iphdr;
    char ip[16];
    char tos[18];
    iphdr = (struct ip*)(packet+sizeof(struct ether_header));
    wprintw(packet_window, "Source ip address:");
    ipFtoa((u_char *)&(iphdr->ip_src), ip);
    wprintw(packet_window, "%s\n",ip);
    wprintw(packet_window, "Destination ip address:");
    ipFtoa((u_char *)&(iphdr->ip_dst), ip);
    wprintw(packet_window, "%s\n",ip);
    wprintw(packet_window, "TOS:");
    ipTtos(iphdr->ip_tos, tos);
    wprintw(packet_window, "%s\n",tos);
    wprintw(packet_window, "Transport protocol:");
    wprintw(packet_window, "%d\n", iphdr->ip_p);
    return iphdr->ip_p;
}

void printICMP(u_char *packet, int len, WINDOW *packet_window){
    struct icmp *icmphdr;
    icmphdr = (struct icmp*)(packet+sizeof(struct ether_header)+sizeof(struct ip));
    wprintw(packet_window, "ICMP type:");
    wprintw(packet_window, "%d\n",icmphdr->icmp_type);
    wprintw(packet_window, "ICMP code:");
    wprintw(packet_window, "%d\n",icmphdr->icmp_code);
    wprintw(packet_window, "Payload:\n");
    dumpPacket(packet, len, packet_window);
}

void printTCP(u_char *packet, int len, WINDOW *packet_window){
    struct tcphdr *tcph;
    tcph = (struct tcphdr*)(packet+sizeof(struct ether_header)+sizeof(struct ip));
    wprintw(packet_window, "Source port:%d\n", ntohs(tcph->source));
    wprintw(packet_window, "Destination port:%d\n", ntohs(tcph->dest));
    wprintw(packet_window, "Flags:");
    if(!(tcph->ack || tcph->fin || tcph->psh || tcph->rst || tcph->syn || tcph->urg))
        wprintw(packet_window, "None");
    else{
        if(tcph->ack)
            wprintw(packet_window, "|ACK|");
        if(tcph->fin)
            wprintw(packet_window, "|FIN|");
        if(tcph->psh)
            wprintw(packet_window, "|PSH|");
        if(tcph->rst)
            wprintw(packet_window, "|RSH|");
        if(tcph->syn)
            wprintw(packet_window, "|SYN|");
        if(tcph->urg)
            wprintw(packet_window, "|URG|");
    }
    wprintw(packet_window, "\n");
    wprintw(packet_window, "Payload:\n");
    dumpPacket(packet, len, packet_window);
}

void printUDP(u_char *packet, int len, WINDOW *packet_window){
    struct udphdr *udph;
    udph = (struct udphdr*)(packet+sizeof(struct ether_header)+sizeof(struct ip));
    wprintw(packet_window, "Source port:%d\n", ntohs(udph->source));
    wprintw(packet_window, "Destination port:%d\n", ntohs(udph->dest));
    wprintw(packet_window, "Payload:\n");
    dumpPacket(packet, len, packet_window);
}

void printARP(u_char *packet, int len, WINDOW *packet_window){
    struct arphdr *arph;
    char mac[18];
    char ip[16];
    arph = (struct arphdr*)(packet+sizeof(struct ether_header));
    wprintw(packet_window, "Sender mac address:");
    macNtoa(arph->__ar_sha, mac);
    wprintw(packet_window, "%s\n", mac);
    wprintw(packet_window, "Target mac address:");
    macNtoa(arph->__ar_tha, mac);
    wprintw(packet_window, "%s\n", mac);
    wprintw(packet_window, "Sender ip address:");
    ipFtoa(arph->__ar_sip, ip);
    wprintw(packet_window, "%s\n", ip);
    wprintw(packet_window, "Target ip address:");
    ipFtoa(arph->__ar_tip, ip);
    wprintw(packet_window, "%s\n", ip);
    wprintw(packet_window, "Payload:\n");
    dumpPacket(packet, len, packet_window);
}

void macNtoa(u_char *macaddr, char* mac_string){
    sprintf(mac_string,"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",macaddr[0],macaddr[1],macaddr[2],macaddr[3],macaddr[4],macaddr[5]);
}

void ipFtoa(u_char *ipaddr, char* ip_string){
    sprintf(ip_string, "%d.%d.%d.%d", ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);
}

void ipTtos(uint8_t tos, char* tos_string){
    int t[8];
    int mod=256;
    for(int i=0;i<8;i++){
        t[i] = (tos%mod)%2;
        mod/=2;
    }
    sprintf(tos_string, "|%d|%d|%d|%d|%d|%d|%d|%d|", t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7]);
}

void print(const u_char* payload, int len, int offset, int maxlen, WINDOW *packet_window){
    wprintw(packet_window, "%.5d ",offset);
    int max=maxlen;
    for(int i=0;i<16;i++){
        if((len-i)>0){
            wprintw(packet_window, "%.2x ",payload[max-len+i]);
        }else{
            wprintw(packet_window, "   ");
        }
    }
    wprintw(packet_window, "\t");
    for(int i=0;i<16;i++){
        if(isprint(payload[max-len+i])){
            wprintw(packet_window, "%c",payload[max-len+i]);
        }else{
            wprintw(packet_window, ".");
        }
    }
}

void dumpPacket(const u_char* payload,int len, WINDOW *packet_window){
    int line_width=16;
    int len_rem=len;
    int maxlen=len;
    int offset=0;
    while (1)
    {
        if(len_rem<line_width){
            if(len_rem==0){
                break;
            }else{
                print(payload,len_rem,offset,maxlen, packet_window);
                offset=offset+len_rem;
                wprintw(packet_window, "\n");
                break;
            }
        }else{
            print(payload,len_rem,offset,maxlen, packet_window);
            offset=offset+16;
            wprintw(packet_window, "\n");
        }
        len_rem=len_rem-line_width;
    }
}