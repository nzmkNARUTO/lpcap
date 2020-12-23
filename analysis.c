#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
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

void packetProcess(struct pcap_pkthdr* pkthdr, u_char* packet, int count){

    printf("count:%d\n",count);
    printf("Packet len:%d, Bytes:%d, Received time:%s", pkthdr->len, pkthdr->caplen, ctime((const time_t *)&pkthdr->ts.tv_sec));
    u_short type = printEthernet(packet);
    switch (type)
    {
    case ETHERTYPE_IP:
        printf("Ethernet protocol is IP protocol\n");
        uint8_t ip_type = printIP(packet);
        switch(ip_type){
            case 1:
                printf("Transport protocol is ICMP protocol\n");
                newPacket(pkthdr->caplen, 2);
                printICMP(packet, pkthdr->len);
                break;
            case 6:
                printf("Transport protocol is TCP protocol\n");
                newPacket(pkthdr->caplen, 1);
                printTCP(packet, pkthdr->len);
                break;
            case 17:
                printf("Transport protocol is UDP protocol\n");
                newPacket(pkthdr->caplen, 1);
                printUDP(packet, pkthdr->len);
                break;
            default:
                newPacket(pkthdr->caplen, 1);
                printf("Known protocol\n");
                break;
        }
        break;
    case ETHERTYPE_ARP:
        printf("Ethernet protocol is ARP protocol\n");
        newPacket(pkthdr->caplen, 3);
        printARP(packet, pkthdr->len);
        break;
    case ETHERTYPE_REVARP:
        printf("Ethernet protocol is RARP protocol\n");
        newPacket(pkthdr->caplen, 3);
        printARP(packet, pkthdr->len);
        break;
    default:
        printf("Unkown protocol\n");
        newPacket(pkthdr->caplen, 3);
        break;
    }
}

u_short printEthernet(u_char* packet){
    struct ether_header *ethhdr;
    u_short ether_type;
    char mac[18];
    ethhdr = (struct ether_header *)packet;
    printf("Source mac address:");
    macNtoa(ethhdr->ether_shost, mac);
    printf("%s\n",mac);
    printf("Destination mac address:");
    macNtoa(ethhdr->ether_dhost, mac);
    printf("%s\n",mac);
    ether_type = ntohs(ethhdr->ether_type);
    printf("Ethernet type:");
    printf("%04X\n",ether_type);
    return ether_type;
}

uint8_t printIP(u_char *packet){
    struct ip *iphdr;
    char ip[16];
    char tos[18];
    iphdr = (struct ip*)(packet+sizeof(struct ether_header));
    printf("Source ip address:");
    ipFtoa((u_char *)&(iphdr->ip_src), ip);
    printf("%s\n",ip);
    printf("Destination ip address:");
    ipFtoa((u_char *)&(iphdr->ip_dst), ip);
    printf("%s\n",ip);
    printf("TOS:");
    ipTtos(iphdr->ip_tos, tos);
    printf("%s\n",tos);
    printf("Transport protocol:");
    printf("%d\n", iphdr->ip_p);
    return iphdr->ip_p;
}

void printICMP(u_char *packet, int len){
    struct icmp *icmphdr;
    icmphdr = (struct icmp*)(packet+sizeof(struct ether_header)+sizeof(struct ip));
    printf("ICMP type:");
    printf("%d\n",icmphdr->icmp_type);
    printf("ICMP code:");
    printf("%d\n",icmphdr->icmp_code);
    printf("Payload:\n");
    dumpPacket(packet, len);
}

void printTCP(u_char *packet, int len){
    struct tcphdr *tcph;
    tcph = (struct tcphdr*)(packet+sizeof(struct ether_header)+sizeof(struct ip));
    printf("Source port:%d\n", ntohs(tcph->source));
    printf("Destination port:%d\n", ntohs(tcph->dest));
    printf("Flags:");
    if(!(tcph->ack || tcph->fin || tcph->psh || tcph->rst || tcph->syn || tcph->urg))
        printf("None");
    else{
        if(tcph->ack)
            printf("|ACK|");
        if(tcph->fin)
            printf("|FIN|");
        if(tcph->psh)
            printf("|PSH|");
        if(tcph->rst)
            printf("|RSH|");
        if(tcph->syn)
            printf("|SYN|");
        if(tcph->urg)
            printf("|URG|");
    }
    printf("\n");
    printf("Payload:\n");
    dumpPacket(packet, len);
}

void printUDP(u_char *packet, int len){
    struct udphdr *udph;
    udph = (struct udphdr*)(packet+sizeof(struct ether_header)+sizeof(struct ip));
    printf("Source port:%d\n", ntohs(udph->source));
    printf("Destination port:%d\n", ntohs(udph->dest));
    printf("Payload:\n");
    dumpPacket(packet, len);
}

void printARP(u_char *packet, int len){
    struct arphdr *arph;
    char mac[18];
    char ip[16];
    arph = (struct arphdr*)(packet+sizeof(struct ether_header));
    printf("Sender mac address:");
    macNtoa(arph->__ar_sha, mac);
    printf("%s\n", mac);
    printf("Target mac address:");
    macNtoa(arph->__ar_tha, mac);
    printf("%s\n", mac);
    printf("Sender ip address:");
    ipFtoa(arph->__ar_sip, ip);
    printf("%s\n", ip);
    printf("Target ip address:");
    ipFtoa(arph->__ar_tip, ip);
    printf("%s\n", ip);
    printf("Payload:\n");
    dumpPacket(packet, len);
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

void print(const u_char* payload, int len, int offset, int maxlen){
    printf("%.5d ",offset);
    int max=maxlen;
    for(int i=0;i<16;i++){
        if((len-i)>0){
            printf("%.2x ",payload[max-len+i]);
        }else{
            printf("   ");
        }
    }
    printf("\t");
    for(int i=0;i<16;i++){
        if(isprint(payload[max-len+i])){
            printf("%c",payload[max-len+i]);
        }else{
            printf(".");
        }
    }
}

void dumpPacket(const u_char* payload,int len){
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
                print(payload,len_rem,offset,maxlen);
                offset=offset+len_rem;
                printf("\n");
                break;
            }
        }else{
            print(payload,len_rem,offset,maxlen);
            offset=offset+16;
            printf("\n");
        }
        len_rem=len_rem-line_width;
    }
}