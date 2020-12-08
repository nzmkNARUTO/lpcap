#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define MAX_SIZE 65536

typedef struct SListNode{//struct to store packet informations
    uint8_t source_mac_address[ETH_ALEN];
    uint8_t destinaion_mac_address[ETH_ALEN];
    uint16_t ether_type;

    struct ip
    {
        uint32_t source_ip_address;
        uint32_t destination_ip_address;
        uint8_t ip_protocol;

        struct tcp
        {
            uint16_t source_port;
            uint16_t destination_port;
            tcp_seq sequence_number;
            tcp_seq acknowledge_number;
            uint8_t offset;
            uint8_t flags;
            uint16_t window;
            uint16_t checksum;
        };

        struct udp
        {
            uint16_t source_port;
            uint16_t destinaion_port;
            uint16_t length;
            uint16_t checksum;
        };

        struct icmp
        {
            uint8_t type;
            uint8_t code;
            uint16_t checksum;
        };

    };

    struct arp
    {
        unsigned short int hardware_address;
        unsigned short int protocol_address;
        unsigned short int opcode;
    };

    char* packet[MAX_SIZE];
    struct SListNode* _PNext;
}Node,*PNode;

typedef struct SList{       //封装了链表的结构
    PNode _pHead;//指向链表第一个节点
}SList;

void SListInit(SList*s);//链表的初始化

//在链表s最后一个节点后插入一个值为data的节点
void SListPushBack(SList* s, PNode data);

// 在链表中查找值为data的节点，找到返回该节点的地址，否则返回NULL
PNode SListFind(SList* s, PNode data);

// 获取链表中有效节点的个数
int SListSize(SList* s);

// 检测链表是否为空
int SListEmpty(SList* s);

// 销毁链表
void SListDestroy(SList* s);

//打印链表
void SListPrint(SList* s);