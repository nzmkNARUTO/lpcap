#pragma once
#include <pcap.h>

/**
 * @brief a node contains a packet
 * @param id the sequence of packet
 * @param pkthdr pcap defined packet header
 * @param packet packet content
 * @param next the pointer to next packet
 */
typedef struct Node {
    int id;
    struct pcap_pkthdr pkthdr;
    u_char packet[65535];
    struct ListNode* next;
}node, *pNode;


/**
 * @brief packet the node list
 * @param _pHead the head pointer of list
 */
typedef struct NodeList{
    pNode _pHead;
}NList;

/**
 * @brief init the list
 * 
 * @param n the head pointer of the list
 */
void init(NList *n);

/**
 * @brief add an element to the list
 * 
 * @param n which list
 * @param id the sequence number of the list
 * @param pkthdr pcap defiend packet header
 * @param packet packet content
 */
void add(NList *n, int id, struct pcap_pkthdr *pkthdr, u_char *packet);

/**
 * @brief get an element from list n
 * 
 * @param n which list
 * @param id the sequence number of the packet
 * @return pNode -the pointer of the element
 */
pNode get(NList *n, int id);

/**
 * @brief get the size of the list
 * 
 * @param n which list
 * @return int the size of the list
 */
int getSize(NList *n);

/**
 * @brief show the information of the list
 * (desperate)
 * @param n which list
 */
void show(NList *n);

/**
 * @brief use to log rather than
 * print to the screen
 * @param string the log string
 */
void logStatus(char* string);