#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "util.h"

void log(char* string){
    FILE* f;
    f = fopen("log.txt","a");
    fprintf(f,string);
    fclose(f);
}


void init(NList *n){
    assert(n);
    n->_pHead = NULL;
}

void add(NList *n, int id, struct pcap_pkthdr *pkthdr, u_char *packet){
    assert(n);
    pNode new_node = (pNode)malloc(sizeof(node));
    new_node->id = id;
    memcpy(&new_node->pkthdr, pkthdr, sizeof(struct pcap_pkthdr));
    memcpy(new_node->packet, packet, sizeof(u_char)*pkthdr->caplen);
    //printf("%d\n", new_node->id);
    if(n->_pHead == NULL)
        n->_pHead = new_node;
    else{
        pNode temp = n->_pHead;
        while (temp->next)
        {
            temp = temp->next;
        }
        temp->next = new_node;
    }
}

pNode get(NList *n, int id){
    pNode temp = n->_pHead;
    for(;id > 1 && temp->next; id--){
        temp = temp->next;
    }
    return temp;
}

int getSize(NList *n){
    assert(n);
    int count = 0;
    pNode temp = n->_pHead;
    while (temp)
    {
        temp=temp->next;
        count++;
    }
    return count;
}

void show(NList *n){
    assert(n);
    pNode temp = n->_pHead;
    printf("Show packet!\n");
    while (temp)
    {
        printf("%d\t", temp->id);
        temp = temp->next;
    }
}

int getach()
{
    struct termios tm, tm_old;
    int fd = 0, ch;
    if (tcgetattr(fd, &tm) < 0) {//保存现在的终端设置
        return -1;
    }

    tm_old = tm;
    cfmakeraw(&tm);//更改终端设置为原始模式，该模式下所有的输入数据以字节为单位被处理
    if (tcsetattr(fd, TCSANOW, &tm) < 0) {//设置上更改之后的设置
        return -1;
    }

    ch = getchar();
    if (tcsetattr(fd, TCSANOW, &tm_old) < 0) {//更改设置为最初的样子
        return -1;
    }

    return ch;
}