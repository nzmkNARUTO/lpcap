#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

void SListInit(SList*s) {
    assert(s);
    s->_pHead = NULL;
}

void SListPushBack(SList* s, PNode data) {
    //找链表最后一个节点
    assert(s);
    PNode pNewNode = (PNode)malloc(sizeof(Node));
    memcpy(pNewNode, data, sizeof(Node));
    if (s->_pHead == NULL) {//链表没有节点的情况
        s->_pHead = pNewNode;
    }else {
        PNode pCur = s->_pHead;
        while (pCur->_PNext) {
            pCur = pCur->_PNext;
        }
        //让最后一个节点指向新节点
        pCur->_PNext = pNewNode;
    }
}

PNode SListFind(SList* s, PNode data) {
    assert(s);
    PNode pCur = s->_pHead;
    while (pCur) {
        if (pCur->_data == data) {
            return pCur;
        }
        pCur = pCur->_PNext;
    }
    return NULL;
}

int SListSize(SList* s) {            //获取链表有效节点的个数
    assert(s);
    int count = 0;
    PNode pCur = s->_pHead;
    while (pCur) {
        count++;
        pCur = pCur->_PNext;
    }
    return count;
}

int SListEmpty(SList* s) {              //检测链表是否为空
    assert(s);
    if (s->_pHead == NULL) {
        return -1;
    }
    return 0;
}

void SListDestroy(SList* s) {            //销毁链表
    assert(s);
    if (s->_pHead == NULL) {
        free(s->_pHead);
        return;
    }
    while (s->_pHead) {
        PNode Tmp = s->_pHead->_PNext;
        free(s->_pHead);
        s->_pHead = Tmp;
    }
}

/*
void SListPrint(SList* s) {             //打印链表
    assert(s);
    PNode pCur = s->_pHead;
    while (pCur) {
        printf("%d--->", pCur->_data);
        pCur = pCur->_PNext;
    }
    printf("\n");
}
*/