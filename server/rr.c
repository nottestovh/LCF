#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rr.h"


RRing* rr_create(void)
{
    RRing *rr = (RRing*)malloc(sizeof(RRing));
    if ( !rr ) return NULL;

    rr->head = rr->tail = rr->cur = NULL;
    rr->size = 0;

    return rr;
}


RRNode* rr_add(RRing *rr, RRData data)
{
    if ( !rr ) return NULL;
    if ( rr->size == UINT32_MAX ) return NULL;

    RRNode *node = (RRNode*)malloc(sizeof(RRNode));
    if ( !node ) return NULL;
    
    node->data = data;
    node->id = rr->size;
    if ( rr->size == 0 ) {
        node->next = node->prev = node;
        rr->head = rr->tail = rr->cur = node;
    } else {
        node->prev = rr->tail;
        node->next = rr->head;
        rr->tail->next = node;
        rr->head->prev = node;
        rr->tail = node;
    }
    rr->size++;

    return node;
}


void rr_del_tail(RRing *rr)
{
    if ( !rr || !rr->head || !rr->tail ) return;
    
    if ( rr->head == rr->tail ) {
        free(rr->tail);
        rr->head = rr->tail = NULL;
    } else {
        RRNode *old_tail = rr->tail;
        RRNode *new_tail = old_tail->prev;

        new_tail->next = rr->head;
        rr->head->prev = new_tail;
        rr->tail = new_tail;

        if (rr->cur == old_tail)
            rr->cur = rr->tail;

        free(old_tail);
    }
    
    if (rr->size > 0)
        rr->size--;
}


void rr_del(RRing *rr)
{
    if ( !rr || !rr->head || !rr->tail ) return;

    RRNode *cur = rr->head;
    RRNode *next = NULL;

    if ( rr->head == rr->tail ) {
        free(rr->tail);
        rr->head = rr->tail = NULL;
    } else {
        do {
            next = cur->next;
            free(cur);
            cur = next;
        } while ( cur && cur != rr->head );
    }

    rr->head = rr->tail = NULL;
    rr->size = 0;

    free(rr);
}
