#ifndef _RR_H
#define _RR_H

#include <stdlib.h>
#include <stdint.h>

typedef union RRData {
    struct {
        void *ptr;
        size_t size;
    } buf;
    uint64_t u64;
    uint32_t u32;
} RRData;

typedef struct RRNode {
    int id;
    RRData data;
    struct RRNode *next;
    struct RRNode *prev;
} RRNode;

typedef struct RRing {
    RRNode *head;
    RRNode *tail;
    RRNode *cur;
    size_t size;
} RRing;


RRing*  rr_create(void);
RRNode* rr_add(RRing *rr, RRData data);
void rr_del_tail(RRing *rr);
void rr_del(RRing *rr);

#endif // _RR_H
