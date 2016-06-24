#include <skbuff.h>
#include <stdlib.h>
#include "helpers.h"
void ss_skb_queue_head_init(SsSkbList * l) {
    l->head = l->tail = NULL;
}

void ss_skb_queue_purge(SsSkbList * l) {
    struct sk_buff * a, *b;
    a = l->head;
    while (a) {
        b = a;
        a = a->next;
        free(b);
    }
    l->head = l->tail = NULL;
}

void ss_skb_queue_add(SsSkbList * l, char * data, size_t len) {
    struct sk_buff * b = (struct sk_buff*)malloc(sizeof(*b));
    BUG_ON(b==NULL);

    b->data = data;
    b->lenght = len;

    if (!l->head) {
        l->head = l->tail = b;
        b->prev = b->next = NULL;
    } else {
        b->prev = l->tail;
        b->next = NULL;
        l->tail->next = b;
        l->tail = b;
    }


}
