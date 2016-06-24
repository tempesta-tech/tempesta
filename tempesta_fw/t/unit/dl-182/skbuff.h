#ifndef SKBUFF_H
#define SKBUFF_H

#include <stddef.h>
#include "linux_list.h"

struct sk_buff {
    struct sk_buff * next;
    struct sk_buff * prev;
    void          * data;
    size_t          lenght;
};

typedef struct {
    struct sk_buff * head;
    struct sk_buff * tail;
} SsSkbList;

inline struct sk_buff * ss_skb_peek_tail(SsSkbList * l) {
    return l->tail;
}
void ss_skb_queue_head_init(SsSkbList * l);
void ss_skb_queue_add(SsSkbList * l, char * data, size_t len);
void ss_skb_queue_purge(SsSkbList * l);



#endif // SKBUFF_H

