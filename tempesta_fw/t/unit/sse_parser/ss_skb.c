#include "ss_skb.h"
#include <string.h>
SsSkbList createSkbList(unsigned char ** text) {
    SsSkbList list;
    list.first = list.last = NULL;

    for(int i = 0; text[i]; ++text) {
       int len = strlen(text[i]);
       if (len == 0) continue;
       struct sk_buff * buf = malloc(sizeof(struct sk_buff));
       assert(buf);
       buf->prev   = list.last;
       buf->next   = NULL;
       buf->data   = text;
       buf->length = len;

       if (list.last) {
           list.last->next = buf;
           list.last = buf;
       } else {
           list.last = list.first = buf;
       }
    }
    return list;
}

void destroySkbList(SsSkbList list) {
    struct sk_buf * tmp;
    if (list.first == NULL)
        return;
    do {
         tmp = list.first;
         list.first = list.first->next;
         free(tmp);
    } while (list.first != list.last);
}

