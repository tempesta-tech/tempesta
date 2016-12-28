#ifndef HELPERS_H
#define HELPERS_H

#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <assert.h>
#include <errno.h>

//#define DEBUG 3

#define BUG_ON(expr) assert(!(expr))

#define PAGE_SIZE 4096
#define PAGE_MASK (~(PAGE_SIZE-1))

#define likely(a)	__builtin_expect((a), 1)
#define unlikely(a)	__builtin_expect((a), 0)

#define __data_offset(pos)						\
    (size_t)((pos) - data)
#define __data_remain(pos)						\
    (len - __data_offset(pos))
#define __data_available(pos, num)					\
    (num <= __data_remain(pos))

#define TFW_BANNER	"[tempesta] "
#define KERN_ERR    "ERROR: "
#define KERN_WARNING "Warning: "

#define __TFW_DBG1(...) printf(TFW_BANNER "  " __VA_ARGS__)
#define __TFW_DBG2(...) printf(TFW_BANNER "    " __VA_ARGS__)
#define __TFW_DBG3(...) printf(TFW_BANNER "      " __VA_ARGS__)

#if defined(DEBUG) && (DEBUG >= 1)
#define TFW_DBG(...) __TFW_DBG1(__VA_ARGS__)
#else
#define TFW_DBG(...)
#endif

#if defined(DEBUG) && (DEBUG >= 2)
#define TFW_DBG2(...) __TFW_DBG2(__VA_ARGS__)
#else
#define TFW_DBG2(...)
#endif

#if defined(DEBUG) && (DEBUG >= 3)
#define TFW_DBG3(...) __TFW_DBG3(__VA_ARGS__)
#define TFW_PSSE(...) __print_sse(__VA_ARGS__)
#else
#define TFW_DBG3(...)
#define TFW_PSSE(...)
#endif

#if defined(DEBUG) && (DEBUG >= 1)
#define __CALLSTACK_MSG(...)						\
do {									\
    printf(__VA_ARGS__);						\
} while (0)

#define TFW_ERR(...)	__CALLSTACK_MSG(KERN_ERR TFW_BANNER		\
                    "ERROR: " __VA_ARGS__)
#define TFW_WARN(...)	__CALLSTACK_MSG(KERN_WARNING TFW_BANNER		\
                    "Warning: " __VA_ARGS__)
#define TFW_LOG(...)	pr_info(TFW_BANNER __VA_ARGS__)
#else
#define TFW_ERR(...)	printf(TFW_BANNER "ERROR: " __VA_ARGS__)
#define TFW_WARN(...)	printf(TFW_BANNER "Warning: " __VA_ARGS__)
#define TFW_LOG(...)	printf(TFW_BANNER __VA_ARGS__)
#endif

#define EXPORT_SYMBOL(sym)

#define min(a, b) ((a) < (b) ? (a):(b))
#define max(a, b) ((a) > (b) ? (a):(b))

#define __FSM_STATE(st) case st: st: TFW_DBG("\n\tState: %s\n", #st);

typedef unsigned char u_char;

#endif // HELPERS_H

