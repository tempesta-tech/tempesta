#ifndef __TTLS_THREADING_ALT_H__
#define __TTLS_THREADING_ALT_H__

#include <linux/spinlock.h>

#define mbedtls_threading_mutex_t spinlock_t

#endif /* __TTLS_THREADING_ALT_H__ */
