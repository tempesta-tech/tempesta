#ifndef __MBEDTLS_LK_H__
#define __MBEDTLS_LK_H__

#ifndef CHAR_BIT
#define CHAR_BIT 8 /* Normally in <limits.h> */
#endif

#include MBEDTLS_CONFIG_FILE

#include <linux/kernel.h>
#include <linux/string.h>

#include <linux/slab.h>

extern void *calloc(size_t n, size_t size);
extern void free(void *ptr);

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_PKCS1_V15)

#include <linux/random.h>

extern int rand(void);

#endif /* MBEDTLS_SELF_TEST && MBEDTLS_PKCS1_V15 */

#endif /* __MBEDTLS_LK_H__ */
