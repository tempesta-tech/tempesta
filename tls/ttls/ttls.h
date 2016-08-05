#ifndef __TTLS_H__
#define __TTLS_H__

#ifndef CHAR_BIT
#define CHAR_BIT 8 /* Normally in <limits.h> */
#endif

#include "config.h"

#include <linux/slab.h>
#include <linux/random.h>
#include <linux/string.h>

extern void *calloc(size_t n, size_t size);
extern void free(void *ptr);

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_PKCS1_V15)
extern int rand(void);
#endif /* MBEDTLS_SELF_TEST && MBEDTLS_PKCS1_V15 */

/*
 * Include all the needed headers here.
 */

#include "aes.h"
#include "rsa.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "ssl.h"
#include "net.h"
#include "certs.h"
#include "debug.h"
#include "error.h"

#endif /* __TTLS_H__ */
