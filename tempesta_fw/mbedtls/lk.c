#include "lk.h"

void *calloc(size_t n, size_t size)
{
	return kzalloc(n * size, GFP_ATOMIC);
}

void free(void *ptr)
{
	kfree(ptr);
}

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_PKCS1_V15)
int rand(void)
{
	return get_random_int();
}
#endif
