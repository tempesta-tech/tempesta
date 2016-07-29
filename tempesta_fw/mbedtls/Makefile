ccflags-y = $(MBEDTLS_CFLAGS)

mbedtls-src = $(wildcard $(MBEDTLS)/mbedtls/library/*.c)
mbedtls-obj = $(patsubst %.c, %.o, $(mbedtls-src))

obj-y = lk.o $(subst $(MBEDTLS),,$(mbedtls-obj))
