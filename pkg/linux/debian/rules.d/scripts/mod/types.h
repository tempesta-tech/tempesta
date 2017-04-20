/* Minimal definitions for mod_devicetable.h and devicetable-offsets.c */
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef struct {
        __u8 b[16];
} uuid_le;
#define offsetof(a,b) __builtin_offsetof(a,b)
