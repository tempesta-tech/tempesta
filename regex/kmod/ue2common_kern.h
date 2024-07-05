#ifndef UE2COMMON_KERN_H
#define UE2COMMON_KERN_H

#include "config.h"

#ifndef pr_fmt
#define pr_fmt(fmt) "hyperscan:%s: " fmt, __func__
#endif

/* standard types used across ue2 */

/* We use the size_t type all over the place, usually defined in stddef.h. */
#include <linux/stddef.h>
/* stdint.h for things like uintptr_t and friends */
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/compiler_attributes.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/minmax.h>
#include <linux/printk.h>

/* Linux kernel synonyms */
#define FALLTHROUGH fallthrough
#define ALIGN_ATTR(x) __aligned(x)
#define ARRAY_LENGTH(a) ARRAY_SIZE(a)
#define UNUSED __always_unused
#define HS_PUBLIC_API /* nothing */

#define ALIGN_DIRECTIVE __aligned(16)
#define ALIGN_AVX_DIRECTIVE __aligned(32)
#define ALIGN_CL_DIRECTIVE __aligned(64)

/* We append the 'a' for aligned, since these aren't common, garden variety
 * 64 bit values. The alignment is necessary for structs on some platforms,
 * so we don't end up performing accidental unaligned accesses. */
typedef u64 __aligned(8) u64a;
typedef s64 __aligned(8) s64a;

/* get the SIMD types */
#include "util/simd_types.h"

/** \brief Report identifier, used for internal IDs and external IDs (those
 * reported on match). */
typedef u32 ReportID;

/** \brief Shorthand for the attribute to shut gcc about unused parameters */

/* really_inline forces inlining always */
#if defined(HS_OPTIMIZE)
#define really_inline __always_inline __maybe_unused
#else
#define really_inline __maybe_unused
#endif

/** no, seriously, inline it, even if building in debug mode */
#define really_really_inline __always_inline __maybe_unused
#define never_inline noinline
#define alignof __alignof

/* We use C99-style "restrict". */
#define restrict __restrict

/* Align to 16-byte boundary */
#define ROUNDUP_16(a) (((a) + 0xf) & ~0xf)
#define ROUNDDOWN_16(a) ((a) & ~0xf)

/* Align to N-byte boundary */
#define ROUNDUP_N(a, n) (((a) + ((n)-1)) & ~((n)-1))
#define ROUNDDOWN_N(a, n) ((a) & ~((n)-1))

/* Align to a cacheline - assumed to be 64 bytes */
#define ROUNDUP_CL(a) ROUNDUP_N(a, 64)

/* Align ptr to next N-byte boundary */
#define ROUNDUP_PTR(ptr, n) (__typeof__(ptr))(ROUNDUP_N((uintptr_t)(ptr), (n)))
#define ROUNDDOWN_PTR(ptr, n) \
	(__typeof__(ptr))(ROUNDDOWN_N((uintptr_t)(ptr), (n)))

#define ISALIGNED_N(ptr, n) (((uintptr_t)(ptr) & ((n)-1)) == 0)
#define ISALIGNED_16(ptr) ISALIGNED_N((ptr), 16)
#define ISALIGNED_CL(ptr) ISALIGNED_N((ptr), 64)
#define ISALIGNED(ptr) ISALIGNED_N((ptr), alignof(__typeof__(*(ptr))))
#define N_CHARS 256

/* Maximum offset representable in the 'unsigned long long' we use to return
   offset values. */
#define MAX_OFFSET 0xffffffffffffffffULL

#if 0
/* Produces lots of warnings about implicit integer casts */
#define MIN min
#define MAX max
#else
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#define LIMIT_TO_AT_MOST(a, b) (*(a) = MIN(*(a), (b)))
#define ENSURE_AT_LEAST(a, b) (*(a) = MAX(*(a), (b)))

#define DEBUG_PRINTF(fmt, ...) pr_debug(fmt, ##__VA_ARGS__)

#define assert(cond) BUG_ON(!(cond))

#endif
