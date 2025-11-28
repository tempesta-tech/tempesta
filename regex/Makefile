obj-m := xdp_rex.o

CC_FLAGS_HSRUNTIME	:= -isystem $(shell $(CC) -print-file-name=include)
CC_FLAGS_REMOVE_SIMD	:= -mno-80387 -mno-fp-ret-in-387 -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx
CC_FLAGS_HSRUNTIME	+= -DHAVE_SSE2
CC_FLAGS_SIMD		:= -msse4.2 -msse4.1
CC_FLAGS_HSRUNTIME	+= -DHAVE_SSE41 -DHAVE_SSE42
CC_FLAGS_SIMD		+= -mavx -mavx2
CC_FLAGS_HSRUNTIME	+= -DHAVE_AVX -DHAVE_AVX2
CC_FLAGS_SIMD		+= -mavx512f -mavx512cd -mavx512bw -mavx512vl -mavx512vnni
CC_FLAGS_HSRUNTIME	+= -DHAVE_AVX512
#CC_FLAGS_SIMD		+= -mavx512vbmi -mavx512vbmi2 -mavx512vnni
#CC_FLAGS_HSRUNTIME	+= -DHAVE_AVX512VBMI

CC_FLAGS_HSRUNTIME		+= $(CC_FLAGS_SIMD)
CC_FLAGS_REMOVE_HSRUNTIME	:= $(CC_FLAGS_REMOVE_SIMD)
CC_FLAGS_HSRUNTIME		+= -Wframe-larger-than=2048
CC_FLAGS_HSRUNTIME		+= -std=gnu11

ccflags-y			+= -I$(src) -I$(src)/kmod -I$(src)/../
ccflags-y			+= $(CC_FLAGS_HSRUNTIME)
ccflags-remove-y		+= $(CC_FLAGS_REMOVE_HSRUNTIME)

CFLAGS_kmod/rex.o		:= $(CC_FLAGS_REMOVE_HSRUNTIME)
CFLAGS_REMOVE_kmod/rex.o	:= $(CC_FLAGS_HSRUNTIME)
CFLAGS_alloc.o			:= $(CC_FLAGS_REMOVE_SIMD)
CFLAGS_REMOVE_alloc.o		:= $(CC_FLAGS_SIMD)
CFLAGS_scratch.o		:= $(CC_FLAGS_REMOVE_SIMD)
CFLAGS_REMOVE_scratch.o		:= $(CC_FLAGS_SIMD)
CFLAGS_database.o		:= $(CC_FLAGS_REMOVE_SIMD)
CFLAGS_REMOVE_database.o	:= $(CC_FLAGS_SIMD)

xdp_rex-m	:= kmod/rex.o               \
		   alloc.o                  \
		   scratch.o                \
		   runtime.o                \
		   database.o               \
		   hs_version.o             \
		   stream_compress.o        \
		   fdr/fdr.o                \
		   fdr/teddy_avx2.o         \
		   fdr/teddy.o              \
		   hwlm/hwlm.o              \
		   hwlm/noodle_engine.o     \
		   nfa/accel.o              \
		   nfa/castle.o             \
		   nfa/gough.o              \
		   nfa/lbr.o                \
		   nfa/limex_64.o           \
		   nfa/limex_accel.o        \
		   nfa/limex_native.o       \
		   nfa/limex_simd128.o      \
		   nfa/limex_simd256.o      \
		   nfa/limex_simd384.o      \
		   nfa/limex_simd512.o      \
		   nfa/mcclellan.o          \
		   nfa/mcsheng.o            \
		   nfa/mcsheng_data.o       \
		   nfa/mpv.o                \
		   nfa/nfa_api_dispatch.o   \
		   nfa/repeat.o             \
		   nfa/sheng.o              \
		   nfa/shufti.o             \
		   nfa/tamarama.o           \
		   nfa/truffle.o            \
		   rose/block.o             \
		   rose/catchup.o           \
		   rose/init.o              \
		   rose/match.o             \
		   rose/program_runtime.o   \
		   rose/stream.o            \
		   som/som_runtime.o        \
		   som/som_stream.o         \
		   util/cpuid_flags.o       \
		   util/masked_move.o       \
		   util/multibit.o          \
		   util/simd_utils.o        \
		   util/state_compress.o    \
#
