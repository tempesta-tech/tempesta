#ifndef __TFW_FUZZER_H__
#define __TFW_FUZZER_H__

int fuzz_gen(char *str, int move);

enum {
	FUZZ_VALID,
	FUZZ_INVALID,
	FUZZ_END
};

#endif /* __TFW_FUZZER_H__ */
