#ifndef __TFW_FUZZER_H__
#define __TFW_FUZZER_H__

int fuzz_gen(char *str, int move, int type);

enum {
	FUZZ_VALID,
	FUZZ_INVALID,
	FUZZ_END
};

enum {
	FUZZ_REQ,
	FUZZ_RESP
};

#endif /* __TFW_FUZZER_H__ */
