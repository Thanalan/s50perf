#ifndef __HASH_H__
#define __HASH_H__
#include "perf.h"
#include "cipher.h"

int test_hmac_loop(void *args);
int test_hash_loop(void *args);

void test_hash_perf(loopargs_t *loopargs);

int test_hash_hit(const char *algo_name);

/*

//实现hash算法
#define IMPLEMENT_HASH(algo,ALGO,hmac_algo)\
if (do_sym_or_hash[ALGO_##ALGO##_IDX]) {\
        for (testnum = 0; testnum < SIZE_NUM; testnum++) {\
            print_message(#algo, 0, lengths[testnum], cmd_option.duration);\
            loopargs->test_length = lengths[testnum];\
			loopargs->hash_algo = PCE_HASH_##ALGO;\
            Time_F(START);\
            count = run_benchmark(test_##algo##_loop, loopargs);\
            d = Time_F(STOP);\
            print_result(ALGO_##ALGO##_IDX, testnum, count, d);\
        }\
    }\
if (do_sym_or_hash[ALGO_HMAC_##ALGO##_IDX]) {\
      	for (testnum = 0; testnum < SIZE_NUM; testnum++) {\
            print_message(#hmac_algo, 0, lengths[testnum],cmd_option.duration);\
            loopargs->test_length = lengths[testnum];\
			loopargs->hash_algo = PCE_HMAC_##ALGO;\
            Time_F(START);\
            count = run_benchmark(test_hmac_##algo##_loop, loopargs);\
            d = Time_F(STOP);\
            print_result(ALGO_HMAC_##ALGO##_IDX, testnum, count, d);\
        }\
    }\

#define IMPLEMENT_HASH_HIT(ALGO)\
	else if (!strcmp(algo_name, algo_names[ALGO_##ALGO##_IDX]))) \
		tlv->do_sym_or_hash[ALGO_##ALGO##_IDX] = 1; \
		ret = 0; \
	}else if (!strcmp(algo_name, algo_names[ALGO_HMAC_##ALGO##_IDX]))) \
		tlv->do_sym_or_hash[ALGO_HMAC_##ALGO##_IDX] = 1; \
		ret = 0; \
	}
    
*/


#endif
