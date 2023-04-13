#ifndef __HASH_H__
#define __HASH_H__
#include "perf.h"
#include "cipher.h"

int test_hmac_loop(void *args);
int test_hash_loop(void *args);

void test_hash_perf(loopargs_t *loopargs);

int test_hash_hit(const char *algo_name);


#endif
