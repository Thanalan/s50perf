#ifndef _RAND_H_
#define _RAND_H_

#include "perf.h"
#include "cipher.h"

void test_rand_perf(loopargs_t *loopargs);

int test_rand_hit(const char *algo_name);

#endif

