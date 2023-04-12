#ifndef __AEAD_H__
#define __AEAD_H__
#include "perf.h"
#include "cipher.h"
int test_aead_enc_loop(void *args);
int test_aead_dec_loop(void *args);
void test_aead_perf(loopargs_t *loopargs);
int test_aead_hit(const char *algo_name);




#endif

