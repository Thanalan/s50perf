#ifndef _RSA_H_
#define _RSA_H_

#include "perf.h"

//int init_rsa_data(loopargs_t *loopargs, int loopargs_len);

//void free_rsa_data(loopargs_t *loopargs, int loopargs_len);

void test_perf_for_rsa(loopargs_t *loopargs);

void show_results_for_rsa(uint16_t thread_id);

int test_hit_for_rsa(const char *algo_name);

int do_multi_buf_rsa(char *buf, int n);

#endif

