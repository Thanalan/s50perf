#ifndef _ECC_H_
#define _ECC_H_

#include "perf.h"

//int init_sm2_data(loopargs_t *loopargs, int loopargs_len);

//void free_sm2_data(loopargs_t *loopargs, int loopargs_len);

void test_perf_for_sm2(loopargs_t *loopargs);

void show_results_for_sm2(uint16_t thread_id);

int test_hit_for_sm2(const char *algo_name);

int do_multi_buf_sm2(char *buf, int n);


//ecc

//int init_ecc_data(loopargs_t *loopargs, int loopargs_len);

//void free_ecc_data(loopargs_t *loopargs, int loopargs_len);

void test_perf_for_ecc(loopargs_t *loopargs);

void show_results_for_ecc(uint16_t thread_id);

int test_hit_for_ecc(const char *algo_name);

int do_multi_buf_ecc(char *buf, int n);


#endif


