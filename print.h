#ifndef PRINT_H
#define PRINT_H
#include "perf.h"
void print_result(int alg, int run_no, int count, double time_used,int thread_id);
void print_message(const char *s, long num, int length, int sec_time);

void pkey_print_message(const char *str, const char *str2, long num, int bits,
                        int tm);

/*解析子进程的输出信息*/
char *sstrsep(char **string, const char *delim);

#endif
