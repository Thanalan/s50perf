#include <unistd.h>
#include "print.h"
void print_result(int alg, int run_no, int count, double time_used,int thread_id)
{
	
    if (count == -1) {
        fprintf(stderr, "EVP error!\n");
        exit(1);
    }
	//if(g_thread_num == 1){
    fprintf(stderr, mr ? "+R:%d:%s:%f\n" : "%d %s's in %.2fs\n", count,
            algo_datas[alg].algo, time_used);
	//}
	
    results[thread_id][alg][run_no] =
        ((double)count) * lengths[run_no] / time_used; // 每秒处理的字节数
    latency_results[thread_id][alg][run_no] = time_used / (((double)count)); 
        
}

/*
打印运行信息，并开启计时
*/
void print_message(const char *s, long num, int length, int sec_time)
{
    (void)num;
	//if(g_thread_num == 1){
    fprintf(stderr,
            mr ? "+DT:%s:%d:%d\n" : "Doing %s for %ds on %d size blocks: ", s,
            sec_time, length);
		//}
    (void)fflush(stderr);
    alarm(sec_time);
}

void pkey_print_message(const char *str, const char *str2, long num, int bits,
                        int tm)
{
    (void)num;
    fprintf(stderr,
            mr ? "+DTP:%d:%s:%s:%d\n" : "Doing %d bit %s %s's for %ds: ", bits,
            str, str2, tm); // str  算法名， str2
    (void)fflush(stderr);
    alarm(tm);
}

/*解析子进程的输出信息*/
char *sstrsep(char **string, const char *delim)
{
    char isdelim[256];
    char *token = *string;

    if (**string == 0)
        return NULL;

    memset(isdelim, 0, sizeof isdelim);
    isdelim[0] = 1;

    while (*delim) {
        isdelim[(unsigned char)(*delim)] = 1;
        delim++;
    }

    while (!isdelim[(unsigned char)(**string)]) {
        (*string)++;
    }

    if (**string) {
        **string = 0;
        (*string)++;
    }

    return token;
}



