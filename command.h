#ifndef _COMMAND_H_
#define _COMMAND_H_

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

#define CLOG_LOG_ALWAYS(...) printf(__VA_ARGS__)

#define CLOG_LOG_ERR(...) printf(__VA_ARGS__)
#define CLOG_LOG_WRN(...) printf(__VA_ARGS__)
#define CLOG_LOG_INF(...) printf(__VA_ARGS__)
#define CLOG_LOG_DBG(...) // printf( __VA_ARGS__)

// 使用数组保存，简单化
#define MAX_OPTION_NUM (64)

typedef int (*cmd_opt_parser)(void *opt_results, const char *option, char *arg);
typedef void (*cmd_opt_help_printer)(const char *option);

/* 命令选项信息及回调函数 */
typedef struct {
    const char *name;
    const char *help;
    cmd_opt_help_printer help_fn;
    cmd_opt_parser parser_fn;
} cmd_opt_cfg;

typedef struct {
    char *algo_name;
    char *mode;
    uint16_t op; // op 0:encrypt 1:decrypt
    uint16_t duration;
    uint16_t multi;
    uint16_t generic; // generic 0:ce 1:generic
    int 	thread_num; //线程数量
	int     queue_num; //队列数量
	char 	*mixed;   //混合模式
	int     latency;
	int     linklist; //分片模式
	int     batch;
	int		depth;
} perf_cmd_args;

int perf_cmd_parse(perf_cmd_args *results, int argc, char **argv);

#endif
