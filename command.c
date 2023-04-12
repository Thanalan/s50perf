#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "command.h"




typedef struct {
    char *prog_name;
    /* 所有选项的配置信息 */
    cmd_opt_cfg opt_cfgs[MAX_OPTION_NUM + 1];

    /* 用于getopt_long的选项配置，最后一个需要是NULL */
    struct option long_opts[MAX_OPTION_NUM + 1];
    uint32_t opt_cnt; /* 选项个数 */
} cmd_opt_configs;

/* 命令选项配置信息 */
cmd_opt_configs g_cmd_opt_configs = {0};

// <getopt.h>中的定义
// struct option {
//     const char *name;
//     int has_arg;
//     int *flag;
//     int val;
// };

/**
 *@ Description: 用于判断未知选项程序是否继续执行
 *
 *@ return true：继续执行 false: 输出usage并退出
 */
__attribute__((weak)) bool __command_unknown_option_bypass(void)
{
    return false;
}

/**
 *@ Description: 查找指定选项名称的配置
 *@ name: [in] 选项名
 *@ return 非NULL: 选项配置指针 NULL:不存在改选项配置
 */
cmd_opt_cfg *find_opt_cfg(const char *name)
{
    uint32_t i = 0;
    cmd_opt_cfg *pconfig = NULL;

    for (i = 0; i < g_cmd_opt_configs.opt_cnt; i++) {
        if (0 == strcmp(g_cmd_opt_configs.opt_cfgs[i].name, name)) {
            pconfig = &g_cmd_opt_configs.opt_cfgs[i];
        }
    }

    return pconfig;
}

/**
 *@ Description: 增加一个选项配置
 *@ cfg: [in] 选项配置
 *@ return 0：成功 非0：失败
 */
int add_cmd_opt(cmd_opt_cfg *cfg, struct option *opt_cfg)
{
    if (NULL == cfg || NULL == opt_cfg) {
        return -1;
    }

    cmd_opt_cfg *pconfig = find_opt_cfg(cfg->name);
    if (pconfig) {
        *pconfig = *cfg;
        g_cmd_opt_configs.long_opts[pconfig - g_cmd_opt_configs.opt_cfgs] =
            *opt_cfg;
    } else {
        if (g_cmd_opt_configs.opt_cnt < MAX_OPTION_NUM) {
            g_cmd_opt_configs.opt_cfgs[g_cmd_opt_configs.opt_cnt] = *cfg;
            g_cmd_opt_configs.long_opts[g_cmd_opt_configs.opt_cnt] = *opt_cfg;
            g_cmd_opt_configs.opt_cnt++;
        } else {
            CLOG_LOG_ERR("Count of option reach max limit %d\r\n",
                         MAX_OPTION_NUM);
            return -1;
        }
    }

    CLOG_LOG_DBG("Add option %s succeed\r\n", cfg->name);

    return 0;
}

/**
 *@ Description: 输出帮助的函数
 *@ progname: [in] 程序名
 *@ return void
 */
void usage(void)
{
    CLOG_LOG_ALWAYS("Usage\n"
                    " %s [options] ...\n"
                    "Options:\r\n",
                    g_cmd_opt_configs.prog_name);

    uint32_t i = 0;
    for (; i < g_cmd_opt_configs.opt_cnt; i++) {
        if (g_cmd_opt_configs.opt_cfgs[i].help) {
            CLOG_LOG_ALWAYS("%s", g_cmd_opt_configs.opt_cfgs[i].help);
        } else if (g_cmd_opt_configs.opt_cfgs[i].help_fn) {
            g_cmd_opt_configs.opt_cfgs[i].help_fn(
                g_cmd_opt_configs.opt_cfgs[i].name);
        }
    }
}

/**
 *@ Description: 选项解析
 *@ opt_idx: [in] 选项在g_command_long_options中对应的索引
 *@ options: [in, out] 选项解析结果
 *@ return void
 */
static int cmd_parse_opt_with_idx(int opt_idx, void *cmd_results)
{
    if (g_cmd_opt_configs.opt_cfgs[opt_idx].parser_fn) {
        CLOG_LOG_DBG("parse option %s\r\n",
                     g_cmd_opt_configs.opt_cfgs[opt_idx].name);
        return g_cmd_opt_configs.opt_cfgs[opt_idx].parser_fn(
            cmd_results, g_cmd_opt_configs.opt_cfgs[opt_idx].name, optarg);
    }

    return 0;
}

/**
 *@ Description: 解析命令行选项
 *@ options: [in, out] 选项解析结果
 *@ argc: [in] 选项个数
 *@ argv: 选项数组
 *@ return void
 */
int cmd_parse(void *results, int argc, char **argv)
{
    int opt, retval =0 , opt_idx;

    g_cmd_opt_configs.prog_name = argv[0];

    while ((opt = getopt_long(argc, argv, "", g_cmd_opt_configs.long_opts,
                              &opt_idx)) != EOF) {
        switch (opt) {
        case 0:
            retval = cmd_parse_opt_with_idx(opt_idx, results);
            if (retval != 0) {
                usage();
                return retval;
            }
            break;

        default: // hit unknown option
            if (!__command_unknown_option_bypass()) {
                usage();
                exit(EXIT_FAILURE);
            }
            break;
        }
    }

    return 0;
}

/**
 *@ Description: 默认的选项解析函数
 *@ opts: [in, out] 当前选项解析结果，解析后的数据保存到这边
 *@ option: [in] 选项名称
 *@ arg: [in] 选项对应的值的字符串，可能为NULL
 *@ return 0：成功 非0：失败
 */
static int perf_cmd_default_parser(perf_cmd_args *opts, const char *option,
                                   char *arg)
{
    char *eptr = NULL;
    if (!option || !opts) {
        CLOG_LOG_ERR("Invalid pointer param NULL\r\n");
        return -1;
    }

    if (0 == strcmp(option, "algo")) {
        opts->algo_name = arg;
    } else if (0 == strcmp(option, "multi")) {
        opts->multi = strtol(arg, &eptr, 0);
        if (eptr && *eptr != '\0') {
            CLOG_LOG_ERR("Parse option %s %s error\r\n", option, arg);
            return -1;
        }
    } else if (0 == strcmp(option, "duration")) {
        opts->duration = strtol(arg, &eptr, 0);
        if (eptr && *eptr != '\0') {
            CLOG_LOG_ERR("Parse option %s %s error\r\n", option, arg);
            return -1;
        }
    } else if (0 == strcmp(option, "mode")) {
        opts->mode = arg;
    } else if (0 == strcmp(option, "help")) {
        usage();
        exit(EXIT_SUCCESS); // 执行完直接退出
    } else if (0 == strcmp(option, "op")) {
        if (0 == strcmp(arg, "dec")) {
            opts->op = 1;
        }
    } else if (0 == strcmp(option, "latency")) {
        opts->latency = 1;
    } else if (0 == strcmp(option, "thread")) {
        opts->thread_num  = strtol(arg, &eptr, 0);
        if (eptr && *eptr != '\0') {
            CLOG_LOG_ERR("Parse option %s %s error\r\n", option, arg);
            return -1;
        }
	}else if (0 == strcmp(option, "queue")) {
        opts->queue_num  = strtol(arg, &eptr, 0);
        if (eptr && *eptr != '\0') {
            CLOG_LOG_ERR("Parse option %s %s error\r\n", option, arg);
            return -1;
        }
	}else if (0 == strcmp(option, "linklist")) {
        opts->linklist  = strtol(arg, &eptr, 0);
        if (eptr && *eptr != '\0') {
            CLOG_LOG_ERR("Parse option %s %s error\r\n", option, arg);
            return -1;
        }
		
	}else if (0 == strcmp(option, "mix")) {
        opts->mixed  = arg;
		
	}else if (0 == strcmp(option, "burst")) {
        opts->batch  = strtol(arg, &eptr, 0);
        if (eptr && *eptr != '\0') {
            CLOG_LOG_ERR("Parse option %s %s error\r\n", option, arg);
            return -1;
        }
	}else if (0 == strcmp(option, "depth")) {
        opts->depth  = strtol(arg, &eptr, 0);
        if (eptr && *eptr != '\0') {
            CLOG_LOG_ERR("Parse option %s %s error\r\n", option, arg);
            return -1;
        }
	}else {
        CLOG_LOG_ERR("Unsupported option %s value %s\r\n", option, arg);
        return -1;
    }

    return 0;
}
//增加参数
//--thread 线程数量，默认为1
//--queue 队列数量，默认为1
//--linklist 链表模式，参数为分片数量，需要参数，默认为2，此操作会将所有测试数据进行分片，无论数据为多长，长度以字节为单位
//--latency IO延迟测试，在单线程模式则是取各个线程延迟的平均值，不需要参数。
//--mix 混合模式，此模式最少会创建两个线程，向一个队列发送数据
//请注意，目前一个线程仅能向一个队列发送数据，不能向多个队列发送数据，所以混合模式采用的是多线程向一个队列发送的情况
//一个线程执行的是hash.另外一个线程执行的是cipher,
//混合模式输入需要输入组合算法,以+号作为分割符，不能有空格：
//举例：aes-128-ecb+sha1 表示线程0执行aes-128-ecb，线程1执行sha1算法，都向一个队列发送。
//举例：sha1+sha3-224+sm3 会创建三个线程，线程0执行sha1,线程1执行sha3-224,线程2执行sm3，都向一个队列发送
//--batch 一次向硬件队列发送请求的数量,如果使用latency,则延迟是一整个bacth的延迟，而不是batch中一个的延迟
//--depth 配置硬件队列深度


//统一算法格式，统一为openssl的算法格式


/**
 *@ Description: 默认选项配置初始化
 *@ return void
 */
static void perf_cmd_register(void)
{
#define INIT_OPTION(n, fn, req, help_str)                                      \
    {                                                                          \
        cmd_opt_cfg cfg;                                                       \
        cfg.name = n;                                                          \
        cfg.help = help_str;                                                   \
        cfg.help_fn = NULL;                                                    \
        cfg.parser_fn = (cmd_opt_parser)fn;                                    \
        struct option opt_cfg;                                                 \
        opt_cfg.name = n;                                                      \
        opt_cfg.has_arg = req;                                                 \
        opt_cfg.flag = 0;                                                      \
        opt_cfg.val = 0;                                                       \
        add_cmd_opt(&cfg, &opt_cfg);                                           \
    }

    INIT_OPTION("algo", perf_cmd_default_parser, required_argument,
                " --algo : Specified algo name\n");

    INIT_OPTION("multi", perf_cmd_default_parser, required_argument,
                " --multi : Run benchmarks in parallel\n");

    INIT_OPTION("duration", perf_cmd_default_parser, required_argument,
                " --duration : Test duration, default 10s\n");

    INIT_OPTION("mode", perf_cmd_default_parser, required_argument,
                " --mode : Specified algorithm mode (HASH: hmac | normal, "
                "default normal. CIPHER: ecb | ctr | cbc etc, default ecb.)\n");

    INIT_OPTION("op", perf_cmd_default_parser, required_argument,
                " --op : Encrypt mode,  dec/enc, default enc\n");

    INIT_OPTION("help", perf_cmd_default_parser, no_argument,
                " --help : Print this helps\n");
	
	INIT_OPTION("thread", perf_cmd_default_parser, required_argument,
                " --thread : Test thread number, default 1\n");
	
	INIT_OPTION("queue", perf_cmd_default_parser, required_argument,
                " --queue : Test queue number, default 1\n");
	
	INIT_OPTION("linklist", perf_cmd_default_parser, required_argument,
                " --linklist : Linklist number, default 2\n");
	
	INIT_OPTION("latency", perf_cmd_default_parser, no_argument,
                " --latency : Print latency result\n");
	
	INIT_OPTION("burst", perf_cmd_default_parser, required_argument,
                " --burst : The number of request sent at a time\n");
	
	INIT_OPTION("mix", perf_cmd_default_parser, required_argument,
                " --mix : The mixed mode\n");
	INIT_OPTION("depth", perf_cmd_default_parser, required_argument,
                " --depth : The queue depth\n");
#undef INIT_OPTION
}

int perf_cmd_parse(perf_cmd_args *results, int argc, char **argv)
{
    static bool inited = false;
    if (!inited) {
        perf_cmd_register();
        inited = true;
    }

    // set default valus
    //设置默认参数
    memset(results, 0, sizeof(perf_cmd_args));
    results->duration = 1;
    results->mode = "ecb";
	results->thread_num = 1;
	results->queue_num = 1;
	results->batch = 1;

    return cmd_parse(results, argc, argv);
}
