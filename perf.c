#include <pthread.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <signal.h>
#include <sys/times.h>

#include "command.h"


#include "perf.h"
#include "digest.h"
#include "cipher.h"
#include "rsa.h"
#include "rand.h"
#include "aead.h"

#include "ecc.h"

//全局变量定义
int do_sym_or_hash[ALGO_SYM_NUM] = {0};

// #define OPENSSL_NO_EC 0
perf_callbacks global_perf_algo_list[];
sem_t end_sem;
sem_t end_poll;


#define MAX_QUEUE_NUM 16
#define MAX_NUMBER_OF_THREADS 16
#define POLLING_NUM 8 //一个线程最多负责轮询几个队列，当大于4时，创建两个线程，一个线程负责两个队列，大于8时创建两个线程

//用于通知加密操作完成
int ceu_node = 0;

pce_queue_handle g_queue_handles[MAX_QUEUE_NUM];

pthread_key_t thread_key; //线程私有数据，用于存放每个线程的id和需要执行的loopargs

pthread_key_t *key = NULL;

volatile int running = 0;
volatile int stop_poll = 1;

int g_thread_num = 1; // 线程数量默认值
int g_queue_num = 1;  //队列数量默认值
int g_batch = 1;
int g_queue_depth = QUEUE_DEPTH_256;


//处理多线程数据，改为三维数组，按照线程号索引进行打印结果。打印结果仍然为主线程
double results[MAX_THREAD_NUM][ALGO_SYM_NUM][SIZE_NUM] = {0};
double latency_results[MAX_THREAD_NUM][ALGO_SYM_NUM][SIZE_NUM]={0};
int processed_count[ALGO_SYM_NUM]={0}; //计算当前成功完成处理的数量


int lengths[SIZE_NUM] = {16,32, 64, 128, 256, 1024,  4 * 1024, 8192,16384};

perf_cmd_args cmd_option = {0};
static volatile int run = 0;
static volatile int poll_run = 0;

int mr = 0; // multi response to parent
static int usertime = 1;
int testnum = 0;

algo_data_t algo_datas[] = {
	{"md5", PCE_HASH_MD5, ALGO_MD5_IDX, ALGO_TYPE_HASH, MD5_LEN},
	{"hmac(md5)", PCE_HMAC_MD5, ALGO_HMAC_MD5_IDX ,ALGO_TYPE_HMAC, MD5_LEN},//以此类推，由于查找是使用hashtable可以不按顺序存放，不支持算法2,3项直接给NULL

	{"sha1", PCE_HASH_SHA1, ALGO_SHA1_IDX, ALGO_TYPE_HASH, SHA1_LEN},
	{"hmac(sha1)", PCE_HMAC_SHA1, ALGO_HMAC_SHA1_IDX, ALGO_TYPE_HMAC, SHA1_LEN},

	{"sm3", PCE_HASH_SM3, ALGO_SM3_IDX, ALGO_TYPE_HASH, SM3_LEN},
	{"hmac(sm3)", PCE_HMAC_SM3, ALGO_HMAC_SM3_IDX, ALGO_TYPE_HMAC, SM3_LEN},
	
	{"sha224", PCE_HASH_SHA224, ALGO_SHA2_224_IDX, ALGO_TYPE_HASH, SHA224_LEN},
	{"hmac(sha224)", PCE_HMAC_SHA224, ALGO_HMAC_SHA2_224_IDX, ALGO_TYPE_HMAC, SHA224_LEN},
	{"sha256", PCE_HASH_SHA256, ALGO_SHA2_256_IDX, ALGO_TYPE_HASH, SHA256_LEN},
	{"hmac(sha256)", PCE_HMAC_SHA256, ALGO_HMAC_SHA2_256_IDX, ALGO_TYPE_HMAC, SHA256_LEN},
	{"sha384", PCE_HASH_SHA384, ALGO_SHA2_384_IDX, ALGO_TYPE_HASH, SHA384_LEN},
	{"hmac(sha384)", PCE_HMAC_SHA256, ALGO_HMAC_SHA2_384_IDX, ALGO_TYPE_HMAC, SHA384_LEN},
	{"sha512", PCE_HASH_SHA512, ALGO_SHA2_512_IDX, ALGO_TYPE_HASH, SHA512_LEN},
	{"hmac(sha512)", PCE_HMAC_SHA512, ALGO_HMAC_SHA2_512_IDX, ALGO_TYPE_HMAC, SHA512_LEN},

	{"sha3-224", PCE_HASH_SHA3_224, ALGO_SHA3_224_IDX, ALGO_TYPE_HASH, SHA3_224_LEN},
	{"hmac(sha3-224)", 0, ALGO_HMAC_SHA3_224_IDX, ALGO_TYPE_HMAC, SHA3_224_LEN},
	{"sha3-256", PCE_HASH_SHA3_256, ALGO_SHA3_256_IDX, ALGO_TYPE_HASH, SHA3_256_LEN},
	{"hmac(sha3-256)", 0, ALGO_HMAC_SHA3_256_IDX, ALGO_TYPE_HMAC, SHA3_256_LEN},
	{"sha3-384", PCE_HASH_SHA3_384, ALGO_SHA3_384_IDX, ALGO_TYPE_HASH, SHA3_384_LEN},
	{"hmac(sha3-384)", 0, ALGO_HMAC_SHA3_384_IDX, ALGO_TYPE_HMAC, SHA3_384_LEN},
	{"sha3-512", PCE_HASH_SHA3_512, ALGO_SHA3_512_IDX, ALGO_TYPE_HASH, SHA3_512_LEN},
	{"hmac(sha3-512)", 0, ALGO_HMAC_SHA3_512_IDX, ALGO_TYPE_HMAC, SHA3_512_LEN},
	

	//对称加密示例,不全
	//AES-128
	{"aes-128-cbc", PCE_AES_128_CBC, ALGO_AES_128_CBC_IDX, ALGO_TYPE_SYM_CIPHER, AES_128_KEYIV},
	
	{"aes-128-ccm", PCE_AES_128_CCM, ALGO_AES_128_CCM_IDX, ALGO_TYPE_AEAD, AES_128_KEYIV},
	
	{"aes-128-cfb", PCE_AES_128_CFB, ALGO_AES_128_CFB_IDX, ALGO_TYPE_SYM_CIPHER, AES_128_KEYIV},
	{"aes-128-ctr", PCE_AES_128_CFB, ALGO_AES_128_CTR_IDX, ALGO_TYPE_SYM_CIPHER, AES_128_KEYIV},
	{"aes-128-cts", NULL           , ALGO_AES_128_CTS_IDX, ALGO_TYPE_SYM_CIPHER, AES_128_KEYIV},
	{"aes-128-ecb", PCE_AES_128_ECB, ALGO_AES_128_ECB_IDX, ALGO_TYPE_SYM_CIPHER, AES_128_KEYIV},
	
	{"aes-128-gcm", PCE_AES_128_GCM, ALGO_AES_128_GCM_IDX, ALGO_TYPE_AEAD, AES_128_KEYIV},
	{"aes-128-ocb", NULL           , ALGO_AES_128_OCB_IDX, ALGO_TYPE_AEAD, AES_128_KEYIV},
	
	{"aes-128-ofb", PCE_AES_128_OFB, ALGO_AES_128_OFB_IDX, ALGO_TYPE_SYM_CIPHER, AES_128_KEYIV},
	{"aes-128-xts", PCE_AES_128_XTS, ALGO_AES_128_XTS_IDX, ALGO_TYPE_SYM_CIPHER, AES_128_XTS_KEYIV},

	//AES-192
	{"aes-192-cbc", PCE_AES_192_CBC, ALGO_AES_192_CBC_IDX, ALGO_TYPE_SYM_CIPHER, AES_192_KEYIV},
	
	{"aes-192-ccm", PCE_AES_192_CCM, ALGO_AES_192_CCM_IDX, ALGO_TYPE_AEAD, AES_192_KEYIV},
	
	{"aes-192-cfb", PCE_AES_192_CFB, ALGO_AES_192_CFB_IDX, ALGO_TYPE_SYM_CIPHER, AES_192_KEYIV},
	{"aes-192-ctr", PCE_AES_192_CFB, ALGO_AES_192_CTR_IDX, ALGO_TYPE_SYM_CIPHER, AES_192_KEYIV},
	{"aes-192-cts", NULL           , ALGO_AES_192_CTS_IDX, ALGO_TYPE_SYM_CIPHER, AES_192_KEYIV},
	{"aes-192-ecb", PCE_AES_192_ECB, ALGO_AES_192_ECB_IDX, ALGO_TYPE_SYM_CIPHER, AES_192_KEYIV},
	
	{"aes-192-gcm", PCE_AES_192_GCM, ALGO_AES_192_GCM_IDX, ALGO_TYPE_AEAD, AES_192_KEYIV},
	{"aes-192-ocb", NULL           , ALGO_AES_192_OCB_IDX, ALGO_TYPE_AEAD, AES_192_KEYIV},
	
	{"aes-192-ofb", PCE_AES_192_OFB, ALGO_AES_192_OFB_IDX, ALGO_TYPE_SYM_CIPHER, AES_192_KEYIV},
	{"aes-192-xts", NULL           , ALGO_AES_192_XTS_IDX, ALGO_TYPE_SYM_CIPHER, 0},

	//AES-256
	{"aes-256-cbc", PCE_AES_256_CBC, ALGO_AES_256_CBC_IDX, ALGO_TYPE_SYM_CIPHER, AES_256_KEYIV},
	
	{"aes-256-ccm", PCE_AES_256_CCM, ALGO_AES_256_CCM_IDX, ALGO_TYPE_AEAD, AES_256_KEYIV},
	
	{"aes-256-cfb", PCE_AES_256_CFB, ALGO_AES_256_CFB_IDX, ALGO_TYPE_SYM_CIPHER, AES_256_KEYIV},
	{"aes-256-ctr", PCE_AES_256_CFB, ALGO_AES_256_CTR_IDX, ALGO_TYPE_SYM_CIPHER, AES_256_KEYIV},
	{"aes-256-cts", NULL           , ALGO_AES_256_CTS_IDX, ALGO_TYPE_SYM_CIPHER, AES_256_KEYIV},
	{"aes-256-ecb", PCE_AES_256_ECB, ALGO_AES_256_ECB_IDX, ALGO_TYPE_SYM_CIPHER, AES_256_KEYIV},
	
	{"aes-256-gcm", PCE_AES_256_GCM, ALGO_AES_256_GCM_IDX, ALGO_TYPE_AEAD, AES_256_KEYIV},
	{"aes-256-ocb", NULL           , ALGO_AES_256_OCB_IDX, ALGO_TYPE_AEAD, AES_256_KEYIV},
	
	{"aes-256-ofb", PCE_AES_256_OFB, ALGO_AES_256_OFB_IDX, ALGO_TYPE_SYM_CIPHER, AES_256_KEYIV},
	{"aes-256-xts", PCE_AES_256_XTS, ALGO_AES_256_XTS_IDX, ALGO_TYPE_SYM_CIPHER, AES_256_XTS_KEYIV},

	//SM4
	{"sm4-cbc", PCE_SM4_CBC, ALGO_SM4_CBC_IDX, ALGO_TYPE_SYM_CIPHER, SM4_KEYIV},	
	{"sm4-ccm", PCE_SM4_CCM, ALGO_SM4_CCM_IDX, ALGO_TYPE_AEAD, SM4_KEYIV},
	{"sm4-cfb", PCE_SM4_CFB, ALGO_SM4_CFB_IDX, ALGO_TYPE_SYM_CIPHER, SM4_KEYIV},
	{"sm4-ctr", PCE_SM4_CFB, ALGO_SM4_CTR_IDX, ALGO_TYPE_SYM_CIPHER, SM4_KEYIV},
	{"sm4-cts", NULL       , ALGO_SM4_CTS_IDX, ALGO_TYPE_SYM_CIPHER, SM4_KEYIV},
	{"sm4-ecb", PCE_SM4_ECB, ALGO_SM4_ECB_IDX, ALGO_TYPE_SYM_CIPHER, SM4_KEYIV},
	
	{"sm4-gcm", PCE_SM4_GCM, ALGO_SM4_GCM_IDX, ALGO_TYPE_AEAD, SM4_KEYIV},
	{"sm4-ocb", NULL       , ALGO_SM4_OCB_IDX, ALGO_TYPE_AEAD, SM4_KEYIV},
	
	{"sm4-ofb", PCE_SM4_OFB, ALGO_SM4_OFB_IDX, ALGO_TYPE_SYM_CIPHER, SM4_KEYIV},
	{"sm4-xts", PCE_SM4_XTS, ALGO_SM4_XTS_IDX, ALGO_TYPE_SYM_CIPHER, SM4_XTS_KEYIV},
	
	{"rand", PCE_RANDOM, ALGO_RAND_IDX, ALGO_TYPE_RAND, 0},
	{NULL, 0 , 0, 0}
};


HashMap *g_algo_hash_table; //全局变量，用于查找算法

//创建算法查找表
int create_algo_hashtable()
{
	int i;
 	g_algo_hash_table = createHashMap(ALGO_SYM_NUM); //ALGO_SYM_NUM是算法的最大值
	
	for(i = 0; i < ALGO_SYM_NUM ; i++)
	{
		if(algo_datas[i].algo != NULL){
			putHashMap(g_algo_hash_table, algo_datas[i].algo,&algo_datas[i]); //直接插入索引本身的值
		}else{
			break;
			}
	}
	return 0;
}


//映射线程和队列句柄的对应关系
//thread_num 线程总数，queue_num，队列总数
pce_queue_handle *get_queue_handle(int thread_id,int thread_num,int queue_num)
{
	int i;
	//当队列数量大于限制数量时返回索引。
	if(queue_num > MAX_QUEUE_NUM){
		return NULL;
	}
	i = thread_id % queue_num; //将线程映射到对应的设备中，此处需要判断是否为指定映射，
	//通过取余来确定线程应当往哪个队列发送数据

	return g_queue_handles[i];//获得队列描述符地址，可以考虑将队列描述符数组改为地址
}

//初始化queue_num数量的队列到全局数组中，仅在主线程执行
static int init_queue_from_device(int queue_num)
{
	int i = 0;
	//生成对应数量的队列描述符
	for(i = 0 ; i < queue_num && i < MAX_QUEUE_NUM; i++){
		if(g_queue_handles[i] ==  NULL){
			if (pce_request_queue(ceu_node, &g_queue_handles[i])) {
				return -1;
			}
	
			// queue size 256
			if (pce_init_queue(g_queue_handles[i], g_queue_depth, 0)) {
				pce_release_queue(g_queue_handles[i]);
				return -1;
				}
			}
		}
	return 0;
}

//释放队列
int final_queue_from_device(int queue_num)
{
	int i = 0;
	//释放对应数量的队列描述符
	for(i = 0 ; i < queue_num && i < MAX_QUEUE_NUM; i++){
		if(g_queue_handles[i] !=  NULL){
			pce_release_queue(g_queue_handles[i]); 
		}
	}
	return 0;
}



int found(const char *name, const OPT_PAIR *pairs, int *result)
{
    for (; pairs->name; pairs++)
        if (strcmp(name, pairs->name) == 0) {
            *result = pairs->retval;
            return 1;
        }
    return 0;
}

static double app_tminterval(int stop, int usertime)
{
    double ret = 0;
    struct tms rus;
    clock_t now = times(&rus);
    static clock_t tmstart;

    if (usertime)
        now = rus.tms_utime;

    if (stop == START)
        tmstart = now;
    else {
        long int tck = sysconf(_SC_CLK_TCK);
        ret = (now - tmstart) / (double)tck;
    }

    return (ret);
}


double Time_F(int s)
{
    double ret = app_tminterval(s, usertime);
    if (s == STOP)
        alarm(0);


    return ret;
}

/*通过alarm信号控制执行时间*/
static void sig_done(int sig);
static void sig_done(int sig)
{
    (void)sig;
    signal(SIGALRM, sig_done);
    poll_run = 0;
	//run = 0;
}

/**
 *@ Description: 调用测试函数进行基准测试
 *@ loop_function: [in] 循环参数
 *@ loopargs: [in] 参数
 *@
 *@ return 返回运行的次数
 */
int run_benchmark(bench_function loop_function, loopargs_t *loopargs)
{
    int count, i;

    run = 1;
    count = 0;
	//0x3fffffff用于防止死锁
    for (i = 0;run && i < 0x3fffffff; i++) {
		
        count += loop_function((void *)loopargs);
		if(sem_trywait(&end_sem) == 0 ){
			break;
		}
    }

    return count;
}

int run_poll_benchmark(bench_function loop_function, void *loopargs)
{
    int count, i;

    poll_run = 1;
    count = 0;
    for (i = 0; poll_run && i < 0x2fffffff; i++) {
        count += loop_function((void *)loopargs);
		if(stop_poll == 2){
			break;
		}
    }

    return count;
}


perf_callbacks global_perf_algo_list[] = {
    {.init_data = init_sm2_data,
     .free_data = free_sm2_data,
     .test_algo = test_perf_for_sm2,
     .show_results = show_results_for_sm2,
     .test_hit = test_hit_for_sm2,
     .proc_multi_buf = do_multi_buf_sm2},
     
     {.init_data = init_rsa_data,
     .free_data = free_rsa_data,
     .test_algo = test_perf_for_rsa,
     .show_results = show_results_for_rsa,
     .test_hit = test_hit_for_rsa,
     .proc_multi_buf = do_multi_buf_rsa},
     
    {.init_data = init_ecc_data,
    .free_data = free_ecc_data,
    .test_algo = test_perf_for_ecc,
    .show_results = show_results_for_ecc,
    .test_hit = test_hit_for_ecc,
    .proc_multi_buf = do_multi_buf_ecc},
    {.test_algo = test_hash_perf, .test_hit = test_hash_hit},
    {.test_algo = test_cipher_perf, .test_hit = test_cipher_hit},
	{.test_algo = test_rand_perf, .test_hit = test_rand_hit}
};
static int do_multi(int multi)
{
    int n, i;
    int fd[2];
    int *fds;
    static char sep[] = ":";

    fds = malloc(sizeof(*fds) * multi);
    for (n = 0; n < multi; ++n) {
        if (pipe(fd) == -1) {
            fprintf(stderr, "pipe failure\n");
            exit(1);
        }
        fflush(stdout);
        fflush(stderr);
        if (fork()) { // parent, close fd1, save fd0  read endpoint.
            close(fd[1]);
            fds[n] = fd[0];
        } else {
            close(fd[0]);
            close(1);
            if (dup(fd[1]) == -1) {
                fprintf(stderr, "dup failed\n");
                exit(1);
            }
            close(fd[1]);
            mr = 1;
            usertime = 0;
            free(fds);
            return 0;
        }
        printf("Forked child %d\n", n);
    }

    /* for now, assume the pipe is long enough to take all the output */
    for (n = 0; n < multi; ++n) {
        FILE *f;
        char buf[1024];
        char *p;

        f = fdopen(fds[n], "r");
        while (fgets(buf, sizeof buf, f)) {
            p = strchr(buf, '\n');
            if (p)
                *p = '\0';
            if (buf[0] != '+') {
                fprintf(stderr, "Don't understand line '%s' from child %d\n",
                        buf, n);
                continue;
            }
            printf("Got: %s from %d\n", buf, n);

            if (strncmp(buf, "+F:", 3) == 0) {
                int alg;
                int j;

                p = buf + 3;
                alg = atoi(sstrsep(&p, sep));
                sstrsep(&p, sep);
                //for (j = 0; j < SIZE_NUM; ++j)
                //    results[alg][j] += atof(sstrsep(&p, sep));
            } else if (strncmp(buf, "+H:", 3) == 0) {
                ;
            } else {
                int done = 0;
                for (i = 0; i < sizeof(global_perf_algo_list) /
                                    sizeof(global_perf_algo_list[0]);
                     i++) {
                    if (global_perf_algo_list[i].test_enabled &&
                        global_perf_algo_list[i].proc_multi_buf) {
                        if (0 ==
                            global_perf_algo_list[i].proc_multi_buf(buf, n)) {
                            done = 1;
                        }
                    }
                }

                if (!done)
                    fprintf(stderr, "Unknown type '%s' from child %d\n", buf,
                            n);
            }
        }

        fclose(f);
    }
    free(fds);
    return 1;
}


//以下函数可以去掉
int polute_doit_flag(char *algo_name)
{
    int ret = -1;
    int i;

    if (NULL == algo_name) {
        return ret;
    }
	
	if(getHashMap(g_algo_hash_table,algo_name) == NULL){
		return -1;
	}

	algo_data_t *algo_data = (algo_data_t*)getHashMap(g_algo_hash_table, algo_name);
		//algo_data_t *algo_data2 = (algo_data_t*)getHashMap(g_algo_hash_table, "asa");
	
	if(algo_data->algo_type != ALGO_TYPE_ASYM) {//如果不是非对称算法，则是对称类或者摘要算法或者aead算法
		do_sym_or_hash[algo_data->algo_index] = 1; //完成原有test_hash_hit函数的功能
		return 0;
	}
	
	//暂时不支持非对称算法
    for (i = 0;
         i < sizeof(global_perf_algo_list) / sizeof(global_perf_algo_list[0]);
         i++) {
        if (0 == global_perf_algo_list[i].test_hit(algo_name)) { //执行test_hit函数,设置本线程应该执行什么操作，此处为const
            ret = 0;
            global_perf_algo_list[i].test_enabled = 1;
        }
    }

	if (ret < 0) {
        printf("Invalid algo name %s to test.\n", cmd_option.algo_name);
    }
    return ret;
}


//根据线程id获得该线程应该执行的算法
/*
char * get_mixed_algo_name(int thread_id)
{	
	int i = 0;
	if(cmd_option.mixed == NULL){
		fprintf(stderr, "No mixed input!");
		return 0;
	}
	char *ret = NULL;
	char str[256] = { 0 };
	strcpy(str, cmd_option.mixed); //复制一份
	
	char* str1 = strtok(str, "+"); //以+作为分割符
	if(thread_id == 0){
		return str1;
	}
	while (str1 != NULL)
	{	
		i++;
        str1 = strtok(NULL, "+");
		if(thread_id == i){ 
			return str1;
		}
	}
	//g_thread_num = (i+1); //设置线程总数,如果有一个参数，i=0,创建一个线程
	//如果有两个参数，i = 1,创建两个线程
	g_queue_num = 1;
	//混合模式为所有线程都向这一个队列发送数据，即使申请了大于一个的队列也不会使用
	return NULL;
	
}
*/
//获得algo有几个算法
int  get_algo_name_num(char *name)
{	
	int i = 0;
	char *p = NULL;
	if(name == NULL){
		fprintf(stderr, "No algo input!\n");
		return -1;
		}
	char str1[50] = { 0 };
	strcpy(str1, name); //复制一份
	for (p = strtok(str1, "+");p != NULL;p=strtok(NULL,"+")) {
		i++;
	}
	return i; //此处返回值要注意是否是参数个数，而不是参数个数-1
}

char * get_algo_name(char* name, int index)
{	
	int i = 0;
	
	char *ret = NULL;
	char str[256] = { 0 };
	strcpy(str, name); //复制一份
	char* str1 = strtok(str, "+"); //以+作为分割符

	//从s开头开始的一个个被分割的串。当s中的字符查找到末尾时，返回NULL。
	//如果查找不到delim中的字符时，返回当前strtok的字符串的指针。
	//所有delim中包含的字符都会被滤掉，并将被滤掉的地方设为一处分割的节点

	if(index == 0){  //获得第一个算法名称
		return str1;
	}
	while (str1 != NULL)
	{	
		i++;
        str1 = strtok(NULL, "+");
		if(index == i){ 
			return str1;
		}
	}
	return NULL;

}

//子线程执行的函数
void* thread_function(void* id)
{
	int i,k;
	int ret = -1;
	int loopargs_len = 1; // only support one args now.
	loopargs_t *loopargs = NULL;
	int loopnum = 1;
	int thread_id = id;
	int batch = 1;
	
	thread_local_variables_t *tlv = malloc(sizeof(thread_local_variables_t));//生成tlv
	memset(tlv, 0, sizeof(thread_local_variables_t));

	tlv->algo_name = malloc(sizeof(char) * 256); //分配50个字符大小的空间用于存放字符串
	memset(tlv->algo_name , 0 ,sizeof(char) * 256); //清零,写入字符
	//如果是混合模式，则根据线程id和对应的参数号进行分割
	if(cmd_option.mixed != NULL) //混合模式
	{
		//在混合模式此时会设置algo_name
		strcpy(tlv->algo_name , get_algo_name(cmd_option.mixed,thread_id)); //获得本线程应该执行的算法
	}else if(cmd_option.algo_name != NULL){

		//在非混合模式此时不会设置algo_name,此数组仍然0
		loopnum = get_algo_name_num(cmd_option.algo_name); //获得algo_name有几个参数，如果输入只有一个参数，则返回1
		strcpy(tlv->algo_name , get_algo_name(cmd_option.algo_name, 0)); //获得第一次执行的算法
	}

	//因为每个线程执行的函数相同，但是访问的数据不同，所以需要线程私有数据，每个线程存一个副本
	pthread_setspecific(thread_key, (void*)tlv);

	polute_doit_flag(tlv->algo_name); //执行操作test_hit操作

	//loopargs需要是线程私有数据，每个线程执行的不同

	//与原版代码不同，loopargs只能为1个如果有多个参数，会依次执行这些结果，最后再统一输出

    loopargs_len = 1; // only support one args now.
    loopargs = malloc(sizeof(loopargs_t));
	memset(loopargs, 0, sizeof(loopargs_t));
    if (NULL == loopargs) {
        fprintf(stderr, "alloc memory failed  in %s:%d\n",__func__ , __LINE__);
        //return -1;
    }

    memset(loopargs, 0, sizeof(loopargs_t));
	//参数全部给NULL ,在perf中会再分配参数
	loopargs->src_buf = malloc(lengths[SIZE_NUM - 1] + 64); //源数据
	loopargs->dst_buf = malloc(lengths[SIZE_NUM - 1] + 64);  //分配数据的最大长度
    loopargs->src = loopargs->src_buf;
    loopargs->dst = loopargs->dst_buf;

	loopargs->queue_handle =  get_queue_handle (thread_id, g_thread_num, g_queue_num); //需要设置为申请的队列地址,也就是一个loopargs对应一个队列对
	loopargs->processed_count = malloc(sizeof(int) * ALGO_SYM_NUM);

	//分配请求的空间
	loopargs->requests = malloc((sizeof(pce_op_data_t)) * g_batch);
	loopargs->callbacks = malloc((sizeof(callback_context_t)) * g_batch);
	loopargs->op_datas = malloc((sizeof(pce_op_data_t*)) * g_batch);
	loopargs->batch = g_batch;
    
	//处理线程私有数据
	tlv->thread_id = thread_id;
	tlv->loopargs = loopargs ; //每个线程执行的loopargs
	tlv->queue = get_queue_handle (thread_id, g_thread_num, g_queue_num);//获得本线程应该向哪个队列发送数据

	//如果有多个输入算法，则执行多次，如果为mix的，则只会执行一次
	for(i = 0 ; i < loopnum; i++ ){
		memset(loopargs->src_buf , 0 ,(lengths[SIZE_NUM - 1] + 64));
		memset(loopargs->dst_buf , 0 ,(lengths[SIZE_NUM - 1] + 64));

		loopargs->index = i;
		if((tlv->algo_name[0] == 0) &&(tlv->algo_name[1] == 0)) { //如果前两个字符被设置，则表示不是第一次执行
			//获得算法
			strcpy(tlv->algo_name,get_algo_name(cmd_option.algo_name,i)); //将不是第一次执行的算法 algo_name修改为新算法
		}
		
		algo_data_t *algo_data = (algo_data_t*)getHashMap(g_algo_hash_table, tlv->algo_name);
		if(algo_data == NULL){
			fprintf(stderr,"Invaild algoname:%s,please check input algoname!\n",tlv->algo_name);
			exit(0);
		}
		switch(algo_data->algo_type){
			case ALGO_TYPE_HASH:
			case ALGO_TYPE_HMAC:
				test_hash_perf(loopargs);
				break;
			case ALGO_TYPE_SYM_CIPHER:
				test_cipher_perf(loopargs);
				break;
			case ALGO_TYPE_RAND:
				test_rand_perf(loopargs);
				break;
			case ALGO_TYPE_AEAD:
				test_aead_perf(loopargs);
				break;
			default:
				fprintf(stderr,"unsupport algo type in func:%s in line:%d\n",__func__,__LINE__);

		}
		memset(tlv->algo_name, 0, sizeof(char) * 50); //名称数组长度为50个字符，清零
		fprintf(stderr, "run func %s in thread id:%d for %d times\n",__func__ ,thread_id,i+1);
	}
	sem_post(&end_poll);
	poll_run = 0;
	stop_poll =2;
	//执行完后释放,loopargs
	free(loopargs->src_buf);
	free(loopargs->dst_buf);
	free(loopargs->requests);
	free(loopargs->callbacks);
	free(loopargs->op_datas);
	free(loopargs->processed_count);
	free(loopargs);
	//释放tlv
	free(tlv->do_sym_or_hash);
	free(tlv->algo_name);
	free(tlv);
	return NULL;
	

}
typedef struct {
	pce_rsp_t *rsp_datas;
	int rsp_datas_size;
	pce_queue_handle *queue_handle;
	int thread_id;
}poll_struct;

//处理响应队列的结果
int poll_queue(void* polling)
{
	poll_struct *poll = polling;
	int dequeued_count;	
	int i =0,k = 0;
	callback_context_t *callback_tag = NULL;
	//running 用于判断是否执行
	//如果没有收到结束信号时则一直执行，使用while1
	pce_rsp_t *rsp_datas = poll->rsp_datas;;
	//int rsp_datas_size = poll->rsp_datas_size;
	int rsp_datas_size = 5;
	pce_queue_handle queue_handle = poll->queue_handle;
	dequeued_count = pce_dequeue(queue_handle, rsp_datas, rsp_datas_size);//尽量多出队
		
	for (i = 0; i < dequeued_count; i++) {
					
		if (rsp_datas[i].state != CMD_SUCCESS) {
			//fprintf(stderr, "in_bytes ");
	   
			//continue;
		}
		callback_tag =(callback_context_t *)rsp_datas[i].tag;
			 
		(callback_tag->callbackfunc)(callback_tag); 
	}

}

volatile double used_time;

void* process_response(void * id) //仅需要轮询对应的队列即可，也可也轮询所有的队列
{
	int i = 0,k = 0,count;
	pce_rsp_t *rsp_datas;
	int enqueued_count = 127;//一次性出队最大数目
	int dequeued_count;
	callback_context_t *callback_tag = NULL;
	int step = (g_queue_num / POLLING_NUM) + 1;//最少创建一个线程，大于4则创建两个
	int poll_thread_num = step;
	pce_queue_handle  queue_handle = NULL;
	int thread_id = id;//消除pthread_create向函数传参数必须为void*类型的警告
	struct	timeval    tv;
	struct	timeval tv1;
	double d;
	poll_struct poll;
	pce_op_data_t *temp_op = NULL;		
	rsp_datas = malloc(sizeof(pce_rsp_t) * enqueued_count);
        if (NULL == rsp_datas) {
            goto out;
    }
	poll.rsp_datas = rsp_datas;
	poll.rsp_datas_size = enqueued_count;
	poll.queue_handle = g_queue_handles[0];
	//开始计时
	do{ 
		sem_init(&end_sem,0,0);
		for(i=0; i<g_thread_num;i++){
		sem_wait(&start_sem);}
		running = 1;
		gettimeofday(&tv,NULL);
    	Time_F(START);			
    	count = run_poll_benchmark(poll_queue, &poll);
    	d = Time_F(STOP);
				//结束计时,通知结束发送
		used_time = d;
		gettimeofday(&tv1,NULL);
		//fprintf(stderr,"\nprocess_response:time:%ld ",tv1.tv_usec);
		//fprintf(stderr,"time:%ld \n",tv.tv_usec);			 
		//used_time = (tv1.tv_usec-tv.tv_usec)/(100000.0)+((tv1.tv_sec-tv.tv_sec));
		run = 0;
		for(i=0; i<g_thread_num;i++){
		sem_post(&end_sem);}
	}while(sem_trywait(&end_poll) != 0);
	//sem_post //通知发送线程结束发送
out:
	if (rsp_datas) {
		free(rsp_datas);
	}
	return NULL;
		
}

int create_poll_threads(pthread_t *pollingthread)
{
	int i;
	int poll_thread_num = (g_queue_num / POLLING_NUM) + 1;//最少创建一个线程，大于4则创建两个

	for(i = 0;i < poll_thread_num; i++){
		//轮询线程一个暂定为负责四个队列，如果创建的队列数量大于四个，假设为7个，则会创建两个线程，
		//0号线程负责0，2，4，6，0号线程负责1，3，5，队列
		//大于八个则会创建三个线程，以此类推
		
		pthread_create(&pollingthread[i],NULL,process_response,i);//第四个参数可以找到响应队列，
	}
	return 0;

}

//虚拟地址转为物理地址
void *va_to_iova(void *usr, void *va)
{
    return (void *)pce_mem_virt2iova(va);
}
int thread_run_algo[MAX_THREAD_NUM] = {0};

int show_results(int pr_header) //多线程输出结果不正确
{
	int i = 0, k = 0,j = 0,m = 0;

    //打印多线程测试结果，由主线程执行,i用于处理多线程
    int testnum = 0;
    for(i = 0; i < g_thread_num ; i++){
		//表示这是第i个线程的计算结果，子线程从0开始，不包括主线程
		printf("Benchmark result of thread id: %d\n", i);
    	if (pr_header) { // for sym or hash etc.
        	if (mr)      // child
            	printf("+H");
        	else { // parent
            	printf(
                	"The 'numbers' are in 1000s of bytes per second processed.\n");
            	printf("type        ");
        	}
        	for (testnum = 0; testnum < SIZE_NUM; testnum++)
            	printf(mr ? ":%d" : "%7d bytes", lengths[testnum]);
        	printf("\n");
    	}
		printf("type        ");
	
			//获得线程执行的算法
			k = thread_run_algo[i];
				
	 if (mr){
			printf("type	   ");
				printf("+F:%d:%s", k, algo_datas[k].algo);
			printf("\n");
	
		}
			else{
			printf("%s", algo_datas[k].algo);
			printf("\n");
			printf("  data_size");
			printf("   speed/KBps");
			printf("  speed/Mbps");
			printf("\n");
			}
			for (testnum = 0; testnum < SIZE_NUM; testnum++) {
				printf(mr?":%d":"%7dbytes",lengths[testnum]);
			  //if (results[i][k][testnum] > 10000 && !mr){
			  if (results[i][k][testnum] > 10000 && !mr){
			  		printf(" %11.2f", g_batch*results[i][k][testnum] / (1e3));
					printf(" %11.2f",g_batch*results[i][k][testnum]*8/(1e6));
					printf("\n");
					}
				else{
					printf(mr ? ":%.2f" : " %11.2f ", g_batch*results[i][k][testnum]/(1e3));
					printf(mr ? ":%.2f" : " %11.2f ", g_batch*results[i][k][testnum]*8/(1e6));
					printf("\n");}
			}
			printf("\n");
		
    //	}

    	for (j = 0;
         	j < sizeof(global_perf_algo_list) / sizeof(global_perf_algo_list[0]);
         	j++) {
        	if (global_perf_algo_list[j].test_enabled &&
            	global_perf_algo_list[j].show_results) {
            	global_perf_algo_list[j].show_results();
        	}
    	}
    }
	return 0;
}

int show_latency_results(int pr_header)
{
	int i = 0;
	int k = 0;
	double latency = 0;
	double sum[SIZE_NUM] = {0}; //延迟取平均值,一个测试数量取一个延迟
	// parent
    //统计延迟数据
    int test_num;
    for(i = 0; i < g_thread_num ; i++){
		//表示这是第i个线程的计算结果，子线程从0开始，不包括主线程
		for (test_num = 0; test_num < SIZE_NUM; test_num++) {
			
    		k = thread_run_algo[i];
            sum[test_num] += latency_results[i][k][test_num];
    		
			}
	}
	//取平均值
	for(i = 0;i < SIZE_NUM; i++){
		sum[i] = sum[i] / g_thread_num;
		printf("latency of length:%d is %11.4f ns\n",lengths[i],sum[i] * (1e9)); //单位是us,需要乘1e6
	}
	return 0;
}

static int set_global_variables()
{
	if(get_algo_name_num(cmd_option.mixed) > 0){ //如果有MIX的输入，则使用mix
		//g_thread_num = 1;
		g_thread_num = get_algo_name_num(cmd_option.mixed);
	}else if(get_algo_name_num(cmd_option.algo_name) > 1){ //如果有algo的输入
		fprintf(stderr,"input more than one algo name,only use last!!\n");
		g_thread_num = 1; //
	}else if(get_algo_name_num(cmd_option.algo_name) > 0){
		g_thread_num = 1; //
	}else {
		fprintf(stderr,"No algo or mix input,exit perf!!\n");
		exit(0);
	}
	
	if(cmd_option.thread_num > 1){
		g_thread_num = cmd_option.thread_num;	
	}
		
	if(cmd_option.queue_num >= 1){
		g_queue_num = cmd_option.queue_num;
	}
	
	if(cmd_option.batch > g_batch){ //如果不这样设置会出现错误corrupted size vs. prev_size
		g_batch = cmd_option.batch;
	}
	
	if(cmd_option.depth != 0){ //如果传入了depth
		switch(cmd_option.depth){
			case 256:
				g_queue_depth = QUEUE_DEPTH_256;
				break;
			case 1024:
				g_queue_depth = QUEUE_DEPTH_1024;
				break;
			case 8192:
				g_queue_depth = QUEUE_DEPTH_8192;
				break;
			case 65536:
				g_queue_depth = QUEUE_DEPTH_65536;
				break;
			default:
				fprintf(stderr,"Invaid depth input:%d in func:%s line %d\n",cmd_option.depth,__func__,__LINE__);
				fprintf(stderr,"supported size:256, 1024, 8192, 65536\n");
				g_queue_depth = QUEUE_DEPTH_256;
				break;
		}		
	}else{
		fprintf(stderr,"No depth input,use default queue depth: 256\n");
		g_queue_depth = QUEUE_DEPTH_256;
	}

	sem_init(&end_poll,0,0);
	sem_init(&end_sem,0,0);
	sem_init(&start_sem, 0, 0);
	return 0;
}

int main(int argc, char **argv)
{
    loopargs_t *loopargs = NULL;
    int loopargs_len = 0;
    int i;
    int ret = 0;
    int multi = 0;
    int pr_header = 0;
	int queue_num = 1; //目前队列对数量为一个
	int thread_num = 1; //默认为一个线程
	int status = 0;
	pthread_t pollingthreads[MAX_QUEUE_NUM / POLLING_NUM]; //轮询线程最大数量
	
	pthread_t threads[MAX_NUMBER_OF_THREADS];


    ret = perf_cmd_parse(&cmd_option, argc, argv);
    if (ret) {
        return ret;
    }
	//创建映射表

	set_global_variables();
	
	pthread_key_create(&thread_key, NULL);//创建线程私有数据
	
	create_algo_hashtable();
	//printf("createkey:%d",pthread_key_create(&thread_key, NULL)); 

	//初始化设备
	pce_lib_cfg_t cfg = {
		.op_addr_mode = PCE_MEM_MODE_VA,
		.iomap = {.iova_map = va_to_iova},
	};
	
	if (pce_lib_init(&cfg)) {
		return -1;
	}

	//申请队列并保存到g_queue_handles中
	init_queue_from_device(queue_num);
	
	//创建轮询响应队列的线程
	//running = 1; 
	create_poll_threads(pollingthreads);

    for (i = 0; i < ALGO_SYM_NUM; i++)
        if (do_sym_or_hash[i])
            pr_header++;

    multi = cmd_option.multi;
    if (multi && do_multi(multi)) {
        goto show_res;
    }

    signal(SIGALRM, sig_done);
    if (usertime == 0 && !mr){ // parent...
        fprintf(stderr, "You have chosen to measure elapsed time "
                        "instead of user CPU time.\n");
    	}

	//创建子线程执行操作，主线程则不执行操作，多线程执行的部分，如果为单线程	
	for(i = 0; i < g_thread_num; i++)
	{
		printf("Main here. Creating thread %d\n",i);
		status = pthread_create(&threads[i], NULL, thread_function, i);
		if(status!=0)
		{
			printf("pthread_create returned error code %d\n",status);
			exit(0);
		}
	}
	
		//running = 0;
	//等待所有线程结束
	for( i = 0;i < g_thread_num; i++)
		pthread_join(threads[i],NULL);

	for( i = 0;i < ((g_queue_num / POLLING_NUM) ); i++)
		pthread_join(pollingthreads[i],NULL);

	pthread_key_delete(thread_key);
	//释放队列，结束设备
	final_queue_from_device(queue_num);
	pce_lib_exit();
/*******************************show results*********************************/
show_res:
    // parent
    //打印多线程测试结果，由主线程执行,i用于处理多线程
    

	if(cmd_option.latency == 1 ){
		//输出延迟测试结果
		show_latency_results(pr_header);
	}else{
		show_results(pr_header);
	}
//error
    for (i = 0;
         i < sizeof(global_perf_algo_list) / sizeof(global_perf_algo_list[0]);
         i++) {
        if (global_perf_algo_list[i].test_enabled &&
            global_perf_algo_list[i].free_data) {
            global_perf_algo_list[i].free_data(loopargs, loopargs_len);
        }
    }

    if (loopargs) {
        for (i = 0; i < loopargs_len; i++) {
            if (loopargs[i].src_buf) {
                free(loopargs[i].src_buf);
            }

            if (loopargs[i].dst_buf) {
                free(loopargs[i].dst_buf);
            }
        }

        free(loopargs);
    }

    return ret;
}
