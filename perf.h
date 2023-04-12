#ifndef __PERF_H_
#define __PERF_H_

#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include <pthread.h>
#include <semaphore.h>
#include <sys/time.h>

#include "command.h"
#include "hashtable.h"
#define USE_INTER_PCE 1
#if 0
#include <pce/pce_crypto.h>

#include <pce/pce.h>
#include <pce/pce_common.h>

#include <pce/pce_utils.h>
#else
#include "pce_crypto.h"

#include "pce.h"
#include "pce_common.h"

#include "pce_utils.h"
#endif

#define SIZE_NUM (9)
#define ALGOR_NUM (34)

#define EC_NIST_NUM 5
#define EC_NUM (EC_NIST_NUM)
#define EC_NIST_IDX_192 (0)
#define EC_NIST_IDX_224 (1)
#define EC_NIST_IDX_256 (2)
#define EC_NIST_IDX_384 (3)
#define EC_NIST_IDX_521 (4)
#define SM2_NUM (1)

//rsa包括1个操作
#define RSA_NUM (1)

#define MAX_THREAD_NUM 16
#define MAX_QUEUE_NUM 16

#define START 0
#define STOP 1

enum ALGO_TYPE{
	ALGO_TYPE_HASH = 0,
	ALGO_TYPE_HMAC = 1,
	ALGO_TYPE_SYM_CIPHER = 2,
	ALGO_TYPE_AEAD = 3,
	ALGO_TYPE_ASYM =4,
	ALGO_TYPE_RAND =5
};

//更改算法模式，对称算法统一为算法名称加模式，格式与openssl算法名称一致
enum ALGO_IDX {
    ALGO_MD5_IDX = 0,
    ALGO_HMAC_MD5_IDX = 1,
    ALGO_SHA1_IDX,
    ALGO_HMAC_SHA1_IDX,
    ALGO_SM3_IDX,
    ALGO_HMAC_SM3_IDX,
    ALGO_SHA2_224_IDX,
    ALGO_HMAC_SHA2_224_IDX,
    ALGO_SHA2_256_IDX,
    ALGO_HMAC_SHA2_256_IDX,
    ALGO_SHA2_384_IDX,
    ALGO_HMAC_SHA2_384_IDX,
    ALGO_SHA2_512_IDX,
    ALGO_HMAC_SHA2_512_IDX,
    ALGO_SHA3_224_IDX,
    ALGO_HMAC_SHA3_224_IDX,
    ALGO_SHA3_256_IDX,
    ALGO_HMAC_SHA3_256_IDX,
    ALGO_SHA3_384_IDX,
    ALGO_HMAC_SHA3_384_IDX,
    ALGO_SHA3_512_IDX,
    ALGO_HMAC_SHA3_512_IDX,
    //以下为新增
    //AES-128
    ALGO_AES_128_CBC_IDX,
    ALGO_AES_128_CCM_IDX,
    ALGO_AES_128_CFB_IDX,
    ALGO_AES_128_CTR_IDX,
    ALGO_AES_128_CTS_IDX,
    ALGO_AES_128_ECB_IDX,
    ALGO_AES_128_GCM_IDX,
    ALGO_AES_128_OCB_IDX,
    ALGO_AES_128_OFB_IDX,
    ALGO_AES_128_XTS_IDX,
    
    //AES 192
    ALGO_AES_192_CBC_IDX,
    ALGO_AES_192_CCM_IDX,
    ALGO_AES_192_CFB_IDX,
    ALGO_AES_192_CTR_IDX,
    ALGO_AES_192_CTS_IDX,
    ALGO_AES_192_ECB_IDX,
    ALGO_AES_192_GCM_IDX,
    ALGO_AES_192_OCB_IDX,
    ALGO_AES_192_OFB_IDX,
    ALGO_AES_192_XTS_IDX,
    
    //AES 256
    ALGO_AES_256_CBC_IDX,
    ALGO_AES_256_CCM_IDX,
    ALGO_AES_256_CFB_IDX,
    ALGO_AES_256_CTR_IDX,
    ALGO_AES_256_CTS_IDX,
    ALGO_AES_256_ECB_IDX,
    ALGO_AES_256_GCM_IDX,
    ALGO_AES_256_OCB_IDX,
    ALGO_AES_256_OFB_IDX,
    ALGO_AES_256_XTS_IDX,
    
    //SM4
    ALGO_SM4_CBC_IDX,
    ALGO_SM4_CCM_IDX,
    ALGO_SM4_CFB_IDX,
    ALGO_SM4_CTR_IDX,
    ALGO_SM4_CTS_IDX,
    ALGO_SM4_ECB_IDX,
    ALGO_SM4_GCM_IDX,
    ALGO_SM4_OCB_IDX,
    ALGO_SM4_OFB_IDX,
    ALGO_SM4_XTS_IDX,

	//rand
	ALGO_RAND_IDX,

	//asym cipher
	ALGO_SM2_IDX,
	//结束
	ALGO_SYM_NUM,
    ALGO_SYM_INVALID = ALGO_SYM_NUM
    
};

enum ALGO_SYM_MODE {
    ALGO_SYM_MODE_CBC = 0,
    ALGO_SYM_MODE_CCM = 1,
    ALGO_SYM_MODE_CFB = 2,
    ALGO_SYM_MODE_CTR = 3,
    ALGO_SYM_MODE_CTS = 4,
    ALGO_SYM_MODE_GCM = 5,
    ALGO_SYM_MODE_OCB = 6,
    ALGO_SYM_MODE_OFB = 7,
    ALGO_SYM_MODE_XTS = 8,
    ALGO_SYM_MODE_ECB = 8,
    ALGO_SYM_MODE_NUM,
    ALGO_SYM_MODE_INVALID = ALGO_SYM_MODE_NUM
};

enum ALGO_HASH_MODE {
    ALGO_HASH_IDX = 0,
    ALGO_HMAC_IDX = 1,
    ALGO_HASH_MODE_NUM
};

typedef int (*bench_function)(void *);

//测试函数
typedef int (*test_fn)(void *args);

typedef struct {
	char *algo; //算法名称,格式参考openssl evp,作为hashmap的key,用于存放算法
	uint16_t pce_algo; //算法在pce_crypto.h中的索引，PCE_AES_128_XTS
	int algo_index ; //内部索引，即ALGO_AES_192_CBC_IDX,
	int algo_type; //算法类型
	int algo_longness; // 如果是摘要算法，则存放摘要长度，如果是加密算法，则存放key和iv的长度，前16位存放key,后16位存放iv
	//通过接口访问，不建议直接访问
}algo_data_t;

extern algo_data_t algo_datas[];
extern HashMap *g_algo_hash_table; 
typedef struct string_int_pair_st {
    const char *name;
    int retval;
} OPT_PAIR, STRINT_PAIR;

extern int mr;
extern int lengths[SIZE_NUM];
extern perf_cmd_args cmd_option;

extern int thread_run_algo[MAX_THREAD_NUM] ;

extern double results[MAX_THREAD_NUM][ALGO_SYM_NUM][SIZE_NUM];
extern double latency_results[MAX_THREAD_NUM][ALGO_SYM_NUM][SIZE_NUM];

extern int do_sym_or_hash[ALGO_SYM_NUM];
extern int processed_count[ALGO_SYM_NUM];


extern int ceu_node;
extern int mem_node;
extern int cpu_node;
extern pthread_key_t thread_key; //用于访问线程私有数据
extern pce_queue_handle g_queue_handles[MAX_QUEUE_NUM];
extern int g_thread_num ; // 线程数量默认值
extern int g_queue_num ;
extern int g_batch;
extern volatile int running ;
extern volatile int stop_poll;

extern sem_t start_sem;
extern sem_t end_sem;
extern sem_t end_poll;
extern volatile double used_time;
extern struct	timeval    tv;
extern struct  timeval	tv1;


struct completion_struct
{
    sem_t semaphore;
	int i;
};

/* Use semaphores to signal completion of events */
#define COMPLETION_STRUCT completion_struct

#define COMPLETION_INIT(s)  sem_init(&((s)->semaphore), 0, 0);
//sem_init(&((s)->semaphore), 0, 0);

#define COMPLETION_WAIT(s, timeout) (sem_wait(&((s)->semaphore)) == 0)

#define COMPLETE(s) sem_post(&((s)->semaphore))

#define COMPLETION_DESTROY(s) sem_destroy(&((s)->semaphore))

#define PRINT_ERR(args...)                                                     \
    do                                                                         \
    {                                                                          \
        printf("%s, %s():%d ", __FILE__, __func__, __LINE__);                   \
        printf(args);                                                           \
    } while (0)

#define PRINT_DBG(args...)                                                 \
    do                                                                     \
    {                                                                      \
        printf("%s(): ", __func__);                                        \
        printf(args);                                                      \
        fflush(stdout);                                                    \
    }                                                                      \
     while (0)



//container_of宏,通过已知的一个数据结构成员指针ptr，数据结构类型type,获取结构体首地址
//#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#define container_of(ptr, type, member) ({              \
	const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
	(type *)( (char *)__mptr - offsetof(type,member) );})




typedef struct callback_t{
	void (*callbackfunc)(void *pCallbackTag);
	void *op_tag;
	struct COMPLETION_STRUCT *complete; //信号量，用于同步完成状态
	int algo_index; //索引完成计数
	int test_num;
	int thread_id;
	int *process_count;
}callback_context_t;

typedef struct {
    int index;
    int reserved[8];
    uint8_t *src_buf;
    uint8_t *dst_buf;
    uint8_t *src;
    uint8_t *dst;
    void *rsa_data[RSA_NUM];
	void *sm2_data;
    void *ecc_data;
    int test_length;
    pce_queue_handle queue_handle;//队列描述符，目前仅有一个队列
	uint16_t cipher_algo; //用于存放对称加密算法，类型为 enum pce_alg,也用于存放aead算法
	uint16_t hash_algo; //用于存放摘要算法，类型为enum pce_alg
	uint8_t *cipher_key; //对称加密的密钥+iv，也用于存放aeadkey+iv
	//request
	pce_op_data_t *requests;
	callback_context_t *callbacks;
	pce_op_data_t **op_datas;
	int batch;
	int algo_index;
	int testnum;
	int *processed_count;
} loopargs_t;

//线程私有数据定义
typedef struct tlv_t{
	int thread_id;		//线程编号，作用类似于tid,
	loopargs_t *loopargs; //循环参数
	//perf_callbacks *perf_func_table; //函数表，用于不同线程执行不同的操作
	pce_queue_handle queue; //指示本线程往哪个队列发送请求，目前仅实现一个线程往一个队列发送，或者多对一，而没有实现一对多。
	int *do_sym_or_hash;   //存放此线程需要执行的函数操作
	char *algo_name; //算法名称
}thread_local_variables_t;


//opdata 在外部申请空间，然后传入指针进行修改成员的值，返回
//hash_alg 算法枚举值，不同算法的值不同，在驱动头文件中定义

void print_result(int alg, int run_no, int count, double time_used, int thread_id);
void print_message(const char *s, long num, int length, int sec_time);
void pkey_print_message(const char *str, const char *str2, long num, int bits,
                        int tm);
double Time_F(int s);
int run_benchmark(bench_function loop_function, loopargs_t *loopargs);
char *sstrsep(char **string, const char *delim);
int found(const char *name, const OPT_PAIR *pairs, int *result);


typedef int (*test_hit_fn)(const char *algo_name);
typedef int (*init_data_fn)(loopargs_t *loopargs, int loopargs_len);
typedef void (*free_data_fn)(loopargs_t *loopargs, int loopargs_len);
typedef void (*test_algo_fn)(loopargs_t *loopargs);
typedef void (*show_results_fn)(void);
typedef int (*proc_multi_buf_fn)(char *buf, int n);

typedef struct {
    int test_enabled;
    init_data_fn init_data;
    free_data_fn free_data;
    test_algo_fn test_algo;
    show_results_fn show_results;
    test_hit_fn test_hit;
    proc_multi_buf_fn proc_multi_buf;
} perf_callbacks;

static void symcallback(void *callbacktag);
void *va_to_iova(void *usr, void *va);


//算法需要的长度定义
#define AES_MIN_KEY_SIZE	16
#define AES_MAX_KEY_SIZE	32

#define AES_KEYSIZE_128		16
#define AES_KEYSIZE_192		24
#define AES_KEYSIZE_256		32

#define AES_BLOCK_SIZE		16

#define AES_IVKEY_LEN	(32)
#define AES_IV_LEN	(16)
#define SM4_KEYSIZE 16
#define SM4_IV_LEN 16

#define BUILD_KEY_IV_LEN(keylen,ivlen) \
	((keylen) << (16) + ivlen )

//取高16位
#define GET_KEYLEN_FORM_STRUCT(num)\
	((num >> 16 ) & 0x0000FFFF)

//取低16位
#define GET_IVLEN_FROM_STRUCT(num)\
	((num) & 0x0000FFFF)

enum ALGO_SYM_KEY_IV_LEN {
	AES_128_KEYIV = ((AES_KEYSIZE_128) <<(16)) + AES_IV_LEN,
	AES_192_KEYIV = ((AES_KEYSIZE_192) << (16))+ AES_IV_LEN,
	AES_256_KEYIV = ((AES_KEYSIZE_256) << (16)) + AES_IV_LEN,
	AES_128_XTS_KEYIV = ((AES_KEYSIZE_128 * 2) << (16)) + AES_IV_LEN, //xts需要两个密钥
	AES_256_XTS_KEYIV = ((AES_KEYSIZE_256 * 2) << (16)) + AES_IV_LEN, //xts需要两个密钥
	SM4_KEYIV = ((SM4_KEYSIZE) << (16)) + SM4_IV_LEN,
	SM4_XTS_KEYIV = ((SM4_KEYSIZE *2) << (16)) + SM4_IV_LEN,
};

enum ALGO_DIGEST_LEN{
	MD5_LEN = 16,
	SHA1_LEN = 20,
	SHA224_LEN = 28,
	SHA256_LEN = 32,
	SHA384_LEN = 48,
	SHA512_LEN = 64,
	SHA3_224_LEN = 28,
	SHA3_256_LEN = 32,
	SHA3_384_LEN = 48,
	SHA3_512_LEN = 64,
	SM3_LEN = 32,

};

static void symcallback(void *callbacktag)
{
	callback_context_t *callback = callbacktag;

    if (NULL != callback)
    {
		//processed_count[callback->algo_index]++; //增加已经处理的数量
		//COMPLETE(callback->complete);
		callback->process_count[callback->algo_index]++;
    }
	
}


#endif
