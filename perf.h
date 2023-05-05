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
#if 1
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

//此宏用于控制一个线程向两个队列发送数据
//线程数量为队列数量整除以2
//#define USE_ONE_TO_MULTI 

//设置轮询线程的cpu分配策略
//例如将轮询线程从cpu5开始依次分配，或者是从cpu16开始从后往前分配，在此修改
//轮询线程数量由POLLING_NUM和队列数量通过((队列数量-1)/POLLING_NUM + 1 )计算得到
//POLLING_NUM宏用于指定轮询线程最多轮询几个队列
//举例，如果设置为2，分配4个队列，则表示一个轮询线程最多轮询2个队列
//0号负责0 2 队列，1号线程负责1 3队列
//如果分配5个队列，则会创建三个轮询线程，0号负责0 2 队列，1号线程负责1 3 队列，2号线程负责4号队列

#define POLLING_NUM 2

#define COMPUTE_POLL_THREAD_CPU(id) \
                            (id + 5)

//设置任务下发侠女的分配策略，目前是从0开始依次分配
#define COMPUTE_THREAD_CPU(id)\
                       (id + 0)

//设置最大队列数量和最大线程数量
#define MAX_QUEUE_NUM 16
#define MAX_NUMBER_OF_THREADS 16
#define MAX_NUMA_NUM 3

#define SIZE_NUM (11)
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

#ifndef true
#define true (0 == 0)
#endif

#ifndef false
#define false (0 == 1)
#endif



enum ALGO_TYPE{
    ALGO_TYPE_HASH = 0,
    ALGO_TYPE_HMAC = 1,
    ALGO_TYPE_SYM_CIPHER = 2,
    ALGO_TYPE_AEAD = 3,
    ALGO_TYPE_RAND = 4,
    ALGO_TYPE_RSA = 5,
    ALGO_TYPE_ECC = 6,
    ALGO_TYPE_SM2 = 7
    
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

    //DES
    ALGO_DES_CBC_IDX,
    ALGO_DES_CFB_IDX,
    ALGO_DES_CTR_IDX,
    ALGO_DES_ECB_IDX,
    ALGO_DES_OFB_IDX,
    ALGO_TDES_128_CBC_IDX,
    ALGO_TDES_128_CFB_IDX,
    ALGO_TDES_128_CTR_IDX,
    ALGO_TDES_128_ECB_IDX,
    ALGO_TDES_128_OFB_IDX,
    ALGO_TDES_192_CBC_IDX,
    ALGO_TDES_192_CFB_IDX,
    ALGO_TDES_192_CTR_IDX,
    ALGO_TDES_192_ECB_IDX,
    ALGO_TDES_192_OFB_IDX,
   
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
    ALGO_RSA_1024_IDX,
    ALGO_RSA_2048_IDX,
    ALGO_RSA_3072_IDX,
    ALGO_RSA_4096_IDX,

    ALGO_ECC_SECP192R1_IDX,
    ALGO_ECC_SECP224R1_IDX,
    ALGO_ECC_SECP256R1_IDX,
    ALGO_ECC_SECP384R1_IDX,
    ALGO_ECC_SECP521R1_IDX,
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
    uint16_t algo_index ; //内部索引，即ALGO_AES_192_CBC_IDX,
    int algo_type; //算法类型
    int algo_longness; // 如果是摘要算法，则存放摘要长度，如果是加密算法，则存放key和iv的长度，前16位存放key,后16位存放iv
} algo_data_t ;

extern algo_data_t algo_datas[];
extern hash_map *g_algo_hash_table; 
typedef struct string_int_pair_st {
    const char *name;
    int retval;
} OPT_PAIR, STRINT_PAIR;

extern int mr;
extern int lengths[SIZE_NUM];
extern perf_cmd_args cmd_option;


extern int g_queue_depth;
extern int thread_run_algo[MAX_THREAD_NUM] ;

//extern double results[MAX_THREAD_NUM][ALGO_SYM_NUM][SIZE_NUM]; //存放处理的数量
extern double results[MAX_THREAD_NUM][SIZE_NUM]; //存放处理的数量

extern int ceu_node;
extern int mem_node;
extern int cpu_node;
extern pthread_key_t thread_key; //用于访问线程私有数据

extern int g_thread_num ; // 线程数量默认值
extern int g_queue_num ;
extern int g_batch;
extern int ceu_node;
extern int numa_node;
extern volatile int running ;
extern volatile int stop_poll;
extern int g_enqueue_batch;
extern struct   timeval    tv;
extern struct  timeval  tv1;
//extern double error_count[MAX_THREAD_NUM][ALGO_SYM_NUM][SIZE_NUM];
extern double used_times[MAX_THREAD_NUM];

/*typedef struct callback_t{
    void (*callbackfunc)(void *pCallbackTag);
    void *op_tag;
    int algo_index; //索引完成计数
    int test_num;
    uint16_t thread_id;
    int *process_count;
}callback_context_t;
*/

#define RTE_CACHE_LINE_SIZE 64 
#define __cache_aligned
__attribute__((__aligned__(RTE_CACHE_LINE_SIZE)))

typedef struct{
    pce_queue_handle queue_handle;
    int reference_count;
    /** Ring producer status. */
    struct prod {
        uint32_t watermark;      /**< Maximum items before EDQUOT. */
        uint32_t sp_enqueue;     /**< True, if single producer. */
        uint32_t size;           /**< Size of ring. */
        uint32_t mask;           /**< Mask (size-1) of ring. */
        volatile uint32_t head;  /**< Producer head. */
        volatile uint32_t tail;  /**< Producer tail. */
    } prod;
    struct cons {
        uint32_t sc_dequeue;     /**< True, if single consumer. */
        uint32_t size;           /**< Size of the ring. */
        uint32_t mask;           /**< Mask (size-1) of ring. */
        volatile uint32_t head;  /**< Consumer head. */
        volatile uint32_t tail;  /**< Consumer tail. */
    } cons;
    pce_op_data_t **op_datas;
    
} perf_ring;

extern perf_ring *perf_rings;

int mp_ring_init(int queue_num);
int mp_ring_free(int queue_num);
perf_ring *get_queue_handle_from_ring(int thread_id,int thread_num,int queue_num);
int mp_dequeue(perf_ring *ring, pce_op_data_t **ops,unsigned int n);

int mp_enqueue(perf_ring *ring, pce_op_data_t **ops,unsigned int n);

typedef struct {
    sem_t start_sem;
    sem_t end_sem;
    sem_t end_poll;
    struct timeval tv;
    struct timeval tv1;
    volatile int stop_poll;
    volatile int poll_run;
}control_sem;

extern control_sem *control;
extern int poll_thread_num;

typedef struct {
    int index;
    uint8_t *algo_name; //算法名称
    uint8_t *src_buf;
    uint8_t *dst_buf;
    uint8_t *src;
    uint8_t *dst;
    void *asym_data;
    int test_length;
    pce_queue_handle queue_handle;//队列描述符，目前仅有一个队列
    uint16_t cipher_algo; //用于存放对称加密算法，类型为 enum pce_alg,也用于存放aead算法
    uint16_t hash_algo; //用于存放摘要算法，类型为enum pce_alg
    uint8_t *cipher_key; //对称加密的密钥+iv，也用于存放aeadkey+iv
    pce_op_data_t *requests;
    pce_op_data_t **op_datas;
    int batch;
    uint16_t algo_index;
    uint16_t testnum; //测试长度
    uint16_t thread_id;
    perf_ring *ring;
    bool use_linklist;
}__cache_aligned loopargs_t;

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
typedef void (*show_results_fn)(uint16_t);
typedef int (*proc_multi_buf_fn)(char *buf, int n);

extern show_results_fn show_results_funcs[MAX_THREAD_NUM];

typedef struct {
    int test_enabled;
    init_data_fn init_data;
    free_data_fn free_data;
    test_algo_fn test_algo;
    show_results_fn show_results;
    test_hit_fn test_hit;
    proc_multi_buf_fn proc_multi_buf;
} perf_callbacks;

void *va_to_pa(void *va);


//算法需要的长度定义
#define AES_MIN_KEY_SIZE    16
#define AES_MAX_KEY_SIZE    32

#define AES_KEYSIZE_128     16
#define AES_KEYSIZE_192     24
#define AES_KEYSIZE_256     32

#define AES_BLOCK_SIZE      16

#define AES_IVKEY_LEN   (32)
#define AES_IV_LEN  (16)
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
    DES_KEYIV = ((SM4_KEYSIZE) << (16)) + SM4_IV_LEN, //DES需要往硬件写两次一样的iv，但测试中所有的IV都是0，所有直接借用
    TDES_128_KEYIV = ((SM4_KEYSIZE) << (16)) + SM4_IV_LEN, 
    TDES_192_KEYIV = ((SM4_KEYSIZE) << (16)) + SM4_IV_LEN, 
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
//tag总共有64位，拆分为四部分,各占16位
//| head   |  reserverd | thread_id | algo_index|   
//|
//低16位存放algo_index

#define SET_CALLBACK_INIT() \
    uint64_t callback = 0;\
    callback |= ((0xABCD000000000000 ) &0xFFFF000000000000);

#define SET_CALLBACK_ALGOINDEX(index) \
    callback |= ((index)&0x000000000000FFFF);

#define SET_CALLBACK_TEST_NUM(num) \
    callback |= (((num)<< 16)& 0x00000000FFFF0000);

#define SET_CALLBACK_THREAD_ID(num) \
        callback |= (((uint64_t)(num)<< 32)&0x0000FFFF00000000);


#define GET_CALLBACK_ALGOINDEX(callback)\
    (callback & 0x000000000000FFFF)

#define GET_CALLBACK_TEST_NUM(callback)\
    ((callback>>16)&0x000000000000FFFF)
    
#define GET_CALLBACK_THREAD_ID(callback)\
    ((callback>>32)&0x000000000000FFFF)

//判断是否为本测试程序的数据
#define CALLBACK_HEAD_IS_VAILD(callback)\
    !(((callback) >> 48) ^ 0x000000000000ABCD)


#define GET_START_SEM()\
    &control[thread_id % poll_thread_num].start_sem;
#define GET_END_SEM()\
     &control[thread_id % poll_thread_num].end_sem;
#define GET_END_POLL_SEM()\
     &control[thread_id % poll_thread_num].end_poll;

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))


//将线程分配到cpu
#define SET_THREAD_TO_CPU(num)                                                \
            CPU_ZERO(&cpuset);                                                \
            CPU_SET(num , &cpuset);                                           \
            pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);


#endif
