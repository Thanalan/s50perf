#define _GNU_SOURCE

#include <pthread.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <signal.h>
#include <sys/times.h>
#include <sys/sysinfo.h>
#include <sched.h>
#include <unistd.h>
#include <pthread.h>
#include "command.h"


#include "perf.h"
#include "digest.h"
#include "cipher.h"
#include "rsa.h"
#include "rand.h"
#include "aead.h"
#include "ecc.h"

//全局变量定义

//全局变量定义
perf_callbacks global_perf_algo_list[];
sem_t end_sem;
sem_t end_poll;
cpu_set_t cpuset;

int numa_node = 0;
pthread_key_t thread_key; //线程私有数据，用于存放每个线程的id和需要执行的loopargs
volatile int running = 0;
volatile int stop_poll = 0;

int g_thread_num = 1; // 线程数量默认值
int g_queue_num = 1;  //队列数量默认值
int g_batch = 1;
int g_queue_depth = PCE_QUEUE_DEPTH_256;
int pr_header = 0;
perf_cmd_args cmd_option = {0};
static volatile int run = 0;
static volatile int poll_run = 0;
struct  timeval tv;
struct  timeval tv1;
sem_t start_sem;  
control_sem *control = NULL;

//非对称结果输出函数
show_results_fn show_results_funcs[MAX_THREAD_NUM];

int akcipher = 0;
int mr = 0; // multi response to parent
static int usertime = 1;
int testnum = 0;

//处理多线程数据，改为三维数组，按照线程号索引进行打印结果。打印结果仍然为主线程
//double results[MAX_THREAD_NUM][ALGO_SYM_NUM][SIZE_NUM] = {0};
double results[MAX_THREAD_NUM][SIZE_NUM] = {0};

//错误计数，可能多线程同时操作，使用gcc的__sync_fetch_and_add操作
int error_counts = 0;

//错误计数是统计所有的错误数量，而不是统计每个线程，或者每个算法的错误数量，
//如果需要后者则采用下面的数组。
//double error_count[MAX_THREAD_NUM][ALGO_SYM_NUM][SIZE_NUM] = {0}; //已经处理的数量

int thread_run_algo[MAX_THREAD_NUM] = {0}; //判断执行了哪些算法
int lengths[SIZE_NUM] = {16,32, 64, 128, 256,512, 1024, 2048, 4 * 1024, 8192,16384};

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
    //DES
    //AES-128
    
    {"des-cbc", PCE_DES_CBC, ALGO_DES_CBC_IDX, ALGO_TYPE_SYM_CIPHER, DES_KEYIV},            
    {"des-cfb", PCE_DES_CFB, ALGO_DES_CFB_IDX, ALGO_TYPE_SYM_CIPHER, DES_KEYIV},
    {"des-ctr", PCE_DES_CFB, ALGO_DES_CTR_IDX, ALGO_TYPE_SYM_CIPHER, DES_KEYIV},
    {"des-ecb", PCE_DES_ECB, ALGO_DES_ECB_IDX, ALGO_TYPE_SYM_CIPHER, DES_KEYIV},        
    {"des-ofb", PCE_DES_OFB, ALGO_DES_OFB_IDX, ALGO_TYPE_SYM_CIPHER, DES_KEYIV},
        
    {"tdes-128-cbc", PCE_TDES_128_CBC, ALGO_TDES_128_CBC_IDX, ALGO_TYPE_SYM_CIPHER, TDES_128_KEYIV},            
    {"tdes-128-cfb", PCE_TDES_128_CFB, ALGO_TDES_128_CFB_IDX, ALGO_TYPE_SYM_CIPHER, TDES_128_KEYIV},
    {"tdes-128-ctr", PCE_TDES_128_CFB, ALGO_TDES_128_CTR_IDX, ALGO_TYPE_SYM_CIPHER, TDES_128_KEYIV},
    {"tdes-128-ecb", PCE_TDES_128_ECB, ALGO_TDES_128_ECB_IDX, ALGO_TYPE_SYM_CIPHER, TDES_128_KEYIV},        
    {"tdes-128-ofb", PCE_TDES_128_OFB, ALGO_TDES_128_OFB_IDX, ALGO_TYPE_SYM_CIPHER, TDES_128_KEYIV},

    {"tdes-192-cbc", PCE_TDES_192_CBC, ALGO_TDES_192_CBC_IDX, ALGO_TYPE_SYM_CIPHER, TDES_192_KEYIV},            
    {"tdes-192-cfb", PCE_TDES_192_CFB, ALGO_TDES_192_CFB_IDX, ALGO_TYPE_SYM_CIPHER, TDES_192_KEYIV},
    {"tdes-192-ctr", PCE_TDES_192_CFB, ALGO_TDES_192_CTR_IDX, ALGO_TYPE_SYM_CIPHER, TDES_192_KEYIV},
    {"tdes-192-ecb", PCE_TDES_192_ECB, ALGO_TDES_192_ECB_IDX, ALGO_TYPE_SYM_CIPHER, TDES_192_KEYIV},        
    {"tdes-192-ofb", PCE_TDES_192_OFB, ALGO_TDES_192_OFB_IDX, ALGO_TYPE_SYM_CIPHER, TDES_192_KEYIV},
    
    //AES128
    {"aes-128-cbc", PCE_AES_128_CBC, ALGO_AES_128_CBC_IDX, ALGO_TYPE_SYM_CIPHER, AES_128_KEYIV},
    
    {"aes-128-ccm", PCE_AES_128_CCM, ALGO_AES_128_CCM_IDX, ALGO_TYPE_AEAD, AES_128_KEYIV},
    
    {"aes-128-cfb", PCE_AES_128_CFB, ALGO_AES_128_CFB_IDX, ALGO_TYPE_SYM_CIPHER, AES_128_KEYIV},
    {"aes-128-ctr", PCE_AES_128_CTR, ALGO_AES_128_CTR_IDX, ALGO_TYPE_SYM_CIPHER, AES_128_KEYIV},
    {"aes-128-cts", 0              , ALGO_AES_128_CTS_IDX, ALGO_TYPE_SYM_CIPHER, AES_128_KEYIV},
    {"aes-128-ecb", PCE_AES_128_ECB, ALGO_AES_128_ECB_IDX, ALGO_TYPE_SYM_CIPHER, AES_128_KEYIV},
    
    {"aes-128-gcm", PCE_AES_128_GCM, ALGO_AES_128_GCM_IDX, ALGO_TYPE_AEAD, AES_128_KEYIV},
    {"aes-128-ocb", 0              , ALGO_AES_128_OCB_IDX, ALGO_TYPE_AEAD, AES_128_KEYIV},
    
    {"aes-128-ofb", PCE_AES_128_OFB, ALGO_AES_128_OFB_IDX, ALGO_TYPE_SYM_CIPHER, AES_128_KEYIV},
    {"aes-128-xts", PCE_AES_128_XTS, ALGO_AES_128_XTS_IDX, ALGO_TYPE_SYM_CIPHER, AES_128_XTS_KEYIV},

    //AES-192
    {"aes-192-cbc", PCE_AES_192_CBC, ALGO_AES_192_CBC_IDX, ALGO_TYPE_SYM_CIPHER, AES_192_KEYIV},
    
    {"aes-192-ccm", PCE_AES_192_CCM, ALGO_AES_192_CCM_IDX, ALGO_TYPE_AEAD, AES_192_KEYIV},
    
    {"aes-192-cfb", PCE_AES_192_CFB, ALGO_AES_192_CFB_IDX, ALGO_TYPE_SYM_CIPHER, AES_192_KEYIV},
    {"aes-192-ctr", PCE_AES_192_CTR, ALGO_AES_192_CTR_IDX, ALGO_TYPE_SYM_CIPHER, AES_192_KEYIV},
    {"aes-192-cts", 0              , ALGO_AES_192_CTS_IDX, ALGO_TYPE_SYM_CIPHER, AES_192_KEYIV},
    {"aes-192-ecb", PCE_AES_192_ECB, ALGO_AES_192_ECB_IDX, ALGO_TYPE_SYM_CIPHER, AES_192_KEYIV},
    
    {"aes-192-gcm", PCE_AES_192_GCM, ALGO_AES_192_GCM_IDX, ALGO_TYPE_AEAD, AES_192_KEYIV},
    {"aes-192-ocb", 0              , ALGO_AES_192_OCB_IDX, ALGO_TYPE_AEAD, AES_192_KEYIV},
    
    {"aes-192-ofb", PCE_AES_192_OFB, ALGO_AES_192_OFB_IDX, ALGO_TYPE_SYM_CIPHER, AES_192_KEYIV},
    {"aes-192-xts", 0              , ALGO_AES_192_XTS_IDX, ALGO_TYPE_SYM_CIPHER, 0},

    //AES-256
    {"aes-256-cbc", PCE_AES_256_CBC, ALGO_AES_256_CBC_IDX, ALGO_TYPE_SYM_CIPHER, AES_256_KEYIV},
    
    {"aes-256-ccm", PCE_AES_256_CCM, ALGO_AES_256_CCM_IDX, ALGO_TYPE_AEAD, AES_256_KEYIV},
    
    {"aes-256-cfb", PCE_AES_256_CFB, ALGO_AES_256_CFB_IDX, ALGO_TYPE_SYM_CIPHER, AES_256_KEYIV},
    {"aes-256-ctr", PCE_AES_256_CTR, ALGO_AES_256_CTR_IDX, ALGO_TYPE_SYM_CIPHER, AES_256_KEYIV},
    {"aes-256-cts", 0              , ALGO_AES_256_CTS_IDX, ALGO_TYPE_SYM_CIPHER, AES_256_KEYIV},
    {"aes-256-ecb", PCE_AES_256_ECB, ALGO_AES_256_ECB_IDX, ALGO_TYPE_SYM_CIPHER, AES_256_KEYIV},
    
    {"aes-256-gcm", PCE_AES_256_GCM, ALGO_AES_256_GCM_IDX, ALGO_TYPE_AEAD, AES_256_KEYIV},
    {"aes-256-ocb", 0              , ALGO_AES_256_OCB_IDX, ALGO_TYPE_AEAD, AES_256_KEYIV},
    
    {"aes-256-ofb", PCE_AES_256_OFB, ALGO_AES_256_OFB_IDX, ALGO_TYPE_SYM_CIPHER, AES_256_KEYIV},
    {"aes-256-xts", PCE_AES_256_XTS, ALGO_AES_256_XTS_IDX, ALGO_TYPE_SYM_CIPHER, AES_256_XTS_KEYIV},

    //SM4
    {"sm4-cbc", PCE_SM4_CBC, ALGO_SM4_CBC_IDX, ALGO_TYPE_SYM_CIPHER, SM4_KEYIV},    
    {"sm4-ccm", PCE_SM4_CCM, ALGO_SM4_CCM_IDX, ALGO_TYPE_AEAD, SM4_KEYIV},
    {"sm4-cfb", PCE_SM4_CFB, ALGO_SM4_CFB_IDX, ALGO_TYPE_SYM_CIPHER, SM4_KEYIV},
    {"sm4-ctr", PCE_SM4_CFB, ALGO_SM4_CTR_IDX, ALGO_TYPE_SYM_CIPHER, SM4_KEYIV},
    {"sm4-cts", 0          , ALGO_SM4_CTS_IDX, ALGO_TYPE_SYM_CIPHER, SM4_KEYIV},
    {"sm4-ecb", PCE_SM4_ECB, ALGO_SM4_ECB_IDX, ALGO_TYPE_SYM_CIPHER, SM4_KEYIV},
    
    {"sm4-gcm", PCE_SM4_GCM, ALGO_SM4_GCM_IDX, ALGO_TYPE_AEAD, SM4_KEYIV},
    {"sm4-ocb", 0          , ALGO_SM4_OCB_IDX, ALGO_TYPE_AEAD, SM4_KEYIV},
    
    {"sm4-ofb", PCE_SM4_OFB, ALGO_SM4_OFB_IDX, ALGO_TYPE_SYM_CIPHER, SM4_KEYIV},
    {"sm4-xts", PCE_SM4_XTS, ALGO_SM4_XTS_IDX, ALGO_TYPE_SYM_CIPHER, SM4_XTS_KEYIV},
    
    {"rand", PCE_RANDOM, ALGO_RAND_IDX, ALGO_TYPE_RAND, 0},

    //非对称加密,最后一项存放长度
    {"rsa-1024", PCE_RSA_KEY, ALGO_RSA_1024_IDX, ALGO_TYPE_RSA, 1024},
    {"rsa-2048", PCE_RSA_KEY, ALGO_RSA_2048_IDX, ALGO_TYPE_RSA, 2048},
    {"rsa-3072", PCE_RSA_KEY, ALGO_RSA_3072_IDX, ALGO_TYPE_RSA, 3072},
    {"rsa-4096", PCE_RSA_KEY, ALGO_RSA_4096_IDX, ALGO_TYPE_RSA, 4096},
    
    {"ecc-192", PCE_ECC_KEY, ALGO_ECC_SECP192R1_IDX, ALGO_TYPE_ECC, PCE_ECC_CURVE_SECP192R1},
    {"ecc-224", PCE_ECC_KEY, ALGO_ECC_SECP224R1_IDX, ALGO_TYPE_ECC, PCE_ECC_CURVE_SECP224R1},
    {"ecc-256", PCE_ECC_KEY, ALGO_ECC_SECP256R1_IDX, ALGO_TYPE_ECC, PCE_ECC_CURVE_SECP256R1},
    {"ecc-384", PCE_ECC_KEY, ALGO_ECC_SECP384R1_IDX, ALGO_TYPE_ECC, PCE_ECC_CURVE_SECP384R1},
    {"ecc-521", PCE_ECC_KEY, ALGO_ECC_SECP521R1_IDX, ALGO_TYPE_ECC, PCE_ECC_CURVE_SECP521R1},
    
    {"sm2",PCE_SM2_KEY,ALGO_SM2_IDX,ALGO_TYPE_SM2,0},
    {NULL, 0 , 0, 0}
};

hash_map *g_algo_hash_table; //全局变量，用于查找算法

//创建算法查找表
int create_algo_hashtable()
{
    int i;
    g_algo_hash_table = create_hash_map(ALGO_SYM_NUM); //ALGO_SYM_NUM是算法的最大值
    
    for(i = 0; i < ALGO_SYM_NUM ; i++)
    {
        if(algo_datas[i].algo != NULL){
            put_hash_map(g_algo_hash_table, algo_datas[i].algo,&algo_datas[i]); //直接插入索引本身的值
        }else{
            break;
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
    //stop_poll =2;
    //running = 0;
    for(int i = 0; i < poll_thread_num; i++){
        control[i].poll_run = 0;
    }
    //run = 0;
}

int run_benchmark(bench_function loop_function, loopargs_t *loopargs)
{
    int count, i;
    uint16_t thread_id = loopargs->thread_id ;
    sem_t *end_sem = &control[thread_id % poll_thread_num].end_sem;
    //printf("thread:%d endsemaddr:%lx\n",thread_id,end_sem);
    control[thread_id % poll_thread_num].run = 1;
    count = 0;
    //0x3fffffff用于防止死锁
    for (i = 0;control[thread_id % poll_thread_num].run && i < 0x0ffffffff; i++) {
        //允许一个线程向两个队列发送数据
        #ifdef USE_ONE_TO_MULTI
        loopargs->ring = &perf_rings[thread_id + 2 *(i&1)];
        //if(thread_id == 1)
          //  printf("thread:%d send to %d poll_thread_num:%d\n",thread_id,thread_id + 2*(i & 1),poll_thread_num);
        #endif
       
        count += loop_function((void *)loopargs);
         //if(thread_id == 0)
            //printf("thread:%d send to %d poll_thread_num:%d\n",thread_id,thread_id + 2*(i & 1),poll_thread_num);
        if(sem_trywait(end_sem) == 0 ){
            break;
        }
    }
    return count;
}

typedef struct {
    pce_rsp_t *rsp_datas;
    int rsp_datas_size;
    int thread_id;
}poll_struct;

int run_poll_benchmark(bench_function loop_function, poll_struct *loopargs)
{
    int count, i;
    uint16_t thread_id = loopargs->thread_id;
    volatile int *stop_poll = &(control[thread_id % poll_thread_num].stop_poll);
    volatile int *poll_run = &(control[thread_id % poll_thread_num].poll_run);
    *poll_run = 1;

    count = 0;
    for (i = 0; (*poll_run) && i < 0xfffffffff; i++) {
        count += loop_function((void *)loopargs);
        //if(thread_id == 1){
            //printf("pollthread 1 loopfunc\n");
        //}
        if((*stop_poll) == 1){
            break;
        }
    }

    return count;
}


perf_callbacks global_perf_algo_list[] = {
    {
     .test_algo = test_perf_for_sm2,
     .proc_multi_buf = do_multi_buf_sm2},     
     {
     .test_algo = test_perf_for_rsa,
     .test_hit = test_hit_for_rsa,
     .proc_multi_buf = do_multi_buf_rsa},
    {
    .test_algo = test_perf_for_ecc,
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
                   // results[alg][j] += atof(sstrsep(&p, sep));
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

static int list_all_algorithms(){
    int i, cnt = 0;
    printf("Supported algorithms:\n");
    for(i = 0; i < ARRAY_SIZE(algo_datas); i++){
        if(algo_datas[i].pce_algo != 0){
            printf("%-15s\t",algo_datas[i].algo);
            cnt ++;
            if(cnt % 5 == 0){
                printf("\n");
            }
            
        }
    }
    printf("\n");
}


//获得algo有几个算法
int get_algo_name_num(char *name)
{   
    int i = 0;
    char *p = NULL;
    if(name == NULL){
        //fprintf(stderr, "No algo input!\n");
        return -1;
    }
    char str1[50] = { 0 };
    strcpy(str1, name); //复制一份
    for (p = strtok(str1, "+");p != NULL;p=strtok(NULL,"+")) {
        i++;
    }
    return i; //此处返回值要注意是否是参数个数，而不是参数个数-1
}

char* get_algo_name(char* name, int index)
{   
    int i = 0;
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
    int i;
    //int ret = -1;
    //int loopargs_len = 1; // only support one args now.
    loopargs_t *loopargs = NULL;
    int loopnum = 1;
    int thread_id = id;
    int poll_thread_num = ((g_queue_num - 1)/ POLLING_NUM) +1;//最少创建一个线程，大于4则创建两个
    loopargs = malloc(sizeof(loopargs_t));
    if (NULL == loopargs) {
        fprintf(stderr, "alloc memory failed  in %s:%d\n",__func__ , __LINE__);
        //return -1;
    }
    memset(loopargs, 0, sizeof(loopargs_t));

    //线程绑定核心
    SET_THREAD_TO_CPU(COMPUTE_THREAD_CPU(thread_id));
    printf("thread: %d run at cpu:%d\n",thread_id, sched_getcpu());
    loopargs->algo_name = (uint8_t*)malloc(sizeof(uint8_t) * 256); 
    memset(loopargs->algo_name , 0 ,sizeof(char) * 256); 
    //如果是混合模式，则根据线程id和对应的参数号进行分割
    if(cmd_option.mixed != NULL) //混合模式
    {
        //在混合模式此时会设置algo_name
        strcpy(loopargs->algo_name , get_algo_name(cmd_option.mixed,thread_id)); //获得本线程应该执行的算法
    }else if(cmd_option.algo_name != NULL){

        //在非混合模式此时不会设置algo_name,此数组仍然0
        loopnum = get_algo_name_num(cmd_option.algo_name); //获得algo_name有几个参数，如果输入只有一个参数，则返回1
        strcpy(loopargs->algo_name , get_algo_name(cmd_option.algo_name, 0)); //获得第一次执行的算法
    }

    //因为每个线程执行的函数相同，但是访问的数据不同，所以需要线程私有数据，每个线程存一个副本
    pthread_setspecific(thread_key, (void*)loopargs);
    loopargs->src_buf = pce_alloc_mem(numa_node, lengths[SIZE_NUM - 1] + 64); //源数据
    printf("src_buf:%lx\n",loopargs->src_buf);
    loopargs->dst_buf = pce_alloc_mem(numa_node, lengths[SIZE_NUM - 1] + 64);  //分配数据的最大长度
    loopargs->src = loopargs->src_buf;
    loopargs->dst = loopargs->dst_buf;

    loopargs->ring =  get_queue_handle_from_ring(thread_id, g_thread_num, g_queue_num); //需要设置为申请的队列地址,也就是一个loopargs对应一个队列对
    //分配请求的空间
    //printf("loopargs->ring:%lx\n",loopargs->ring);
    loopargs->requests = malloc((sizeof(pce_op_data_t)) * g_batch);
    loopargs->op_datas = malloc((sizeof(pce_op_data_t*)) * g_batch);
    loopargs->batch = 1;
    loopargs->thread_id = thread_id;
    sem_t *end_poll = &(control[thread_id % poll_thread_num].end_poll);
    sem_t *start_sem = GET_START_SEM();
    //如果有多个输入算法，则执行多次，如果为mix的，则只会执行一次
    for(i = 0 ; i < loopnum; i++ ){
        memset(loopargs->src_buf , 0 ,(lengths[SIZE_NUM - 1] + 64));
        memset(loopargs->dst_buf , 0 ,(lengths[SIZE_NUM - 1] + 64));

        loopargs->index = i;
        if((loopargs->algo_name[0] == 0) &&(loopargs->algo_name[1] == 0)) { //如果前两个字符被设置，则表示不是第一次执行
            //获得算法
            strcpy(loopargs->algo_name,get_algo_name(cmd_option.algo_name,i)); //将不是第一次执行的算法 algo_name修改为新算法
        }

        algo_data_t *algo_data = (algo_data_t*)get_hash_map(g_algo_hash_table, loopargs->algo_name);
        if(algo_data == NULL){
            fprintf(stderr,"Invaild algoname:%s,please check input algoname!\n",loopargs->algo_name);
            list_all_algorithms();
            exit(0);
            goto out;
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
            case ALGO_TYPE_SM2:
                akcipher = 1;
                test_perf_for_sm2(loopargs);
                break;
            case ALGO_TYPE_ECC:
                loopargs->test_length = algo_data->algo_longness; //获取curvetype
                akcipher = 1;
                test_perf_for_ecc(loopargs);
                break;
            case ALGO_TYPE_RSA:
                loopargs->test_length = algo_data->algo_longness; //获得算法长度
                akcipher = 1;
                test_perf_for_rsa(loopargs);
                break;
            default:
                fprintf(stderr,"unsupport algo type in func:%s in line:%d\n",__func__,__LINE__);

        }
        //memset(loopargs->algo_name, 0, sizeof(char) * 256); //名称数组长度为50个字符，清零
        fprintf(stderr, "run func %s in thread id:%d for %d times\n",__func__ ,thread_id,i+1);
    }
out:
    sem_post(end_poll);
    control[thread_id % poll_thread_num].poll_run = 0;
    control[thread_id % poll_thread_num].stop_poll = 1;
    poll_run = 0;
    __sync_fetch_and_add(&stop_poll ,1);
    //执行完后释放,loopargs
    pce_free_mem(loopargs->src_buf);
   // printf("src_buf:%lx\n",loopargs->src_buf);
    //printf("609\n");
    pce_free_mem(loopargs->dst_buf);
   // printf("610\n");
    pce_free_mem(loopargs->requests);
   // printf("611\n");
    pce_free_mem(loopargs->op_datas);
   // printf("614\n");
    free(loopargs->algo_name);
    free(loopargs);
    sem_post(end_poll);
    sem_post(start_sem);
    //__sync_fetch_and_sub(&control[thread_id % poll_thread_num].end1,1);
     for(i = 0;i < ((g_queue_num - 1)/ POLLING_NUM)+1 ; i++){
            sem_post(&control[i].start_sem);
    }
    return NULL;

}


#define prefetch(x) __builtin_prefetch(x)

//处理响应队列的结果
int poll_queue(void* polling)
{
    poll_struct *poll = polling;
    int step = ((g_queue_num - 1)/ POLLING_NUM) +1;//最少创建一个线程，大于4则创建两个
    //int poll_thread_num = step;
    pce_queue_handle queue_handle;
    int dequeued_count; 
    int i = 0,k = 0;
    pce_rsp_t *rsp_datas = poll->rsp_datas;;
    int rsp_datas_size = 1; //一次出队的最大数量，建议和队列长度一致，
    int thread_id = poll->thread_id;

    for(i = 0; i < g_queue_num; i++){
        if(thread_id + step *i > g_queue_num - 1){
            break;
        }
        queue_handle = perf_rings[thread_id + step *i].queue_handle;//获得本次轮询的队列句柄
        if(unlikely(queue_handle == NULL)){
            fprintf(stderr,"poll queue:thread:%d queue_handle:%d is null\n",thread_id,thread_id + step *i );
            continue;
        }
        dequeued_count = pce_dequeue(queue_handle, rsp_datas, rsp_datas_size);//尽量多出队

        for (k = 0; k < dequeued_count; k++) {
            uint64_t  callback = rsp_datas[k].tag;  
            //如果不是由测试程序发送的请求，则掠过，通过判断callback的head部分值是否为ABCD进行判断是否是测试程序的请求
            //printf("rsp_datas:state:%lx\n",rsp_datas[i].state);

            //由于sm2即使算法成功也没有将tag带回，所以只能使用result的[0][0][0]成员进行计数！！
            //同时由于没有带回tag，所以不能通过CALLBACK_HEAD_IS_VAILD判断是否是本测试程序下发的请求
            //因此只能借用result的第一个数据成员存放结果
            //对称加密以及摘要算法可以将tag带回，因此可以使用CALLBACK_HEAD_IS_VAILD判断是否是本测试程序下发的请求

            if ( 1/*CALLBACK_HEAD_IS_VAILD(callback) && rsp_datas[i].state == CMD_SUCCESS*/ ) {
                //printf("responce_error:%lx ,%ld,%ld\n",callback,GET_CALLBACK_THREAD_ID(callback),GET_CALLBACK_ALGOINDEX(callback));
                //results[GET_CALLBACK_THREAD_ID(callback)][GET_CALLBACK_ALGOINDEX(callback)][GET_CALLBACK_TEST_NUM(callback)]++;
                results[GET_CALLBACK_THREAD_ID(callback)][GET_CALLBACK_TEST_NUM(callback)]++;
            }else {
                printf("responce_error:%lx ,%ld,%ld\n",callback,GET_CALLBACK_THREAD_ID(callback),GET_CALLBACK_ALGOINDEX(callback));
                __sync_fetch_and_add(&error_counts, 1);
            }
            //错误计数,仅统计没有成功执行的数量，而不包括入队失败的数量
            //if(rsp_datas[i].state ! = CMD_SUCCESS){
                //error_count[GET_CALLBACK_THREAD_ID(callback_tag)][GET_CALLBACK_ALGOINDEX(callback_tag)]++;
            //}
        }

    }
    return 0;
}

sem_t start_timer;
sem_t start_poll;

int timer(void){
    //由主线程执行,控制定时
    int i= 0;
    for(i = 0;i < poll_thread_num;i++){
        sem_wait(&start_timer);
        control[i].poll_run =1;
    }
    Time_F(START);
    running = 1;
    poll_run = 1;
    while(poll_run);
    for(i = 0;i < poll_thread_num;i++){
        sem_post(&start_poll);
    }
    Time_F(STOP);
    //printf("timer:685\n");
    return 0;
}

volatile double used_time;

void* process_response(void * id) //仅需要轮询对应的队列即可，也可也轮询所有的队列
{
    int i = 0;
    pce_rsp_t *rsp_datas;
    int max_dequeue_count = g_queue_depth;//一次性出队最大数目
    int thread_id = id;//消除pthread_create向函数传参数必须为void*类型的警告
    poll_struct poll;
    int step = ((g_queue_num - 1)/ POLLING_NUM) +1;//最少创建一个线程，大于4则创建两个
    SET_THREAD_TO_CPU(thread_id + 5);
    printf("pollthread: %d run at cpu:%d\n",thread_id, sched_getcpu());
    rsp_datas = malloc(sizeof(pce_rsp_t) * max_dequeue_count);
        if (NULL == rsp_datas) {
            goto out;
    }
    poll.rsp_datas = rsp_datas;
    poll.rsp_datas_size = max_dequeue_count;
    poll.thread_id = thread_id;
    sem_t *end_sem = &control[thread_id].end_sem;
    sem_t *start_sem = &control[thread_id].start_sem;
    //sem_t *end_poll = &control[thread_id].end_poll;
    //开始计时
    int k;
    do{ 
        sem_init(end_sem,0,0);
        printf("thread: %d stop_poll:%d  in 733\n",thread_id,stop_poll);
        for(i = 0; i < (g_thread_num /step); i++){
            //sem_getvalue(start_sem,&k);
            //printf("start_sem:%d\n",k);
            sem_wait(start_sem);
        }
        sem_post(&start_timer);
        while(running == 0);
        //Time_F(START);
       // printf("\npollthread:%d line 694\n",thread_id);
        run_poll_benchmark(poll_queue, &poll);
        //d = Time_F(STOP);

        //结束计时,通知结束发送
        //used_time = d;
        control[thread_id % poll_thread_num].run = 0;
        for(i= 0; i < (g_thread_num /step); i++){
            //sem_getvalue(end_sem,&k);
            //printf("end_sem:%d\n",k);
            sem_post(end_sem);
        }
    }while(/*sem_trywait(end_poll) != 0*/stop_poll != g_thread_num );
    printf("\npollthread:%d line 717 end poll\n",thread_id);
    printf("thread: %d stop_poll:%d g_thread_num:%d in 756\n",thread_id,stop_poll,g_thread_num);
out:
    if (rsp_datas) {
        pce_free_mem(rsp_datas);
    }
    return NULL;

}

int poll_thread_num;

int create_poll_threads(pthread_t *pollingthread)
{
    int i;
    poll_thread_num = ((g_queue_num -1 ) / POLLING_NUM) + 1;//最少创建一个线程，大于4则创建两个
    sem_init(&start_timer,0,0);
    sem_init(&start_poll,0,0);
    control = malloc(sizeof(control_sem) * poll_thread_num);
    memset(control, 0,sizeof(control_sem) * poll_thread_num);
    printf("create poll thread nums:%d\n",poll_thread_num);
    for(i = 0;i < poll_thread_num; i++){
        //轮询线程一个暂定为负责四个队列，如果创建的队列数量大于四个，假设为7个，则会创建两个线程，
        //0号线程负责0，2，4，6，0号线程负责1，3，5，队列
        //大于八个则会创建三个线程，以此类推
        sem_init(&control[i].start_sem, 0, 0);
        sem_init(&control[i].end_sem, 0, 0);
        sem_init(&control[i].end_poll, 0, 0);
        control[i].poll_run = 0;
        control[i].stop_poll = 0;
        control[i].run = 0;
        pthread_create(&pollingthread[i],NULL,process_response,i);//第四个参数可以找到响应队列，
    }
    return 0;

}

//虚拟地址转为物理地址
void *va_to_pa(void * va){
    return (void *)pce_mem_virt2iova(va);
}
void *va_to_iova(void *usr, void *va)
{
    return (void *)pce_mem_virt2iova(va);
}


int show_results(int pr_header) //多线程输出结果不正确
{
    int i = 0, k = 0;
    int length = cmd_option.test_length;
    //打印多线程测试结果，由主线程执行,i用于处理多线程
    int testnum = 0;
    for(i = 0; i < g_thread_num ; i++){
        printf("Benchmark result of thread: %d\n", i);
        #ifdef USE_ONE_TO_MULTI
        printf("thread:%d alloc to queue:%d and %d\n", i,i,i + 2);
        #else
        printf("thread:%d alloc to queue:%d\n", i,i % poll_thread_num);
        #endif
        if (pr_header) { // for sym or hash etc.
            if (mr)      // child
                printf("+H");
            else { // parent
                printf("The 'numbers' are in 1000s of bytes per second processed.\n");
            }
            printf("\n");
        }
        k = thread_run_algo[i];
        if ((akcipher == 1)/*&& mr*/ ){
            printf("show akcipher results:\n");
            (show_results_funcs[i](i));
        
        }else{
            printf("type        ");
            printf("%s", algo_datas[k].algo);
            printf("\n");
            printf("  data_size");
            printf("   speed/KBps");
            printf("  speed/Mbps");
            printf("\n");
        }
        if(length > 0){
            printf(mr?":%d":"%7dbytes",length);
            testnum = SIZE_NUM - 1;
           // printf(" %11.2f",results[i][testnum]*length/((1e3)* used_times[i][testnum]));
           // printf(" %11.2f",results[i][testnum]*length*8/((1e6)*used_times[i][testnum]));
            printf(" %11.2f",results[i][testnum]*length/((1e3)* cmd_option.duration ));
            printf(" %11.2f",results[i][testnum]*length*8/((1e6)* cmd_option.duration ));
            printf("\n");
            continue;
        }else{
        for (testnum = 0; (akcipher == 0)&& testnum < SIZE_NUM; testnum++) {
            printf(mr?":%d":"%7dbytes",lengths[testnum]);
                if (results[i][testnum] > 1/*0000*/ && !mr){
                    //因为所有线程是同步启动和停止，所用时间基本一致，和cmd_options相差不大，因此采用cmd_options.duration
                    //具体值可以通过打印used_times[i]进行判断
                    printf(" %11.2f", results[i][testnum]*lengths[testnum] / ((1e3) *cmd_option.duration /* used_times[i][testnum]*/));
                    printf(" %11.2f", results[i][testnum]*lengths[testnum]*8/((1e6) * cmd_option.duration/*used_times[i]/*[testnum]*/));
                    //printf(" %11.2f", used_times[i]/*[testnum]*/);
                    printf("\n");
                }else{
                    //printf(mr ? ":%.2f" : " %11.2f ", results[i][testnum]*lengths[testnum]/((1e3)* used_times[i]/*[testnum]*/));
                    //printf(mr ? ":%.2f" : " %11.2f ", results[i][testnum]*lengths[testnum]*8/((1e6)* used_times[i]/*[testnum]*/));
                    printf("\n");}
                }
        }
        printf("\n");

    }
    //错误计数
    printf("error count:%d\n",error_counts);
    return 0;
}

int show_latency_results(int pr_header)
{
    int i = 0;
    //int k = 0;
    //double latency = 0;
    double sum[SIZE_NUM] = {0};
    int test_num;
    for(i = 0; i < g_thread_num ; i++){
        //延迟是各个线程的延迟的平均值
        //表示这是第i个线程的计算结果，子线程从0开始，不包括主线程
        for (test_num = 0; test_num < SIZE_NUM; test_num++) {
            sum[test_num] += (used_times[i]/*[test_num]*/ / results[i][test_num]);            
        }
    }
    //取平均值
    for(i = 0;i < SIZE_NUM; i++){
        sum[i] = sum[i] / g_thread_num;
        printf("latency of length:%d is %11.4f ns\n",lengths[i],sum[i] * (1e9)); //单位是ns,需要乘1e6
    }
    return 0;
}

static int set_global_variables()
{
    if(cmd_option.list != 0){
        list_all_algorithms();
        exit(0);
    }
    if(get_algo_name_num(cmd_option.mixed) > 0){ //如果有MIX的输入，则使用mix
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
        if(g_thread_num > MAX_THREAD_NUM){
            fprintf(stderr,"Input thread num is greater than MAX_THREAD_NUM,only use %d!!\n",MAX_THREAD_NUM);
            g_thread_num = MAX_THREAD_NUM;

        }
    }
    
    if(cmd_option.queue_num >= 1){
        g_queue_num = cmd_option.queue_num;
        if(g_queue_num > MAX_QUEUE_NUM){
            fprintf(stderr,"Input queue num is greater than MAX_THREAD_NUM,only use %d!!\n",MAX_QUEUE_NUM);
            g_queue_num = MAX_QUEUE_NUM;
        }

         if(g_queue_num > g_thread_num){
            fprintf(stderr,"Input queue num is greater than thread_num,only use %d!!\n",g_thread_num);
            //g_queue_num = g_thread_num;
        }
    }
//如果允许一个线程向两个队列发送数据
#ifdef USE_ONE_TO_MULTI
    //如果开启此宏，队列数量必须为偶数,奇数会出现问题
    if(g_queue_num % 2 == 1)
        g_queue_num --;
    g_thread_num = g_queue_num / 2;
#endif
    if(cmd_option.batch > g_batch){ //如果不这样设置会出现错误corrupted size vs. prev_size
        g_batch = cmd_option.batch > 32? cmd_option.batch : 32;
    }

    if(cmd_option.numa_node  > numa_node){ //更新numa_node的值
        numa_node = cmd_option.numa_node;
        if(numa_node > 4){
            fprintf(stderr,"Input numa num is greater than MAX_NUMA_NUM,only use %d!!\n",0);
            numa_node = 0;
        }
    }
    if(cmd_option.depth != 0){ //如果传入了depth
        switch(cmd_option.depth){
            case 256:
                g_queue_depth = PCE_QUEUE_DEPTH_256;
                break;
            case 1024:
                g_queue_depth = PCE_QUEUE_DEPTH_1024;
                break;
            case 8192:
                g_queue_depth = PCE_QUEUE_DEPTH_8192;
                break;
            case 65536:
                g_queue_depth = PCE_QUEUE_DEPTH_65536;
                break;
            default:
                fprintf(stderr,"Invaid depth input:%d in func:%s line %d\n",cmd_option.depth,__func__,__LINE__);
                fprintf(stderr,"supported size:256, 1024, 8192, 65536\n");
                g_queue_depth = PCE_QUEUE_DEPTH_256;
                break;
        }
    }else{
        fprintf(stderr,"No depth input,use default queue depth: 256\n");
        g_queue_depth = PCE_QUEUE_DEPTH_256;
    }
    return 0;
}



int main(int argc, char **argv)
{
    int i;
    int ret = 0;
    int multi = 0;
    int status = 0;
    pthread_t pollingthreads[MAX_QUEUE_NUM / POLLING_NUM]; //轮询线程最大数量

    pthread_t threads[MAX_NUMBER_OF_THREADS];

    ret = perf_cmd_parse(&cmd_option, argc, argv);
    if (ret) {
        return ret;
    }
    //创建映射表
    
    set_global_variables(); 
    printf("number of cpu:%d\n",get_nprocs());
    pthread_key_create(&thread_key, NULL);//创建线程私有数据    
    create_algo_hashtable();

    //初始化设备
    pce_lib_cfg_t cfg = {
        .op_addr_mode = PCE_MEM_MODE_VA,
        .iomap = {.iova_map = va_to_iova},
    };

    if (pce_lib_init(&cfg)) {
        return -1;
    }
    
    CPU_ZERO(&cpuset);

    //申请队列并保存到perf_ring中
    mp_ring_init(g_queue_num);

    //创建轮询响应队列的线程
    create_poll_threads(pollingthreads);

    multi = cmd_option.multi;
    if (multi && do_multi(multi)) {
        goto show_res;
    }

    signal(SIGALRM, sig_done);
    if (usertime == 0 && !mr){ // parent...
        fprintf(stderr, "You have chosen to measure elapsed time "
                        "instead of user CPU time.\n");
    }

    //创建子线程执行操作
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

    //主线程负责定时
    timer();
    
    for(i = 0;i < g_thread_num; i++)
        pthread_join(threads[i],NULL);

    for(i = 0;i < ((g_queue_num - 1)/ POLLING_NUM)+1 ; i++){
        pthread_join(pollingthreads[i],NULL);
            sem_destroy(&control[i].start_sem);
		sem_destroy(&control[i].end_sem);
		sem_destroy(&control[i].end_poll);
    }
    pthread_key_delete(thread_key);
    //final_queue_from_device(queue_num);
    mp_ring_free(g_queue_num);
    pce_lib_exit();
    pce_free_mem(control);
    hash_map_clear(g_algo_hash_table);
/*******************************show results*********************************/
show_res:

    if(cmd_option.latency == 1 ){
        show_latency_results(pr_header);
    }else{
        show_results(pr_header);
    }
    return ret;
}
