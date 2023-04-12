#include <stdint.h>
#include <unistd.h>

#include "openssl/bn.h"
#include "openssl/ec.h"

#include "openssl/crypto.h"
#include "openssl/obj_mac.h"

#include "command.h"
#include "lib.h"
#include "ecc.h"

typedef struct {
	uint32_t e_byte_length;
	uint8_t *e_addr;
	uint8_t *pub_key_addr;
	uint8_t *priv_key_addr;
	uint8_t *result_addr;	
	uint8_t *e_signature_addr;
	int algo;

	uint8_t *peer_pub_key_addr;
}ecc_test_data_t;




static const char *test_ecc_curves_names[SM2_NUM] = {
    "eccp256v1",
};
static const int test_ecc_curves_bits[SM2_NUM] = {
    256,
};
int eccsign_doit[SM2_NUM] = {0};
int eccenc_doit[SM2_NUM] = {0};

static double eccsign_results[SM2_NUM][2];
static double eccenc_results[SM2_NUM][2];


static char *d_hex =
    "F4A115840CE610EAEBE6682230D072E88AE891CA803EBB75769A9300E8062742";
static char *xP_hex =
    "9C5DA2F1C38A3BB26334EA02690FF97E41C5DA5BD9C95C9E4FA80C9E7CE9422D";
static char *yP_hex =
    "9299E518237A7E617F3C4547D98E4A9667F774CC67999003BFE4C27FA8D2DF22";

static char *e_hex =
    "9C06F28DE722B449DF3D664F7A64A239AF88A9651993CE1ECF25337178375E27";


static int _init_ecc_test_data(ecc_test_data_t *test_data)
{
    if (NULL == test_data){
		return -1;
    }
	test_data->e_byte_length = 0;
	test_data->e_addr = pce_alloc_mem(mem_node, 0x10000);
	if (NULL == test_data->result_addr) {
		goto out;
	}
	memset(test_data->e_addr, 0, 0x10000);

	test_data->pub_key_addr = pce_alloc_mem(mem_node, 0x10000);
	if (NULL == test_data->pub_key_addr) {
		goto out;
	}
	memset(test_data->pub_key_addr, 0, 0x10000);

	test_data->priv_key_addr = pce_alloc_mem(mem_node, 0x10000);
	if (NULL == test_data->priv_key_addr) {
		goto out;
	}
	memset(test_data->priv_key_addr, 0, 0x10000);

	test_data->result_addr = pce_alloc_mem(mem_node, 0x10000);
	if (NULL == test_data->result_addr) {
		goto out;
	}
	memset(test_data->result_addr, 0, 0x10000);
	test_data->e_signature_addr = pce_alloc_mem(mem_node, 0x10000);
	if (NULL == test_data->e_signature_addr) {
		goto out;
	}
	memset(test_data->e_signature_addr, 0, 0x10000);


	test_data->peer_pub_key_addr= pce_alloc_mem(mem_node, 0x10000);
	if (NULL == test_data->e_addr) {
		goto out;
	}
	memset(test_data->peer_pub_key_addr, 0, 0x10000);
	
	out:

    return 0;
}

int init_ecc_data(loopargs_t *loopargs, int loopargs_len)
{
    int i, j;
    int ret = 0;
    ecc_test_data_t *data;
    for (i = 0; i < loopargs_len; i++) {
	for (j = 0; j < SM2_NUM; j++) {
	    loopargs[i].ecc_data[j] = malloc(sizeof(ecc_test_data_t));
	    memset(loopargs[i].ecc_data[j], 0, sizeof(ecc_test_data_t));
	    ret = _init_ecc_test_data(loopargs[i].ecc_data[j]);
	    if (ret) {
		return ret;
	    }
	}
    }

    return 0;
}

static void _free_ecc_test_data(ecc_test_data_t *test_data)
{
    if (test_data->e_addr)
		pce_free_mem(test_data->e_addr);
	
	if (test_data->pub_key_addr)
		pce_free_mem(test_data->pub_key_addr);

	if (test_data->priv_key_addr)
		pce_free_mem(test_data->priv_key_addr);

	if (test_data->result_addr)
		pce_free_mem(test_data->result_addr);
	
	if (test_data->peer_pub_key_addr)
		pce_free_mem(test_data->peer_pub_key_addr);

	
	if (test_data->e_signature_addr)
		pce_free_mem(test_data->e_signature_addr);
}

void free_ecc_data(loopargs_t *loopargs, int loopargs_len)
{
    int i, j;
    ecc_test_data_t *data;
    for (i = 0; i < loopargs_len; i++) {
	for (j = 0; j < SM2_NUM; j++) {
	    if (loopargs[i].ecc_data[j]) {
		_free_ecc_test_data(loopargs[i].ecc_data[j]);
		free(loopargs[i].ecc_data[j]);
		loopargs[i].ecc_data[j] = NULL;
	    }
	}
    }
}


static int ecc_sign(uint8_t* e_addr, uint8_t* priv_key_addr, uint8_t* result_addr)
{
	int enqueued_count = 0;
	pce_op_data_t **op_datas = NULL;
	pce_op_data_t *ecc_datas = NULL;

	op_datas = malloc(sizeof(pce_op_data_t *));
    if (!op_datas) {
        goto out;
    }

    ecc_datas = malloc(sizeof(pce_op_data_t));
    if (!ecc_datas) {
        goto out;
    }
    memset(ecc_datas, 0, sizeof(pce_op_data_t));
	
	ecc_datas->ecc.sign.e_addr = (uint64_t)e_addr;
	ecc_datas->ecc.sign.priv_key_addr =(uint64_t) priv_key_addr;
	
	ecc_datas->ecc.sign.result_addr = (uint64_t)result_addr;

	struct COMPLETION_STRUCT complete; //初始化信号量

	COMPLETION_INIT(&complete);

	//64是digest数组的长度，不是返回结果的长度。
	//PCE_HASH_SHA1类型未知
	
	op_datas = &(ecc_datas); //满足二级指针的要求
	
    enqueued_count = pce_enqueue(g_queue_handles, op_datas, 1);//入队一个,此处队列句柄来源错误
    if (0 == enqueued_count) {
         goto out;
    }
	
	if (!COMPLETION_WAIT(&complete, TIMEOUT_MS))//等待完成
    {
        fprintf(stderr, "timeout or interruption in %s:%d\n",__func__ , __LINE__);
    }
            //</snippet>
    COMPLETION_DESTROY(&complete); //执行完成后销毁信号量
    //可以考虑使用条件变量进行同步
    out:
    free(ecc_datas);
	return 0;

}

static int ecc_verify(uint8_t* e_signature_addr, uint8_t* pub_key_addr)
{
	int enqueued_count = 0;
	pce_op_data_t **op_datas = NULL;
	pce_op_data_t *ecc_datas = NULL;

	op_datas = malloc(sizeof(pce_op_data_t *));
    if (!op_datas) {
        goto out;
    }

    ecc_datas = malloc(sizeof(pce_op_data_t));
    if (!ecc_datas) {
        goto out;
    }
    memset(ecc_datas, 0, sizeof(pce_op_data_t));
	
	ecc_datas->ecc.verify.e_signature_addr = (uint64_t)e_signature_addr;
	ecc_datas->ecc.verify.pub_key_addr = (uint64_t)pub_key_addr;
	

	struct COMPLETION_STRUCT complete; //初始化信号量

	COMPLETION_INIT(&complete);

	//64是digest数组的长度，不是返回结果的长度。
	//PCE_HASH_SHA1类型未知
	
	op_datas = &(ecc_datas); //满足二级指针的要求
	
    enqueued_count = pce_enqueue(g_queue_handles, op_datas, 1);//入队一个
    if (0 == enqueued_count) {
         goto out;
    }
	
	if (!COMPLETION_WAIT(&complete, TIMEOUT_MS))//等待完成
    {
        fprintf(stderr, "timeout or interruption in %s:%d\n",__func__ , __LINE__);
    }
            //</snippet>
    COMPLETION_DESTROY(&complete); //执行完成后销毁信号量
    //可以考虑使用条件变量进行同步
    out:
    free(ecc_datas);
	return 0;

}



// 0 fail  1 success
static int ecc_sign_test(void *args)
{
    if (NULL == args)
	return 0;

    ecc_test_data_t *data = (ecc_test_data_t *)args;

    return ecc_sign(data->e_addr, data->priv_key_addr, data->result_addr);
}

static int ecc_sign_loop(void *args)
{
    if (NULL == args)
	return 0;

    ecc_test_data_t *data = (ecc_test_data_t *)args;

    ecc_sign(data->e_addr, data->priv_key_addr, data->result_addr);

    return 1;
}

// 0 fail  1 success
static int ecc_verify_test(void *args)
{
    if (NULL == args)
	return 0;

    ecc_test_data_t *data = (ecc_test_data_t *)args;

    return ecc_verify(data->e_signature_addr, data->pub_key_addr);
}

static int ecc_verify_loop(void *args)
{
    if (NULL == args)
	return 0;

    ecc_test_data_t *data = (ecc_test_data_t *)args;

    ecc_verify(data->e_signature_addr, data->pub_key_addr);

    return 1;
}

static int ecc_enc_loop(void *args)
{
    (void)args;

    return 0;
}

/**
 *
 *@ Description: 根据输入的算法名，确认是否执行相关算法， 并自行设置标记
 *
 *
 *@ return 0: 匹配到执行算法，不用继续验证 其他：没有匹配
 */
int test_hit_for_ecc(const char *algo_name)
{
    int ret = -1;

#ifndef OPENSSL_NO_SM2
    int i;
    if (!strcmp(algo_name, "ecc")) {
	for (i = 0; i < SM2_NUM; i++) {
	    eccsign_doit[i] = eccenc_doit[i] = 1;
	}

	ret = 0;
    }

    if (strcmp(algo_name, "eccsign") == 0) {
	for (i = 0; i < SM2_NUM; i++)
	    eccsign_doit[i] = 1;

	ret = 0;
    }

    if (strcmp(algo_name, "eccenc") == 0) {
	for (i = 0; i < SM2_NUM; i++)
	    eccenc_doit[i] = 1;

	ret = 0;
    }
#endif

    return ret;
}

void test_perf_for_ecc(loopargs_t *loopargs)
{
#ifndef OPENSSL_NO_SM2
    int ret;
    int st;
    long count = 0;
    double d;
    int testnum = 0;

    // test ecc sign and verify
    for (testnum = 0; testnum < SM2_NUM; testnum++) {
	st = 1;
	if (!eccsign_doit[testnum]) {
	    continue;
	}

	// 正确性验证
	st = ecc_sign_test(loopargs->ecc_data[testnum]);
	if (0 == st) {
	    count = 1;
	    fprintf(stderr, "SM2 sign failure.  No SM2 sign will be done.\n");
	    continue;
	} else {
	    // 性能测试
	    pkey_print_message("sign", "ecc", 0, test_ecc_curves_bits[testnum],
			       cmd_option.duration);

	    Time_F(START);
	    count = run_benchmark(ecc_sign_loop, loopargs->ecc_data[testnum]);
	    d = Time_F(STOP);
	    fprintf(stderr,
		    mr ? "+R7:%ld:%d:%.2f\n"
		       : "%ld %d bit SM2 signs in %.2fs \n",
		    count, test_ecc_curves_bits[testnum], d);
	    eccsign_results[testnum][0] = d / (double)count; // 每次签名运算耗时
	}

	// 正确性验证
	st = ecc_verify_test(loopargs->ecc_data[testnum]);
	if (0 == st) {
	    fprintf(stderr,
		    "SM2 verify failure.  No SM2 verify will be done.\n");
	    eccsign_doit[testnum] = 0;
	} else {
	    // 性能测试
	    pkey_print_message("verify", "ecc", 0,
			       test_ecc_curves_bits[testnum],
			       cmd_option.duration);
	    Time_F(START);
	    count = run_benchmark(ecc_verify_loop, loopargs->ecc_data[testnum]);
	    d = Time_F(STOP);
	    fprintf(stderr,
		    mr ? "+R8:%ld:%d:%.2f\n"
		       : "%ld %d bit SM2 verify in %.2fs\n",
		    count, test_ecc_curves_bits[testnum],
		    d); // R8 验签结果， +R8 : 运算次数 ： 位数： 耗时秒
	    eccsign_results[testnum][1] = d / (double)count; // 每次验签运算耗时
	}
    }
#endif
}

/**
 *
 *@ Description: 输出ecc算法的执行结果
 *
 * 示例：
 *
 *  Doing 256 bit sign ecc's for 2s: 31593 256 bit SM2 signs in 1.97s
Doing 256 bit verify ecc's for 2s: 5882 256 bit SM2 verify in 2.00s
			      sign    verify    sign/s verify/s
 256 bit ecc (eccp256v1)   0.0001s   0.0003s  16037.1   2941.0
 *
 * +F6:0:256:0.000063:0.000345 // +F6表示类型， 0：位数索引，位数，签名耗时，
验签耗时
 *@ return void
 */
void show_results_for_ecc(void)
{
#ifndef OPENSSL_NO_SM2
    int testnum = 1;
    int k;

    for (k = 0; k < SM2_NUM; k++) {
	if (!eccsign_doit[k])
	    continue;
	if (testnum && !mr) {
	    printf("%30ssign    verify    sign/s verify/s\n", " ");
	    testnum = 0;
	}

	if (mr)
	    printf("+F6:%u:%u:%f:%f\n", k, test_ecc_curves_bits[k],
		   eccsign_results[k][0], eccsign_results[k][1]);
	else
	    printf("%4u bit ecc (%s) %8.4fs %8.4fs %8.1f %8.1f\n",
		   test_ecc_curves_bits[k], test_ecc_curves_names[k],
		   eccsign_results[k][0], eccsign_results[k][1],
		   1.0 / eccsign_results[k][0], 1.0 / eccsign_results[k][1]);
    }
#endif
}

/**
 *
 *@ Description: 解析不同进程的输出，并汇总计算平均每个运算的耗时
	    F6: 签名验签  F7:加密
 *@ buf:       [in] 输出内容
 *@ n:         [in] 进程号
 *@ return 0:已处理  其他：未处理
 */
int do_multi_buf_ecc(char *buf, int n)
{
    int ret = -1;

#ifndef OPENSSL_NO_SM2
    char *p;
    static char sep[] = ":";
    int k;
    double d;

    if (strncmp(buf, "+F6:", 4) == 0) {
	p = buf + 4;
	k = atoi(sstrsep(&p, sep));
	sstrsep(&p, sep);

	d = atof(sstrsep(&p, sep));
	if (n)
	    eccsign_results[k][0] = 1 / (1 / eccsign_results[k][0] + 1 / d);
	else
	    eccsign_results[k][0] = d;

	d = atof(sstrsep(&p, sep));
	if (n)
	    eccsign_results[k][1] = 1 / (1 / eccsign_results[k][1] + 1 / d);
	else
	    eccsign_results[k][1] = d;
	ret = 0;
    } else if (strncmp(buf, "+F7:", 4) == 0) {
	p = buf + 4;
	k = atoi(sstrsep(&p, sep));
	sstrsep(&p, sep);

	d = atof(sstrsep(&p, sep));
	if (n)
	    eccenc_results[k][0] = 1 / (1 / eccenc_results[k][0] + 1 / d);
	else
	    eccenc_results[k][0] = d;

	d = atof(sstrsep(&p, sep));
	if (n)
	    eccenc_results[k][1] = 1 / (1 / eccenc_results[k][1] + 1 / d);
	else
	    eccenc_results[k][1] = d;

	ret = 0;
    }
#endif

    return ret;
}

/*

*/


