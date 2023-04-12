#include <stdint.h>
#include <unistd.h>



#include "command.h"
#include "lib.h"
#include "rsa.h"

typedef struct {
	uint16_t e_bitlen;
	uint16_t n_bitlen;
	
	uint8_t *e_addr;
	uint8_t *d_addr;
	uint8_t *n_addr;

	uint8_t *data_addr;
	uint8_t *result_addr;
	uint8_t *key_addr;
	uint8_t *signature_addr;

	int algo;
}rsa_test_data_t;

int mem_node = 0;



#ifndef OPENSSL_NO_SM2
static const char *test_rsa_curves_names[SM2_NUM] = {
    "rsap256v1",
};
static const int test_rsa_curves_bits[SM2_NUM] = {
    256,
};
int rsasign_doit[RSA_NUM] = {0};
int rsaenc_doit[RSA_NUM] = {0};

static double rsasign_results[RSA_NUM][2];
static double rsaenc_results[RSA_NUM][2];
#endif

static char *d_hex =
    "F4A115840CE610EAEBE6682230D072E88AE891CA803EBB75769A9300E8062742";
static char *xP_hex =
    "9C5DA2F1C38A3BB26334EA02690FF97E41C5DA5BD9C95C9E4FA80C9E7CE9422D";
static char *yP_hex =
    "9299E518237A7E617F3C4547D98E4A9667F774CC67999003BFE4C27FA8D2DF22";
/* e = H(ZA||M)
 * ID = "ALICE123@YAHOO.COM" 414c494345313233405941484f4f2e434f4d
 * ZA = "C6BEEE2E0DCA43B03CAF0DB1CFD0985C217DB7872F1C10404D5AA7B0978F28DF"
 * M  = "message digest digest" 6d6573736167652064696765737420646967657374
 * e  = 9C06F28DE722B449DF3D664F7A64A239AF88A9651993CE1ECF25337178375E27
 */
static char *e_hex =
    "9C06F28DE722B449DF3D664F7A64A239AF88A9651993CE1ECF25337178375E27";


//此处仅进行初始化和清零，忘记赋值了，之后补上
static int _init_rsa_test_data(rsa_test_data_t *test_data)
{
    if (NULL == test_data){
		return -1;
    }
	test_data->result_addr = pce_alloc_mem(mem_node, 0x10000);
	if (NULL == test_data->result_addr) {
		goto out;
	}
	memset(test_data->result_addr, 0, 0x10000);
		
	test_data->data_addr = pce_alloc_mem(mem_node, 0x10000);
	if (NULL == test_data->data_addr) {
		goto out;
	}
	memset(test_data->data_addr, 0, 0x10000);

	test_data->key_addr = pce_alloc_mem(mem_node, 0x10000);
	if (NULL == test_data->key_addr) {
		goto out;
	}
	memset(test_data->key_addr, 0, 0x10000);

	test_data->signature_addr = pce_alloc_mem(mem_node, 0x10000);
	if (NULL == test_data->signature_addr) {
		goto out;
	}
	memset(test_data->signature_addr, 0, 0x10000);


	test_data->e_addr= pce_alloc_mem(mem_node, 0x10000);
	if (NULL == test_data->e_addr) {
		goto out;
	}
	memset(test_data->e_addr, 0, 0x10000);
	
	test_data->d_addr = pce_alloc_mem(mem_node, 0x10000);
	if (NULL == test_data->d_addr) {
		goto out;
	}
	memset(test_data->d_addr, 0, 0x10000);
	
	test_data->n_addr = pce_alloc_mem(mem_node, 0x10000);
	if (NULL == test_data->n_addr) {
		goto out;
	}
	memset(test_data->n_addr, 0, 0x10000);

	test_data->e_bitlen = 0;
	test_data->n_bitlen = 0;

	out:

    return 0;
}

int init_rsa_data(loopargs_t *loopargs, int loopargs_len)
{
    int i, j;
    int ret = 0;
	
	rsa_test_data_t *data;
    for (i = 0; i < loopargs_len; i++) {
	for (j = 0; j < RSA_NUM; j++) {
	    loopargs[i].rsa_data[j] = malloc(sizeof(rsa_test_data_t));
	    memset(loopargs[i].rsa_data[j], 0, sizeof(rsa_test_data_t));
	    ret = _init_rsa_test_data(loopargs[i].rsa_data[j]);
	    if (ret) {
		return ret;
	    }
	}
    }

    return 0;
}

static void _free_rsa_test_data(rsa_test_data_t *test_data)
{
    if (test_data->e_addr)
		pce_free_mem(test_data->e_addr);
	
	if (test_data->d_addr)
		pce_free_mem(test_data->d_addr);

	if (test_data->n_addr)
		pce_free_mem(test_data->n_addr);

	if (test_data->result_addr)
		pce_free_mem(test_data->result_addr);
	
	if (test_data->data_addr)
		pce_free_mem(test_data->data_addr);

	if (test_data->key_addr)
		pce_free_mem(test_data->key_addr);
	
	if (test_data->signature_addr)
		pce_free_mem(test_data->signature_addr);
    
}

void free_rsa_data(loopargs_t *loopargs, int loopargs_len)
{
    int i, j;
    rsa_test_data_t *data;
    for (i = 0; i < loopargs_len; i++) {
	for (j = 0; j < RSA_NUM; j++) {
	    if (loopargs[i].rsa_data[j]) {
		_free_rsa_test_data(loopargs[i].rsa_data[j]);
		free(loopargs[i].rsa_data[j]);
		loopargs[i].rsa_data[j] = NULL;
	    }
	}
    }
}


static int rsa_sign(uint16_t e_bit_length, uint16_t n_bit_length, uint8_t* data_addr, uint8_t* key_addr, uint8_t* result_addr)
{
	int enqueued_count = 0;
	pce_op_data_t **op_datas = NULL;
	pce_op_data_t *rsa_datas = NULL;

	op_datas = malloc(sizeof(pce_op_data_t *));
    if (!op_datas) {
        goto out;
    }

    rsa_datas = malloc(sizeof(pce_op_data_t));
    if (!rsa_datas) {
        goto out;
    }
    memset(rsa_datas, 0, sizeof(pce_op_data_t));
	
	rsa_datas->rsa.sign.e_bit_length = e_bit_length;
	rsa_datas->rsa.sign.n_bit_length = n_bit_length;
	
	rsa_datas->rsa.sign.key_addr = (uint64_t)key_addr;
	rsa_datas->rsa.sign.data_addr = (uint64_t)data_addr;
	rsa_datas->rsa.sign.result_addr = (uint64_t)result_addr;

	struct COMPLETION_STRUCT complete; //初始化信号量

	COMPLETION_INIT(&complete);

	//64是digest数组的长度，不是返回结果的长度。
	//PCE_HASH_SHA1类型未知
	
	op_datas = &(rsa_datas); //满足二级指针的要求
	
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
    free(rsa_datas);
	return 0;

}

static int rsa_verify(uint16_t e_bit_length, uint16_t n_bit_length, uint8_t* signature_addr,
						uint8_t* e_addr, uint8_t* n_addr,uint8_t* result_addr)
{
	int enqueued_count = 0;
	pce_op_data_t **op_datas = NULL;
	pce_op_data_t *rsa_datas = NULL;

	op_datas = malloc(sizeof(pce_op_data_t *));
    if (!op_datas) {
        goto out;
    }

    rsa_datas = malloc(sizeof(pce_op_data_t));
    if (!rsa_datas) {
        goto out;
    }
    memset(rsa_datas, 0, sizeof(pce_op_data_t));
	
	rsa_datas->rsa.verify.e_bit_length = e_bit_length;
	rsa_datas->rsa.verify.n_bit_length = n_bit_length;
	
	rsa_datas->rsa.verify.signature_addr = (uint64_t)signature_addr;
	rsa_datas->rsa.verify.e_addr = (uint64_t)e_addr;
	rsa_datas->rsa.verify.n_addr = (uint64_t)n_addr;
	rsa_datas->rsa.verify.result_addr = (uint64_t)result_addr;

	struct COMPLETION_STRUCT complete; //初始化信号量

	COMPLETION_INIT(&complete);

	//64是digest数组的长度，不是返回结果的长度。
	//PCE_HASH_SHA1类型未知
	
	op_datas = &(rsa_datas); //满足二级指针的要求
	
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
    free(rsa_datas);
	return 0;

}

static int rsa_genkey(uint16_t e_bit_length, uint16_t n_bit_length, uint8_t* e_addr,
						uint8_t* d_addr, uint8_t* n_addr)
{
	int enqueued_count = 0;
	pce_op_data_t **op_datas = NULL;
	pce_op_data_t *rsa_datas = NULL;

	op_datas = malloc(sizeof(pce_op_data_t *));
    if (!op_datas) {
        goto out;
    }

    rsa_datas = malloc(sizeof(pce_op_data_t));
    if (!rsa_datas) {
        goto out;
    }
    memset(rsa_datas, 0, sizeof(pce_op_data_t));
	
	rsa_datas->rsa.genkey.e_bit_length = e_bit_length;
	rsa_datas->rsa.genkey.n_bit_length = n_bit_length;
	
	rsa_datas->rsa.genkey.d_addr = (uint64_t)d_addr;
	rsa_datas->rsa.genkey.e_addr = (uint64_t)e_addr;
	rsa_datas->rsa.genkey.n_addr = (uint64_t)n_addr;


	struct COMPLETION_STRUCT complete; //初始化信号量

	COMPLETION_INIT(&complete);

	//64是digest数组的长度，不是返回结果的长度。
	//PCE_HASH_SHA1类型未知
	
	op_datas = &(rsa_datas); //满足二级指针的要求
	
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
	free(rsa_datas);
	return 0;

}


// 0 fail  1 success
static int rsa_sign_test(void *args)
{
    if (NULL == args)
	return 0;

    rsa_test_data_t *data = (rsa_test_data_t *)args;

    return rsa_sign(data->e_bitlen, data->n_bitlen, data->data_addr, data->key_addr,data->result_addr);
}

static int rsa_sign_loop(void *args)
{
    if (NULL == args)
	return 0;

    rsa_test_data_t *data = (rsa_test_data_t *)args;

    return rsa_sign(data->e_bitlen, data->n_bitlen, data->data_addr, data->key_addr,data->result_addr);

}

// 0 fail  1 success
static int rsa_verify_test(void *args)
{
    if (NULL == args)
	return 0;

    rsa_test_data_t *data = (rsa_test_data_t *)args;

    return rsa_verify(data->e_bitlen, data->n_bitlen,data->signature_addr,data->e_addr,data->n_addr,data->result_addr);
		      
}

static int rsa_verify_loop(void *args)
{
    if (NULL == args)
	return 0;

    rsa_test_data_t *data = (rsa_test_data_t *)args;

    return rsa_verify(data->e_bitlen, data->n_bitlen,data->signature_addr,data->e_addr,data->n_addr,data->result_addr);

}

static int rsa_enc_loop(void *args)
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
int test_hit_for_rsa(const char *algo_name)
{
    int ret = -1;

#ifndef OPENSSL_NO_SM2
    int i;
    if (!strcmp(algo_name, "rsa")) {
	for (i = 0; i < SM2_NUM; i++) {
	    rsasign_doit[i] = rsaenc_doit[i] = 1;
	}

	ret = 0;
    }

    if (strcmp(algo_name, "rsasign") == 0) {
	for (i = 0; i < SM2_NUM; i++)
	    rsasign_doit[i] = 1;

	ret = 0;
    }

    if (strcmp(algo_name, "rsaenc") == 0) {
	for (i = 0; i < SM2_NUM; i++)
	    rsaenc_doit[i] = 1;

	ret = 0;
    }
#endif

    return ret;
}

void test_perf_for_rsa(loopargs_t *loopargs)
{
#ifndef OPENSSL_NO_SM2
    int ret;
    int st;
    long count = 0;
    double d;
    int testnum = 0;

    // test rsa sign and verify
    for (testnum = 0; testnum < SM2_NUM; testnum++) {
	st = 1;
	if (!rsasign_doit[testnum]) {
	    continue;
	}

	// 正确性验证
	st = rsa_sign_test(loopargs->rsa_data[testnum]);
	if (0 == st) {
	    count = 1;
	    fprintf(stderr, "SM2 sign failure.  No SM2 sign will be done.\n");
	    continue;
	} else {
	    // 性能测试
	    pkey_print_message("sign", "rsa", 0, test_rsa_curves_bits[testnum],
			       cmd_option.duration);

	    Time_F(START);
	    count = run_benchmark(rsa_sign_loop, loopargs->rsa_data[testnum]);
	    d = Time_F(STOP);
	    fprintf(stderr,
		    mr ? "+R7:%ld:%d:%.2f\n"
		       : "%ld %d bit SM2 signs in %.2fs \n",
		    count, test_rsa_curves_bits[testnum], d);
	    rsasign_results[testnum][0] = d / (double)count; // 每次签名运算耗时
	}

	// 正确性验证
	st = rsa_verify_test(loopargs->rsa_data[testnum]);
	if (0 == st) {
	    fprintf(stderr,
		    "SM2 verify failure.  No SM2 verify will be done.\n");
	    rsasign_doit[testnum] = 0;
	} else {
	    // 性能测试
	    pkey_print_message("verify", "rsa", 0,
			       test_rsa_curves_bits[testnum],
			       cmd_option.duration);
	    Time_F(START);
	    count = run_benchmark(rsa_verify_loop, loopargs->rsa_data[testnum]);
	    d = Time_F(STOP);
	    fprintf(stderr,
		    mr ? "+R8:%ld:%d:%.2f\n"
		       : "%ld %d bit SM2 verify in %.2fs\n",
		    count, test_rsa_curves_bits[testnum],
		    d); // R8 验签结果， +R8 : 运算次数 ： 位数： 耗时秒
	    rsasign_results[testnum][1] = d / (double)count; // 每次验签运算耗时
	}
    }
#endif
}

/**
 *
 *@ Description: 输出rsa算法的执行结果
 *
 * 示例：
 *
 *  Doing 256 bit sign rsa's for 2s: 31593 256 bit SM2 signs in 1.97s
Doing 256 bit verify rsa's for 2s: 5882 256 bit SM2 verify in 2.00s
			      sign    verify    sign/s verify/s
 256 bit rsa (rsap256v1)   0.0001s   0.0003s  16037.1   2941.0
 *
 * +F6:0:256:0.000063:0.000345 // +F6表示类型， 0：位数索引，位数，签名耗时，
验签耗时
 *@ return void
 */
void show_results_for_rsa(void)
{
#ifndef OPENSSL_NO_SM2
    int testnum = 1;
    int k;

    for (k = 0; k < SM2_NUM; k++) {
	if (!rsasign_doit[k])
	    continue;
	if (testnum && !mr) {
	    printf("%30ssign    verify    sign/s verify/s\n", " ");
	    testnum = 0;
	}

	if (mr)
	    printf("+F6:%u:%u:%f:%f\n", k, test_rsa_curves_bits[k],
		   rsasign_results[k][0], rsasign_results[k][1]);
	else
	    printf("%4u bit rsa (%s) %8.4fs %8.4fs %8.1f %8.1f\n",
		   test_rsa_curves_bits[k], test_rsa_curves_names[k],
		   rsasign_results[k][0], rsasign_results[k][1],
		   1.0 / rsasign_results[k][0], 1.0 / rsasign_results[k][1]);
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
int do_multi_buf_rsa(char *buf, int n)
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
	    rsasign_results[k][0] = 1 / (1 / rsasign_results[k][0] + 1 / d);
	else
	    rsasign_results[k][0] = d;

	d = atof(sstrsep(&p, sep));
	if (n)
	    rsasign_results[k][1] = 1 / (1 / rsasign_results[k][1] + 1 / d);
	else
	    rsasign_results[k][1] = d;
	ret = 0;
    } else if (strncmp(buf, "+F7:", 4) == 0) {
	p = buf + 4;
	k = atoi(sstrsep(&p, sep));
	sstrsep(&p, sep);

	d = atof(sstrsep(&p, sep));
	if (n)
	    rsaenc_results[k][0] = 1 / (1 / rsaenc_results[k][0] + 1 / d);
	else
	    rsaenc_results[k][0] = d;

	d = atof(sstrsep(&p, sep));
	if (n)
	    rsaenc_results[k][1] = 1 / (1 / rsaenc_results[k][1] + 1 / d);
	else
	    rsaenc_results[k][1] = d;

	ret = 0;
    }
#endif

    return ret;
}

/*

*/

