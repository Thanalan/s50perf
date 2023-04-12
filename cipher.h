#ifndef __CIPHER_H__
#define __CIPHER_H__

#include "perf.h"



//分配链式的空间
pce_link_list_item_t* malloc_linklist(pce_link_list_item_t *head,int seg_num);

//释放链式空间
int free_linklist(pce_link_list_item_t *head,int seg_num);

//配置链式的数据
int create_linklist(uint8_t *src, int srclen,pce_link_list_item_t *head,uint16_t max_segs);

//测试对称加密算法
int test_cipher_enc_loop(void *args);
int test_cipher_dec_loop(void *args);

#define BUILD_CIPHER_PERF(ALGO,MODE)											\
if (do_sym_or_hash[ALGO_##ALGO##_##MODE##_IDX]){								\
	setkey(looparg->cipher_key,key16,##ALGO##_KEYSIZE,NULL,AES_IV_LEN);		\
	looparg->cipher_algo = get_cipher_algo_from_string(algo_name,algo_mode);\
	for (testnum = 0; testnum < SIZE_NUM; testnum++) {						\
        print_message(algo_desc, 0, lengths[testnum], cmd_option.duration);	\
        looparg->test_length = lengths[testnum];								\
        if(segnum > 1){ 															\
			create_linklist(loopargs->buf_malloc, loopargs->test_length, head, segnum);\
			loopargs->buf = head; 														\
		}																				\
        Time_F(START);																	\
        count = run_benchmark(test_aes_enc_loop, loopargs);								\
        d = Time_F(STOP);																\
		print_result(ALGO_##ALGO##_##MODE##_IDX, testnum, count, d);					\
	}																					\
		freekey(loopargs->cipher_key);													\
}

#define IMPLEMENT_CIPHER_PERF(ALGO)\
	BUILD_CIPHER_PERF(ALGO,CBC)\
	BUILD_CIPHER_PERF(ALGO,CCM)\
	BUILD_CIPHER_PERF(ALGO,CFB)\
	BUILD_CIPHER_PERF(ALGO,CTR)\
	BUILD_CIPHER_PERF(ALGO,CTS)\
	BUILD_CIPHER_PERF(ALGO,GCM)\
	BUILD_CIPHER_PERF(ALGO,OCB)\
	BUILD_CIPHER_PERF(ALGO,OFB)\
	BUILD_CIPHER_PERF(ALGO,XTS)\
	BUILD_CIPHER_PERF(ALGO,ECB)

//输入算法和模式，生成函数，全部为大写
#define BUILD_CIPHER_HIT(ALGO,MODE) \
	else if (!strcmp(algo_name, algo_names[ALGO_##ALGO##_##MODE##_IDX]))) \
		tlv->do_sym_or_hash[ALGO_##ALGO##_##MODE##_IDX] = 1; \
		ret = 0; \
	}

#define IMPLEMENT_CIPHER_HIT(ALGO)\
	BUILD_CIPHER_HIT(ALGO,CBC)\
	BUILD_CIPHER_HIT(ALGO,CCM)\
	BUILD_CIPHER_HIT(ALGO,CFB)\
	BUILD_CIPHER_HIT(ALGO,CTR)\
	BUILD_CIPHER_HIT(ALGO,CTS)\
	BUILD_CIPHER_HIT(ALGO,GCM)\
	BUILD_CIPHER_HIT(ALGO,OCB)\
	BUILD_CIPHER_HIT(ALGO,OFB)\
	BUILD_CIPHER_HIT(ALGO,XTS)\
	BUILD_CIPHER_HIT(ALGO,ECB)

void test_cipher_perf(loopargs_t *loopargs);
int test_cipher_hit(const char *algo_name);

int setkey(uint8_t *key_iv,const uint8_t *key ,int keylen,uint8_t *iv ,int ivlen);
int freekey(uint8_t *key_iv);
//int build_cipher_cmd (pce_op_data_t *opdata, enum pce_alg cipher_alg,uint8_t *in, 
	//					int inlen, uint8_t *out,int outlen ,uint8_t *key_iv,struct COMPLETION_STRUCT *complete);


#endif
