#ifndef __CIPHER_H__
#define __CIPHER_H__

#include "perf.h"



//分配链式的空间
pce_link_list_item_t* malloc_linklist(pce_link_list_item_t *head,int seg_num);

//释放链式空间
int free_linklist(pce_link_list_item_t *head);

//配置链式的数据
pce_link_list_item_t * create_linklist(uint8_t *src, int srclen,pce_link_list_item_t *head, uint16_t max_segs);

//测试对称加密算法
int test_cipher_enc_loop(void *args);
int test_cipher_dec_loop(void *args);

void test_cipher_perf(loopargs_t *loopargs);
int test_cipher_hit(const char *algo_name);

void* setkey(uint8_t *key_iv,const uint8_t *key ,int keylen,uint8_t *iv ,int ivlen);
int freekey(uint8_t *key_iv);

#endif
