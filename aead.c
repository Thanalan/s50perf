#include "aead.h"

static const unsigned char key16[16] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
					0xde, 0xf0, 0x34, 0x56, 0x78, 0x9a,
					0xbc, 0xde, 0xf0, 0x12};
static const unsigned char key24[24] = {
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x34, 0x56, 0x78, 0x9a,
    0xbc, 0xde, 0xf0, 0x12, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34};
static const unsigned char key32[32] = {
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x34, 0x56, 0x78,
    0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    0x12, 0x34, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56};
static unsigned char iv[16] = {0};

static int build_aead_cmd (pce_op_data_t *opdata, enum pce_alg cipher_alg,uint8_t *in, 
						int inlen, uint8_t *out,int outlen ,uint8_t *key_iv);


int test_aead_enc_loop(void *args)
{
	loopargs_t *loopargs = args;
	
    if (NULL == args) {
        return 0;
    }

	uint8_t *src = loopargs->src;
	uint8_t *dst = loopargs->dst; //此处应该根据链式进行赋值

	pce_queue_handle queue_handle = loopargs->queue_handle;//获取队列描述符
	int i = 0;

	pce_op_data_t *aead_datas = NULL;
	int enqueued_count = 0;
	int aead_length = loopargs->test_length;
	//完成信号量进行同步用，防止出队和出队对于的opdata不一致的情况
	int batch = loopargs->batch;

	callback_context_t *callback_context = loopargs->callbacks;
	//完成信号量进行同步用，防止出队和出队对于的opdata不一致的情况
	aead_datas = loopargs->requests;
		
	for(i = 0; i < batch; i++){
		build_aead_cmd (&aead_datas[i],loopargs->cipher_algo,src, 
								aead_length, dst,aead_length,loopargs->cipher_key);
						
		callback_context->callbackfunc = symcallback;//自定义回调函数
		callback_context->op_tag = &aead_datas[i];
		callback_context[i].algo_index = loopargs->algo_index;
		callback_context[i].test_num = loopargs->testnum;
		callback_context[i].process_count = loopargs->processed_count;
		
		aead_datas[i].aead.tag = (uint64_t) (callback_context);	
	}
	
	//入队
	enqueued_count = pce_enqueue(queue_handle, &aead_datas, batch);//批量入队
	if (0 == enqueued_count) {
		goto out;
	}
	out:
			
    return 1;
	
}
int test_aead_dec_loop(void *args)
{	
	loopargs_t *loopargs = args;
	
    if (NULL == args) {
        return 0;
    }

	uint8_t *src = loopargs->src;
	uint8_t *dst = loopargs->dst;//此处应该根据链式进行赋值

	pce_queue_handle queue_handle = loopargs->queue_handle;//获取队列描述符
	int i = 0;
	pce_op_data_t *aead_datas = NULL;
	int enqueued_count = 0;
	int aead_length = loopargs->test_length;
	//完成信号量进行同步用，防止出队和出队对于的opdata不一致的情况
	int batch = loopargs->batch;

	callback_context_t *callback_context = loopargs->callbacks;
	//完成信号量进行同步用，防止出队和出队对于的opdata不一致的情况
	aead_datas = loopargs->requests;
		
	for(i = 0; i < batch; i++){
		
			//生成模板，之后会对具体值再进行修改
		//aead使用cipher的模板
		build_aead_cmd (&aead_datas[i],loopargs->cipher_algo,src, 
								aead_length, dst,aead_length,loopargs->cipher_key);
			
		callback_context[i].callbackfunc = symcallback;//自定义回调函数
		callback_context[i].op_tag = &aead_datas[i];
		callback_context[i].algo_index = loopargs->algo_index;
		callback_context[i].test_num = loopargs->testnum;
		callback_context[i].process_count = loopargs->processed_count;
		
		aead_datas[i].aead.tag = (uint64_t) (callback_context);
	
	}
	
	//入队
	enqueued_count = pce_enqueue(queue_handle, &aead_datas, batch);//批量入队
	if (0 == enqueued_count) {
		goto out;
	}
	
	out:
			
    return 1;
   
}

static int build_aead_cmd (pce_op_data_t *opdata, enum pce_alg cipher_alg,uint8_t *in, 
						int inlen, uint8_t *out,int outlen ,uint8_t *key_iv)
{	
	memset(opdata, 0, sizeof(pce_op_data_t));
	
	pce_op_data_t *temp_op = NULL;
	temp_op = opdata;
	//temp_op->op_type = PCE_OP_TYPE_AEAD;
	temp_op->session_handle = NULL;
	temp_op->packet_type = PCE_FULL_PACKET;
	
	//temp_op->op_type = PCE_OP_TYPE_HASH;
	temp_op->aead.alg =(uint16_t)cipher_alg;

	//aad固定8字节长度，tagsize与其一致，也就是in的最后8字节作为add,前面的作为ptext
	//由于inlen等于outlen,所以这样处理
	//temp_op->aead.tag_size = outlen - inlen; //!!!此处赋值不确定是否正确
	//temp_op->aead.aad_size = 0; ////!!!此处赋值不确定是否正确
	temp_op->aead.tag_size = 8; //!!!此处赋值不确定是否正确
	temp_op->aead.aad_size = 8; ////!!!此处赋值不确定是否正确

	//根据不同模式进行不同操作
	temp_op->aead.mode = PCE_AEAD_MODE_ENCRYPT; //默认值，需要修改
	temp_op->aead.key_iv = (uint64_t)key_iv; 
	//temp_op->hash.key_bytes = NULL;
		
	temp_op->aead.in = (uint64_t)in;
	temp_op->aead.in_bytes = inlen;
	temp_op->aead.out = (uint64_t)out;
	temp_op->aead.out_bytes = outlen;
	   
	temp_op->aead.dma_mode = 0;
	//temp_op->aead.type = PCE_OP_TYPE_AEAD;
	
	return 0;
}



void test_aead_perf(loopargs_t *loopargs)
{
    int ret;
    int st;
    long count = 0;
    double d;
    int testnum = 0;
    char algo_desc[64] = {0};
    char *op_mode = cmd_option.op ? "decrypt" : "encrypt";
    char *algo_mode = cmd_option.mode;
	int segnum = cmd_option.linklist;
	pce_link_list_item_t *src_head = NULL;
	pce_link_list_item_t *dst_head = NULL;
	test_fn test_aead_fn = NULL;

	//分配链式空间
	if(segnum > 1 ){
		src_head = malloc_linklist(src_head,segnum);
		dst_head = malloc_linklist(dst_head,segnum);
	}
	
	thread_local_variables_t *tlv = (thread_local_variables_t*)pthread_getspecific(thread_key); //找到tlv的首地址
	algo_data_t *algo_data = (algo_data_t*)getHashMap(g_algo_hash_table, tlv->algo_name);

	//获得算法参数
	int algo_index = algo_data->algo_index;
	char *algo_name = algo_data->algo;
	uint16_t pce_algo = algo_data->pce_algo;
	//修改全局数据记得加锁
	thread_run_algo[tlv->thread_id] = algo_index ;
	int keysize = GET_KEYLEN_FORM_STRUCT(algo_data->algo_longness);
	int ivsize = GET_IVLEN_FROM_STRUCT(algo_data->algo_longness);

	//如果不是对称加密
	if(algo_data ->algo_type != ALGO_TYPE_AEAD){
		fprintf(stderr,"Not aead:%s in line:%d in file %s !\n",algo_name, __LINE__,__FILE__);
		//return -1;
	}
	loopargs->batch = cmd_option.batch;
	loopargs->cipher_key = NULL;
	loopargs->cipher_algo = pce_algo;
	loopargs->algo_index = algo_index;
	if(cmd_option.op == 0){
		test_aead_fn = test_aead_enc_loop;
	}else if(cmd_option.op == 1 ){
		test_aead_fn = test_aead_dec_loop;
	}
	setkey(loopargs->cipher_key, key32, keysize, iv, ivsize);		
	for (testnum = 0; testnum < SIZE_NUM; testnum++) {
	    loopargs->test_length = lengths[testnum];
		loopargs->testnum = testnum;
		loopargs->processed_count[algo_index] = 0;
		//如果为链式则创建
		if(segnum > 1){ //此处值有问题
			create_linklist(loopargs->src_buf, loopargs->test_length, src_head, segnum);
			loopargs->src = (uint8_t*)src_head; //buf改为链表地址
			create_linklist(loopargs->dst_buf, loopargs->test_length, dst_head, segnum);
			loopargs->dst = (uint8_t*)dst_head; //buf改为链表地址
		}
			
		print_message(algo_name, 0, lengths[testnum], cmd_option.duration);
		sem_post(&start_sem);
		gettimeofday(&tv,NULL);	
	    count = run_benchmark(test_aead_fn, loopargs);
		gettimeofday(&tv1,NULL);
		d = (tv1.tv_usec-tv.tv_usec)/(100000.0)+((tv1.tv_sec-tv.tv_sec));
		count = loopargs->processed_count[algo_index];
	    print_result(algo_index, testnum, count, d,tlv->thread_id);
	}
	freekey(loopargs->cipher_key);
	/*
	if(cmd_option.op == 0){ //判断是加密还是解密
		//key取最长的，也就是key32，如果keysize小于32只会取前几位
		setkey(loopargs->cipher_key, key32, keysize, iv, ivsize);		
	    for (testnum = 0; testnum < SIZE_NUM; testnum++) {
	       	loopargs->test_length = lengths[testnum];

			loopargs->testnum = testnum;
			loopargs->processed_count[algo_index] = 0;
			//如果为链式则创建
			if(segnum > 1){ //此处值有问题
				create_linklist(loopargs->src_buf, loopargs->test_length, src_head, segnum);
				loopargs->src = (uint8_t*)src_head; //buf改为链表地址
				create_linklist(loopargs->dst_buf, loopargs->test_length, dst_head, segnum);
				loopargs->dst = (uint8_t*)dst_head; //buf改为链表地址
			}			
			print_message(algo_name, 0, lengths[testnum], cmd_option.duration);
	       	sem_post(&start_sem);
			gettimeofday(&tv,NULL);	
	       	count = run_benchmark(test_aead_enc_loop, loopargs);
	        gettimeofday(&tv1,NULL);
			d = (tv1.tv_usec-tv.tv_usec)/(100000.0)+((tv1.tv_sec-tv.tv_sec));
			count = loopargs->processed_count[algo_index];
	       	print_result(algo_index, testnum, count, d,tlv->thread_id);
	     }
		freekey(loopargs->cipher_key);
	}
	else if(cmd_option.op == 1 ){ //解密	
		setkey(loopargs->cipher_key, key32, keysize,iv, ivsize);		
       	for (testnum = 0; testnum < SIZE_NUM; testnum++) {
           	loopargs->test_length = lengths[testnum];
			loopargs->processed_count[algo_index] = 0;
			loopargs->testnum = testnum;
			//如果为链式则创建
			if(segnum > 1){ //此处值有问题
				create_linklist(loopargs->src_buf, loopargs->test_length, src_head, segnum);
				loopargs->src = (uint8_t*)src_head; //buf改为链表地址
				create_linklist(loopargs->dst_buf, loopargs->test_length, dst_head, segnum);
				loopargs->dst = (uint8_t*)dst_head; //buf改为链表地址
			}
			print_message(algo_desc, 0, lengths[testnum], cmd_option.duration);
           	sem_post(&start_sem);
			gettimeofday(&tv,NULL);	
            count = run_benchmark(test_aead_dec_loop, loopargs);
            gettimeofday(&tv1,NULL);
			d = (tv1.tv_usec-tv.tv_usec)/(100000.0)+((tv1.tv_sec-tv.tv_sec));
			count = loopargs->processed_count[algo_index];
            print_result(algo_index, testnum, count, d,tlv->thread_id);
        }
		freekey(loopargs->cipher_key);
	}
*/
	//释放链式空间
	if(segnum > 1 ){
		free_linklist(src_head,segnum);
		free_linklist(dst_head,segnum);
	}

}

int test_aead_hit(const char *algo_name)
{
	//返回0表示成功，返回-1表示失败
	if(getHashMap(g_algo_hash_table,algo_name) == NULL){
		return -1;
	}

	//访问线程私有数据，每个线程的tlv不同，但是操作完全相同
	thread_local_variables_t *tlv = (thread_local_variables_t*)pthread_getspecific(thread_key); //找到tlv的首地
	
	algo_data_t *algo_data = (algo_data_t*)getHashMap(g_algo_hash_table, algo_name);

	do_sym_or_hash[algo_data->algo_index] = 1;
	
    return 0;
}


