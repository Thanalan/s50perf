#include <sys/time.h>
#include <semaphore.h>  

#include "digest.h"

static inline int build_hash_cmd (pce_op_data_t *opdata, enum pce_alg hash_alg,uint8_t *in, 
						int inlen, uint8_t *out,int outlen )
{
	pce_op_data_t *temp_op = NULL;
   	temp_op = opdata;
    temp_op->session_handle = NULL;
    temp_op->packet_type = PCE_FULL_PACKET;
    temp_op->hash.alg = hash_alg;
	
    temp_op->hash.mode = PCE_DIGEST_MODE_NORMAL;
    temp_op->hash.key_iv = (uint64_t) NULL;
	temp_op->hash.key_bytes =(uint64_t)  NULL;
	
    temp_op->hash.in =(uint64_t)  in;
	temp_op->hash.in_bytes = inlen;
    temp_op->hash.out = (uint64_t) out;
    temp_op->hash.digest_len = outlen;
    temp_op->hash.dma_mode = 0;

	return 0;
}

int test_hmac_loop(void *args)
{
    loopargs_t *loopargs = args;
   // struct pacc_hmac_sha3_context ce_context;
    static uint8_t digest[64] = {0};

    if (NULL == args) {
        return 0;
    }
	uint8_t *src = loopargs->src;
	pce_queue_handle queue_handle = loopargs->queue_handle;
	callback_context_t *callback_context = loopargs->callbacks;
	int i;
	pce_op_data_t *hash_datas = NULL;
	int enqueued_count = 0;
	int batch = loopargs->batch;

    hash_datas = loopargs->requests;
	
	for(i = 0; i < batch; i++){
		//COMPLETION_INIT(&loopargs->completions[i]);
	
		//生成模板，之后会对具体值再进行修改
		build_hash_cmd(&hash_datas[i], loopargs->hash_algo , src, loopargs->test_length, digest, 64);
		
		hash_datas[i].hash.mode = PCE_DIGEST_MODE_HMAC;
		hash_datas[i].hash.key_iv = NULL;
		hash_datas[i].hash.key_bytes = 0;
		callback_context->callbackfunc = symcallback;//自定义回调函数
		callback_context->op_tag = hash_datas;
		callback_context[i].algo_index = loopargs->algo_index;
		callback_context[i].test_num = loopargs->testnum;
		callback_context[i].process_count = loopargs->processed_count;
		
		hash_datas[i].hash.tag = (uint64_t) (callback_context);

	}

	//入队
	enqueued_count = pce_enqueue(queue_handle, &hash_datas, batch);//批量入队
    if (0 == enqueued_count) {
         goto out;
    }
    out:		
    return 1;

}



int test_hash_loop(void *args)
{
    loopargs_t *loopargs = args;
	
    if (NULL == args) {
        return 0;
    }

	uint8_t *src = loopargs->src;
	uint8_t *dst = loopargs->dst; //此处应该根据链式进行赋值

	pce_queue_handle queue_handle = loopargs->queue_handle;//获取队列描述符
	int i = 0;
	pce_op_data_t *hash_datas = NULL;
	int enqueued_count = 0;
	int hash_length = loopargs->test_length;
	int batch = loopargs->batch;

	callback_context_t *callback_context = loopargs->callbacks;
	hash_datas = loopargs->requests;
		
	for(i = 0; i < batch; i++){
		
			//生成模板，之后会对具体值再进行修改
		build_hash_cmd(&hash_datas[i], loopargs->hash_algo , src, loopargs->test_length, dst, 64 );
			
		callback_context[i].callbackfunc = symcallback;//自定义回调函数
		callback_context[i].op_tag = &hash_datas[i];
		callback_context[i].algo_index = loopargs->algo_index;
		callback_context[i].process_count = loopargs->processed_count;
		
		hash_datas[i].hash.tag = (uint64_t) (callback_context);
	
	}
	
	//入队
	enqueued_count = pce_enqueue(queue_handle, &hash_datas, batch);//批量入队
	if (0 == enqueued_count) {
		goto out;
	}
	out:
			
    return 1;
}

struct	timeval    tv;
struct  timeval	tv1;

sem_t start_sem;  

void test_hash_perf(loopargs_t *loopargs)
{
    long count = 0;
    double d;
    int testnum = 0;
	int segnum = cmd_option.linklist;
	pce_link_list_item_t *src_head = NULL;
	pce_link_list_item_t *dst_head = NULL;
	test_fn test_hash_fn = NULL;

	//分配链式空间
	if(segnum > 1 ){
		src_head = malloc_linklist(src_head,segnum);
		dst_head = malloc_linklist(dst_head,segnum);
	}
	
	thread_local_variables_t *tlv = (thread_local_variables_t*)pthread_getspecific(thread_key); //找到tlv的首地址
	algo_data_t *algo_data = (algo_data_t*)getHashMap(g_algo_hash_table, tlv->algo_name);
	
	int algo_index = algo_data->algo_index;
	loopargs->algo_index = algo_index;

	//修改全局数据记得加锁
	thread_run_algo[tlv->thread_id] = algo_index;//更新当前线程执行的算法名称

	char *algo_name = algo_data->algo;
	uint16_t pce_algo = algo_data->pce_algo;
	loopargs->batch = cmd_option.batch;

	if(algo_data->algo_type == ALGO_TYPE_HASH){
		test_hash_fn = test_hash_loop;
	}else if(algo_data->algo_type == ALGO_TYPE_HMAC){
		test_hash_fn = test_hmac_loop;
	}else { //此时不是hash或者hmac
		fprintf(stderr,"Not hash or hmac:%s in line %d in file:\n%s\n",algo_name, __LINE__,__FILE__);
	}
	
	for (testnum = 0; testnum < SIZE_NUM; testnum++) {
        loopargs->test_length = lengths[testnum];
		loopargs->hash_algo = pce_algo;
		loopargs->testnum = testnum;
		loopargs->processed_count[algo_index] = 0;
		//如果为链式则创建
		if(segnum > 1){ //此处值有问题
			create_linklist(loopargs->src_buf, loopargs->test_length, src_head, segnum);
			loopargs->src = (uint8_t*)src_head; 
			create_linklist(loopargs->dst_buf, loopargs->test_length, dst_head, segnum);
			loopargs->dst = (uint8_t*)dst_head;
		}
		print_message(algo_name, 0, lengths[testnum], cmd_option.duration);

		sem_post(&start_sem);
		gettimeofday(&tv,NULL);			
        count = run_benchmark(test_hash_fn, loopargs);
		gettimeofday(&tv1,NULL);
		d = (tv1.tv_usec-tv.tv_usec)/(100000.0)+((tv1.tv_sec-tv.tv_sec));
		count = loopargs->processed_count[algo_index];
        print_result(algo_index, testnum, count,d ,tlv->thread_id);	
			
    }
	/*if(algo_data->algo_type == ALGO_TYPE_HASH){
		for (testnum = 0; testnum < SIZE_NUM; testnum++) {
            loopargs->test_length = lengths[testnum];
			loopargs->hash_algo = pce_algo;
			loopargs->testnum = testnum;
			loopargs->processed_count[algo_index] = 0;
			//如果为链式则创建
			if(segnum > 1){ //此处值有问题
				create_linklist(loopargs->src_buf, loopargs->test_length, src_head, segnum);
				loopargs->src = (uint8_t*)src_head; 
				create_linklist(loopargs->dst_buf, loopargs->test_length, dst_head, segnum);
				loopargs->dst = (uint8_t*)dst_head;
			}
			print_message(algo_name, 0, lengths[testnum], cmd_option.duration);
			//sem_post()，通知开始发送

			sem_post(&start_sem);
			gettimeofday(&tv,NULL);			
            count = run_benchmark(test_hash_loop, loopargs);
			gettimeofday(&tv1,NULL);
			d = (tv1.tv_usec-tv.tv_usec)/(100000.0)+((tv1.tv_sec-tv.tv_sec));
			count = loopargs->processed_count[algo_index];
            print_result(algo_index, testnum, count,d ,tlv->thread_id);	
			
        }

	}else if(algo_data->algo_type == ALGO_TYPE_HMAC){
	
		for (testnum = 0; testnum < SIZE_NUM; testnum++) {
			loopargs->test_length = lengths[testnum];
			loopargs->hash_algo = algo_index;
			loopargs->testnum = testnum;
			loopargs->processed_count[algo_index] = 0;
			//如果为链式则创建
			if(segnum > 1){ //此处值有问题
				create_linklist(loopargs->src_buf, loopargs->test_length, src_head, segnum);
				loopargs->src = (uint8_t*)src_head; //src改为链表地址
				create_linklist(loopargs->dst_buf, loopargs->test_length, dst_head, segnum);
				loopargs->dst = (uint8_t*)dst_head; //dst改为链表地址,强制类型转换，数值不变
			}
			print_message(algo_name, 0, lengths[testnum],cmd_option.duration);
			sem_post(&start_sem);
			gettimeofday(&tv,NULL);	
			Time_F(START);
			count = run_benchmark(test_hmac_loop, loopargs);
			d = Time_F(STOP);
			gettimeofday(&tv1,NULL);
			d = (tv1.tv_usec-tv.tv_usec)/(100000.0)+((tv1.tv_sec-tv.tv_sec));
			count = loopargs->processed_count[algo_index];
			print_result(algo_index, testnum, count, d,tlv->thread_id);
		}
	}else { //此时不是hash或者hmac

		fprintf(stderr,"Not hash or hmac:%s in line %d in file:\n%s\n",algo_name, __LINE__,__FILE__);

	}*/

	//释放链式空间
	if(segnum > 1 ){
		free_linklist(src_head,segnum);
		free_linklist(dst_head,segnum);
	}

	
}

//返回0表示成功
int test_hash_hit(const char *algo_name)
{
    int ret = -1;

	thread_local_variables_t *tlv = (thread_local_variables_t*)pthread_getspecific(thread_key); //找到tlv的首地址

	//根据hashtable。传入算法名称作为key，直接找到算法
	//获取Map集合中的指定元素

	if(getHashMap(g_algo_hash_table,algo_name) == NULL){
		return -1;
	}
	
	algo_data_t *algo_data = (algo_data_t*)getHashMap(g_algo_hash_table, algo_name);
	
	
    return 0;
}

