#include <sys/time.h>

#include "cipher.h"
#include "perf.h"
//key的长度
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



int build_cipher_cmd (pce_op_data_t *opdata, enum pce_alg cipher_alg,uint8_t *in, 
						int inlen, uint8_t *out,int outlen ,uint8_t *key_iv);


//分配链式存储的 空间，头结点不存数据,此处需要详细检查代码
pce_link_list_item_t* malloc_linklist(pce_link_list_item_t *head,int seg_num)
{
	pce_link_list_item_t *temp = NULL;//头节点不存数据
	if(head == NULL){
		head = malloc(sizeof(pce_link_list_item_t));
		head->addr =(uint64_t) NULL;
		head->len = 0;
		head->next_link_list_item = (uint64_t) NULL;
		head->link_list_end_flag = 0;
	}
	temp = head;
	while(seg_num--){
		pce_link_list_item_t *node = malloc(sizeof(pce_link_list_item_t));
		node->addr =(uint64_t) NULL;
		node->len = 0;
		node->next_link_list_item = (uint64_t) NULL;
		node->link_list_end_flag = 0;
		//temp为上一个结点
		temp->next_link_list_item =(uint64_t) node;

		//temp更新为新结点
		temp = (pce_link_list_item_t *)temp->next_link_list_item;
		
	}
	return head;
}

//删除链式存储的空间
int free_linklist(pce_link_list_item_t *head,int seg_num)
{
	pce_link_list_item_t *node = head;
	pce_link_list_item_t *temp = NULL;
	while(node->next_link_list_item != (uint64_t)NULL){
		temp = (pce_link_list_item_t *) node->next_link_list_item; //保存下一个结点的指针
		//if(node.addr != NULL){
			//free(node.addr); //释放存放数据的段,如果存放数据的段是由malloc生成的话需要此代码，在本程序中不需要
		//}
		free(node); //释放当前结点
		node = temp; //往后移动一个结点
	}	
	return 0;
}

int create_linklist(uint8_t *src, int srclen,pce_link_list_item_t *head,uint16_t max_segs)
{
	int i = 0;
	int divide = srclen;
	pce_link_list_item_t *temp = (pce_link_list_item_t *) head->next_link_list_item; //头节点不存数据

	//长度为16则不S分片
	if(max_segs > srclen){
		fprintf(stderr,"num of linklist is greater than testlength, use testlength %d as max_segs!!\n",srclen);
	}

	//为使得每一分片大小不会差太多，计算每一分片的长度为比srclen大的最小能整除max_segs的值
	while(divide % max_segs != 0){
		divide ++ ;
	}
	int seglen = divide / max_segs; //分片长度整数部分
	if(seglen*(max_segs-1) >= srclen){ //如果超了则减少
		seglen--;
	}
	int lastseglen = srclen - (seglen * (max_segs-1)); //最后一片的长度,不能取余，长度为16分片为5时会出现问题
	//如果src长度为16，分为3片，每一片应当为6 6 4
	//比16大的最小能被3整除的数是18，divide被加到18，18/3=6 ，即可得到前两片长度6
	//16 % 6 = 4 ，16 = 6*2 + 4，取余即可得到最后一片长度4
	//如果分为4片，16 /4 = 4 ，divide = 16 不需要自增，
	//seglen = divide / max_segs = 16 /4 = 4
	//但是lastseglen = 16 %4 = 0 ,最后一片长度应当与前面一致，所有当lastseglen = 0时需要被赋值为seglen
	
	if(lastseglen == 0){  //如果能够被整除，也就是每一片的长度可以完全一样
		fprintf(stderr,"createlinklist\n");
		lastseglen = seglen; 
	}

	for(i = 0; i < max_segs; i++){ //创建max_segs的链式
		if(i != (max_segs -1) ){
			temp->addr =(uint64_t)(src + (seglen * i)); //获得数据的地址，src为地址，seglen为当前数据
			temp->len = seglen;
			temp->link_list_end_flag = 0;
			temp =(pce_link_list_item_t *) temp->next_link_list_item; //temp 移动到下一片
		}else{ //此时移到最后一片
			temp->addr =(uint64_t) (src + seglen * i);
			temp->len = lastseglen;
			temp->link_list_end_flag = 1; //表示此时已到最后一片
		}
	}		
	return 0;

}

int test_cipher_enc_loop(void *args)
{
	loopargs_t *loopargs = args;
	
    if (NULL == args) {
        return 0;
    }

	uint8_t *src = loopargs->src;
	uint8_t *dst = loopargs->dst; //此处应该根据链式进行赋值

	pce_queue_handle queue_handle = loopargs->queue_handle;//获取队列描述符
	int i = 0;
	pce_op_data_t *cipher_datas = NULL;
	int enqueued_count = 0;
	int cipher_length = loopargs->test_length;
	int batch = loopargs->batch;
	//int batch = g_batch;

	callback_context_t *callback_context = loopargs->callbacks;
	//完成信号量进行同步用，防止出队和出队对于的opdata不一致的情况
	cipher_datas = loopargs->requests;
		
	for(i = 0; i < batch; i++){
		build_cipher_cmd (&cipher_datas[i],loopargs->cipher_algo,src, 
								cipher_length, dst,cipher_length,loopargs->cipher_key);
			
		cipher_datas[i].cipher.mode =  PCE_CIPHER_MODE_ENCRYPT; //操作模式设置为解密
		callback_context[i].callbackfunc = symcallback;//自定义回调函数
		callback_context[i].op_tag = &cipher_datas[i];
		//callback_context[i].complete = &loopargs->completions[i]; //设置为传入的信号量地址
		callback_context[i].algo_index = loopargs->algo_index;
		callback_context[i].test_num = loopargs->testnum;
		callback_context[i].process_count = loopargs->processed_count;
		
		cipher_datas[i].cipher.tag = (uint64_t) (callback_context);
	
	}
	
	//入队
	enqueued_count = pce_enqueue(queue_handle, &cipher_datas, batch);//批量入队
	if (0 == enqueued_count) {
		goto out;
	}

	out:
			
    return 1;
}
int test_cipher_dec_loop(void *args)
{
	loopargs_t *loopargs = args;
	
    if (NULL == args) {
        return 0;
    }

	uint8_t *src = loopargs->src;
	uint8_t *dst = loopargs->dst;//此处应该根据链式进行赋值

	pce_queue_handle queue_handle = loopargs->queue_handle;//获取队列描述符
	int i = 0;
	int j;
	pce_op_data_t *cipher_datas = NULL;
	pce_op_data_t *remain;
	int enqueued_count = 0;
	int cipher_length = loopargs->test_length;
	callback_context_t *callback_context = loopargs->callbacks;
	int batch = loopargs->batch;

	cipher_datas = loopargs->requests;
	
	for(i = 0; i < batch; i++){
	
		//生成模板，之后会对具体值再进行修改
		build_cipher_cmd (&cipher_datas[i],loopargs->cipher_algo,src, 
							cipher_length, dst,cipher_length,loopargs->cipher_key);
		
		cipher_datas[i].cipher.mode =  PCE_CIPHER_MODE_DECRYPT; //操作模式设置为解密
 		callback_context[i].callbackfunc = symcallback;//自定义回调函数
		callback_context[i].op_tag = &cipher_datas[i];
		callback_context[i].algo_index = loopargs->algo_index;
		callback_context[i].test_num = loopargs->testnum;
		callback_context[i].process_count = loopargs->processed_count;
	
		cipher_datas[i].cipher.tag = (uint64_t) (&callback_context[i]);
	}

	//入队
	enqueued_count = pce_enqueue(queue_handle, &cipher_datas, batch);//批量入队
    if (0 == enqueued_count) {
         goto out;
    }
	
	if(enqueued_count < batch){ //未全部入队
		while(enqueued_count < batch){
			remain = &cipher_datas[enqueued_count];
			if(pce_enqueue(queue_handle, &remain,1) == 0){ //每次入队一个，直到入完
				for(j = 0;j < 100;j ++); //如果此时仍然入队失败，则跑一些空指令，等待一段时间（ns级别）后再次尝试
				//可以通过修改100的值来更新此时间
			}else{
				enqueued_count ++; //入队一个成功，自增1
			} 
		}

	}


	out:
				
    return 1;
   
}

//cipher section
int build_cipher_cmd (pce_op_data_t *opdata, enum pce_alg cipher_alg,uint8_t *in, 
						int inlen, uint8_t *out,int outlen ,uint8_t *key_iv)
{

	pce_op_data_t *temp_op = NULL;
	temp_op = opdata;
	//temp_op->op_type = PCE_OP_TYPE_SYM;
	temp_op->session_handle = NULL;
	temp_op->packet_type = PCE_FULL_PACKET;
	
	//temp_op->op_type = PCE_OP_TYPE_HASH;
	temp_op->cipher.alg =(uint16_t)cipher_alg;

	//根据不同模式进行不同操作
	temp_op->cipher.mode = PCE_CIPHER_MODE_ENCRYPT; //默认值，需要修改
	temp_op->cipher.key_iv = (uint64_t)key_iv; 
	//temp_op->hash.key_bytes = NULL;
		
	temp_op->cipher.in = (uint64_t)in;
	temp_op->cipher.in_bytes = inlen;
	temp_op->cipher.out = (uint64_t)out;
	temp_op->cipher.out_bytes = outlen;
	   
	temp_op->cipher.dma_mode = 0;
	//temp_op->cipher.type = PCE_OP_TYPE_SYM;
	
	return 0;

}


//目前暂时不能处理xts的密钥长度
int setkey(uint8_t *key_iv, const uint8_t *key ,int keylen,uint8_t *iv ,int ivlen)
{
	uint8_t *temp = malloc(AES_KEYSIZE_256 * 2 + 16 );//此处是最长的算法加密钥 即aes256xts的密钥和iv
	memset(temp,0 ,AES_KEYSIZE_256 * 2 + 16 );

	//暂未支持xts
	memcpy(temp + 32 - keylen , key, keylen); //按照文档79页进行填充密钥
	
	memcpy(temp + 32 ,iv, ivlen);
	key_iv = temp; //分配空间存放可以和iv
	fprintf(stderr, "set key is using virtual address!\n");
	return 0;
}

int freekey(uint8_t *key_iv){
	if(key_iv != NULL){
		free(key_iv);
	}
	return 0;
}


void test_cipher_perf(loopargs_t *loopargs)
{
    long count = 0;
    double d;
    int testnum = 0;
    char *op_mode = cmd_option.op ? "decrypt" : "encrypt";
	int segnum = cmd_option.linklist;
	pce_link_list_item_t *src_head = NULL;
	pce_link_list_item_t *dst_head = NULL;
	test_fn test_cipher_fn = NULL;

	//分配链式空间
	if(segnum > 1 ){
		src_head = malloc_linklist(src_head,segnum);
		dst_head = malloc_linklist(dst_head,segnum);
	}
	
	thread_local_variables_t *tlv = (thread_local_variables_t*)pthread_getspecific(thread_key); //找到tlv的首地址W
	algo_data_t *algo_data = (algo_data_t*)getHashMap(g_algo_hash_table, tlv->algo_name);

	//获得算法参数
	int algo_index = algo_data->algo_index;
	char *algo_name = algo_data->algo;
	uint16_t pce_algo = algo_data->pce_algo;

	thread_run_algo[tlv->thread_id] = algo_index ;
	
	int keysize = GET_KEYLEN_FORM_STRUCT(algo_data->algo_longness);
	int ivsize = GET_IVLEN_FROM_STRUCT(algo_data->algo_longness);

	//如果不是对称加密
	if(algo_data ->algo_type != ALGO_TYPE_SYM_CIPHER){
		fprintf(stderr,"Not symmetric cipher:%s in line:%d in file %s !\n",algo_name, __LINE__,__FILE__);
		//return -1;
	}
	loopargs->batch = cmd_option.batch;
	loopargs->cipher_key = NULL;
	loopargs->cipher_algo = pce_algo;
	loopargs->algo_index = algo_index;
	//判断是加密还是解密
	if(cmd_option.op == 0){
		test_cipher_fn = test_cipher_enc_loop;
	}else if(cmd_option.op == 1 ){
		test_cipher_fn = test_cipher_dec_loop;
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
	    count = run_benchmark(test_cipher_fn, loopargs);
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
	       	count = run_benchmark(test_cipher_enc_loop, loopargs);
			gettimeofday(&tv1,NULL);
			d = (tv1.tv_usec-tv.tv_usec)/(100000.0)+((tv1.tv_sec-tv.tv_sec));
			count = loopargs->processed_count[algo_index];
	       	print_result(algo_index, testnum, count, d,tlv->thread_id);
	     }
		freekey(loopargs->cipher_key);
	}
	else if(cmd_option.op == 1 ){ //解密
		setkey(loopargs->cipher_key, key32, keysize, iv, ivsize);		
       	for (testnum = 0; testnum < SIZE_NUM; testnum++) { 	
           	loopargs->test_length = lengths[testnum];
			loopargs->processed_count[algo_index] = 0;
			if(segnum > 1)
				create_linklist(loopargs->src_buf, loopargs->test_length, src_head, segnum);
				loopargs->src = (uint8_t*)src_head; //buf改为链表地址
				create_linklist(loopargs->dst_buf, loopargs->test_length, dst_head, segnum);
				loopargs->dst = (uint8_t*)dst_head; //buf改为链表地址
			}
			print_message(algo_name, 0, lengths[testnum], cmd_option.duration);
       		sem_post(&start_sem);
			gettimeofday(&tv,NULL);	
            count = run_benchmark(test_cipher_dec_loop, loopargs);
            gettimeofday(&tv1,NULL);
			d = (tv1.tv_usec-tv.tv_usec)/(100000.0)+((tv1.tv_sec-tv.tv_sec));
			count = loopargs->processed_count[algo_index];
            print_result(algo_index, testnum, count, d,tlv->thread_id);
        }
		freekey(loopargs->cipher_key);
	
*/
	//释放链式空间
	if(segnum > 1 ){
		free_linklist(src_head,segnum);
		free_linklist(dst_head,segnum);
	}

}


int test_cipher_hit(const char *algo_name)
{
	//返回0表示成功，返回-1表示失败
	if(getHashMap(g_algo_hash_table,algo_name) == NULL){
		return -1;
	}

	//访问线程私有数据，每个线程的tlv不同，但是操作完全相同
	thread_local_variables_t *tlv = (thread_local_variables_t*)pthread_getspecific(thread_key); //找到tlv的首地
	
	algo_data_t *algo_data = (algo_data_t*)getHashMap(g_algo_hash_table, algo_name);

	//do_sym_or_hash[algo_data->algo_index] = 1;
	
    return 0;
}


