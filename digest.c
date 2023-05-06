#include <sys/time.h>
#include <semaphore.h>  

#include "digest.h"

static inline int build_hash_cmd (pce_op_data_t *opdata, enum pce_alg hash_alg,uint8_t *in, 
                        int inlen, uint8_t *out,int outlen, bool use_linklist )
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
    if(use_linklist == true ){
        temp_op->hash.dma_mode = 2;
    }else{
        temp_op->hash.dma_mode = 0;
    }
    return 0;
}

int test_hmac_loop(void *args)
{
    loopargs_t *loopargs = args;



    if (NULL == args) {
        return 0;
    }
    uint8_t *src = loopargs->src;
    uint8_t *dst = loopargs->dst;
    int i;
    pce_op_data_t *hash_datas = NULL;
    int enqueued_count = 0;
    int batch = loopargs->batch;
    perf_ring *ring = loopargs->ring;
    hash_datas = loopargs->requests;
    
    for(i = 0; i < batch; i++){
    
        //生成模板，之后会对具体值再进行修改
        build_hash_cmd(&hash_datas[i], loopargs->hash_algo , src, loopargs->test_length, dst, 64,loopargs->use_linklist);
        
        hash_datas[i].hash.mode = PCE_DIGEST_MODE_HMAC;
        hash_datas[i].hash.key_iv = (uint64_t)NULL;
        hash_datas[i].hash.key_bytes = 0;
        SET_CALLBACK_INIT();
        SET_CALLBACK_ALGOINDEX(loopargs->algo_index);
        SET_CALLBACK_THREAD_ID(loopargs->thread_id);
        SET_CALLBACK_TEST_NUM(loopargs->testnum);
        hash_datas[i].hash.tag = (uint64_t)(callback);

    }

    //入队
    enqueued_count = mp_enqueue(ring, &hash_datas, batch);//批量入队
    //printf("thread:%d enqueued count:%d\n",loopargs->thread_id,enqueued_count);
    if (0 == enqueued_count) {
         goto out;
    }
    out:        
    return 1;

}

//CMAC和CBCMAC的generate 值 PCE_CMAC_MODE_GENERATE值都是0，和PCE_DIGEST_MODE_NORMAL的值一样
//因此复用test_hash_loop的函数
//verify暂时不支持
/*
int test_cmac_loop(void *args)
{
    loopargs_t *loopargs = args;
   // struct pacc_hmac_sha3_context ce_context;
    static uint8_t digest[64] = {0};

    if (NULL == args) {
        return 0;
    }
    uint8_t *src = loopargs->src;
    int i;
    pce_op_data_t *hash_datas = NULL;
    int enqueued_count = 0;
    int batch = loopargs->batch;
    perf_ring *ring = loopargs->ring;
    hash_datas = loopargs->requests;
    
    for(i = 0; i < batch; i++){
    
        //生成模板，之后会对具体值再进行修改
        build_hash_cmd(&hash_datas[i], loopargs->hash_algo , src, loopargs->test_length, digest, 64);
        
        hash_datas[i].hash.mode = PCE_CMAC_MODE_GENERATE;
        hash_datas[i].hash.key_iv = (uint64_t)NULL;
        hash_datas[i].hash.key_bytes = 0;
        SET_CALLBACK_INIT();
        SET_CALLBACK_ALGOINDEX(loopargs->algo_index);
        SET_CALLBACK_TEST_NUM(loopargs->testnum);
        hash_datas[i].hash.tag = (uint64_t)(callback);

    }

    //入队
    enqueued_count = mp_enqueue(ring, &hash_datas, batch);//批量入队
    if (0 == enqueued_count) {
         goto out;
    }
    out:        
    return 1;

}

*/

int test_hash_loop(void *args)
{
    loopargs_t *loopargs = args;
    
    if (NULL == args) {
        return 0;
    }
    uint8_t *src = loopargs->src;
    uint8_t *dst = loopargs->dst; //此处应该根据链式进行赋值
    int i = 0;
    pce_op_data_t *hash_datas = NULL;
    int enqueued_count = 0;
    int batch = loopargs->batch;
    perf_ring *ring = loopargs->ring;
    hash_datas = loopargs->requests;
    //pce_queue_handle *queue = loopargs->queue_handle;
    for(i = 0; i < batch; i++){
        
            //生成模板，之后会对具体值再进行修改
        build_hash_cmd(&hash_datas[i], loopargs->hash_algo , src, loopargs->test_length, dst, 64, loopargs->use_linklist);
        SET_CALLBACK_INIT();
        SET_CALLBACK_ALGOINDEX(loopargs->algo_index);
        SET_CALLBACK_TEST_NUM(loopargs->testnum);
        SET_CALLBACK_THREAD_ID(loopargs->thread_id);
        hash_datas[i].hash.tag = (uint64_t)(callback);
    
    }
    //入队
    //enqueued_count = pce_enqueue(queue_handle, &hash_datas, batch);//批量入队
    enqueued_count = mp_enqueue(ring, &hash_datas, batch);//批量入队
    // printf("thread:%d enqueued count:%d\n",loopargs->thread_id,enqueued_count);
    //enqueued_count = pce_enqueue(queue,&hash_datas, 1);
    if (0 == enqueued_count) {
        goto out;
    }
    out:
            
    return 1;
}


void test_hash_perf(loopargs_t *loopargs)
{
    long count = 0;
    double d;
    int testnum = 0;
    int segnum = cmd_option.linklist;
    pce_link_list_item_t *src_head = NULL;
    pce_link_list_item_t *dst_head = NULL;
    test_fn test_hash_fn = NULL;
    uint16_t thread_id = loopargs->thread_id;
    int length = cmd_option.test_length;
    algo_data_t *algo_data = (algo_data_t*)get_hash_map(g_algo_hash_table, loopargs->algo_name);
    struct  timeval tv;
    struct  timeval tv1;
    uint16_t algo_index = algo_data->algo_index;
    loopargs->algo_index = algo_index;

    //修改全局数据记得加锁
    thread_run_algo[thread_id] = algo_index;//更新当前线程执行的算法名称
    if(segnum > 1){
        loopargs->use_linklist = true;
        src_head = malloc_linklist(src_head, segnum);
        dst_head = malloc_linklist(dst_head, segnum);   
    }
    char *algo_name = algo_data->algo;
    uint16_t pce_algo = algo_data->pce_algo;
    loopargs->batch = cmd_option.batch;

    sem_t *start_sem = GET_START_SEM();
    //sem_t *start_sem = &control[thread_id % poll_thread_num].start_sem;
    if(algo_data->algo_type == ALGO_TYPE_HASH){
        test_hash_fn = test_hash_loop;
    }else if(algo_data->algo_type == ALGO_TYPE_HMAC){
        test_hash_fn = test_hmac_loop;
    }else { //此时不是hash或者hmac
        fprintf(stderr,"Not hash or hmac:%s in line %d in file:\n%s\n",algo_name, __LINE__,__FILE__);
    }
    for (testnum = 0; testnum < SIZE_NUM; testnum++) {
        if(length > 0){
            loopargs->test_length = length;
            testnum = SIZE_NUM - 1;
        }else{

            loopargs->test_length = lengths[testnum];
        }
        loopargs->hash_algo = pce_algo;
        loopargs->testnum = testnum;
        //如果为链式则创建
        if(segnum > 1){ //此处值有问题
            loopargs->src = (uint8_t*)create_linklist(loopargs->src_buf, loopargs->test_length,src_head, segnum);
            loopargs->dst = (uint8_t*)create_linklist(loopargs->dst_buf, loopargs->test_length,dst_head, segnum);
        }
        print_message(algo_name, 0, loopargs->test_length, cmd_option.duration);
        //printf("g_poll_thread_num:%d\n",poll_thread_num);
        sem_post(start_sem);
        gettimeofday(&tv,NULL);         
        count = run_benchmark(test_hash_fn, loopargs);
        gettimeofday(&tv1,NULL);
        d = (tv1.tv_usec-tv.tv_usec)/(100000.0)+((tv1.tv_sec- tv.tv_sec));
        print_result(algo_index, testnum, count,d ,thread_id);  
      //  printf("time:%f\n",COMPUTE_TIME_INTERVAL(GET_TV(),GET_TV1()));
    }
    if(segnum > 1 ){
            pce_free_mem(loopargs->src);
            pce_free_mem(loopargs->dst);
        }
}

//返回0表示成功
int test_hash_hit(const char *algo_name)
{
    return 0;
}

