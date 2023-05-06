#include "aead.h"

static const unsigned char key32[32] = {
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x34, 0x56, 0x78,
    0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    0x12, 0x34, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56};

static unsigned char iv[16] = {0};

static int build_aead_cmd (pce_op_data_t *opdata, enum pce_alg cipher_alg,uint8_t *in, 
                        int inlen, uint8_t *out,int outlen ,uint8_t *key_iv, bool use_linklist);


int test_aead_enc_loop(void *args)
{
    loopargs_t *loopargs = args;
    
    if (NULL == args) {
        return 0;
    }

    uint8_t *src = loopargs->src;
    uint8_t *dst = loopargs->dst; 

    int i = 0;

    pce_op_data_t *aead_datas = NULL;
    int enqueued_count = 0;
    int aead_length = loopargs->test_length;
    int batch = loopargs->batch;
    aead_datas = loopargs->requests;
    perf_ring *ring = loopargs->ring;
    for(i = 0; i < batch; i++){
        build_aead_cmd (&aead_datas[i],loopargs->cipher_algo,src, 
                                aead_length, dst,aead_length,loopargs->cipher_key, loopargs->use_linklist);
        SET_CALLBACK_INIT();
        SET_CALLBACK_ALGOINDEX(loopargs->algo_index);
        SET_CALLBACK_TEST_NUM(loopargs->testnum);
        SET_CALLBACK_THREAD_ID(loopargs->thread_id);
        aead_datas[i].aead.tag = (uint64_t) (callback); 
    }
    
    //入队
    enqueued_count = mp_enqueue(ring, &aead_datas, batch);//批量入队
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

    int i = 0;
    pce_op_data_t *aead_datas = NULL;
    int enqueued_count = 0;
    int aead_length = loopargs->test_length;
    int batch = loopargs->batch;
    perf_ring *ring = loopargs->ring;
    aead_datas = loopargs->requests;
        
    for(i = 0; i < batch; i++){
        build_aead_cmd (&aead_datas[i],loopargs->cipher_algo,src, 
                                aead_length, dst,aead_length,loopargs->cipher_key,loopargs->use_linklist);
        SET_CALLBACK_INIT();
        SET_CALLBACK_ALGOINDEX(loopargs->algo_index);
        SET_CALLBACK_TEST_NUM(loopargs->testnum);
        SET_CALLBACK_THREAD_ID(loopargs->thread_id);
        aead_datas[i].aead.tag = (uint64_t) (callback);
    
    }
    
    //入队
    enqueued_count = mp_enqueue(ring, &aead_datas, batch);//批量入队
    if (0 == enqueued_count) {
        goto out;
    }
    
    out:
            
    return 1;
   
}

static int build_aead_cmd (pce_op_data_t *opdata, enum pce_alg cipher_alg,uint8_t *in, 
                        int inlen, uint8_t *out,int outlen ,uint8_t *key_iv,bool use_linklist)
{       
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
       
    if(use_linklist == true ){
        temp_op->aead.dma_mode = 2;
    }else{
        temp_op->aead.dma_mode = 0;
    }
    
    return 0;
}



void test_aead_perf(loopargs_t *loopargs)
{
    long count = 0;
    double d;
    int testnum = 0;
    int length = cmd_option.test_length;
    int segnum = cmd_option.linklist;
    pce_link_list_item_t *src_head = NULL;
    pce_link_list_item_t *dst_head = NULL;
    test_fn test_aead_fn = NULL;
    uint16_t thread_id = loopargs->thread_id;

    algo_data_t *algo_data = (algo_data_t*)get_hash_map(g_algo_hash_table, loopargs->algo_name);

    int algo_index = algo_data->algo_index;
    char *algo_name = algo_data->algo;
    uint16_t pce_algo = algo_data->pce_algo;
    struct  timeval tv;
    struct  timeval tv1;
    thread_run_algo[thread_id] = algo_index ;

    if(segnum > 1){
        loopargs->use_linklist = true;
        src_head = malloc_linklist(src_head, segnum);
        dst_head = malloc_linklist(dst_head, segnum);   
    }
    
    sem_t *start_sem = GET_START_SEM();
    int keysize = GET_KEYLEN_FORM_STRUCT(algo_data->algo_longness);
    int ivsize = GET_IVLEN_FROM_STRUCT(algo_data->algo_longness);

    //如果不是AEAD
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
    
    loopargs->cipher_key = setkey(loopargs->cipher_key, key32, keysize, iv, ivsize);        
    for (testnum = 0; testnum < SIZE_NUM; testnum++) {
        if(length > 0){
            loopargs->test_length = length;
            testnum = SIZE_NUM - 1;
        }else{
            loopargs->test_length = lengths[testnum];
        }
        loopargs->testnum = testnum;
        //如果为链式则创建
        if(segnum > 1){ //此处值有问题
            loopargs->src = (uint8_t*)create_linklist(loopargs->src_buf, loopargs->test_length, src_head, segnum);
            loopargs->dst = (uint8_t*)create_linklist(loopargs->dst_buf, loopargs->test_length, dst_head, segnum);
        }
            
        print_message(algo_name, 0, loopargs->test_length, cmd_option.duration);
        sem_post(start_sem);
        gettimeofday(&tv,NULL); 
        count = run_benchmark(test_aead_fn, loopargs);
        gettimeofday(&tv1,NULL);
        d = (tv1.tv_usec-tv.tv_usec)/(100000.0)+((tv1.tv_sec-tv.tv_sec));
        print_result(algo_index, testnum, count, d,thread_id);
    }
    if(segnum > 1 ){
        pce_free_mem(loopargs->src);
        pce_free_mem(loopargs->dst);
    }
    freekey(loopargs->cipher_key);

}

int test_aead_hit(const char *algo_name)
{
    
    return 0;
}


