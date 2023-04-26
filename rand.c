#include "rand.h"

static inline int build_rand_cmd (pce_op_data_t *opdata, enum pce_alg rand_alg,uint8_t *in, 
                        int inlen, uint8_t *out,int outlen )
{
    pce_op_data_t *temp_op = NULL;
    temp_op = opdata;
    temp_op->session_handle = NULL;
    temp_op->packet_type = PCE_FULL_PACKET;

    //temp_op->op_type = PCE_OP_TYPE_HASH;
    temp_op->rand.alg = rand_alg;
    
    temp_op->rand.out = (uint64_t) out;
    temp_op->rand.out_bytes = outlen;
   
   // temp_op->rand.dma_mode = 0;
    //temp_op->rand.type = PCE_OP_TYPE_HASH;


    return 0;
}

int test_rand_loop(void *args)
{
    loopargs_t *loopargs = args;
    
    if (NULL == args) {
        return 0;
    }
    uint8_t *src = loopargs->src;
    uint8_t *dst = loopargs->dst; //此处应该根据链式进行赋值

    int i = 0;
    pce_op_data_t *rand_datas = NULL;
    int enqueued_count = 0;
    int batch = loopargs->batch;
    perf_ring *ring = loopargs->ring;
    rand_datas = loopargs->requests;    
    for(i = 0; i < batch; i++){
        build_rand_cmd(&rand_datas[i], PCE_RANDOM , src, loopargs->test_length, dst, loopargs->test_length);
        SET_CALLBACK_INIT();
        SET_CALLBACK_ALGOINDEX(loopargs->algo_index);
        SET_CALLBACK_TEST_NUM(loopargs->testnum);
        SET_CALLBACK_THREAD_ID(loopargs->thread_id);
        rand_datas[i].rand.tag = (uint64_t) (callback);
    }

    //入队
    enqueued_count = mp_enqueue(ring, &rand_datas, batch);//批量入队
    if (0 == enqueued_count) {
         goto out;
    }
    
out:
        
    return 1;
}


void test_rand_perf(loopargs_t *loopargs)
{
    long count = 0;
    double d;
    int testnum = 0;
    algo_data_t *algo_data = (algo_data_t*)get_hash_map(g_algo_hash_table, loopargs->algo_name);
    int algo_index = algo_data->algo_index; 
    uint16_t thread_id = loopargs->thread_id;
    //修改全局数据记得加锁
    thread_run_algo[thread_id] = algo_index;//更新当前线程执行的算法名称
    
    char *algo_name = algo_data->algo;
    uint16_t pce_algo = algo_data->pce_algo;
    loopargs->batch = cmd_option.batch;
    loopargs->algo_index = algo_index;
    sem_t *start_sem = GET_START_SEM();
    if(algo_data->algo_type == ALGO_TYPE_RAND){
        for (testnum = 0; testnum < SIZE_NUM; testnum++) {
            loopargs->test_length = lengths[testnum];
            loopargs->hash_algo = pce_algo; 
            loopargs->testnum = testnum;
            print_message(algo_name, 0, lengths[testnum], cmd_option.duration);
            
            gettimeofday(&tv,NULL);
            sem_post(start_sem);
            count = run_benchmark(test_rand_loop, loopargs);
            gettimeofday(&tv1,NULL);
            d = (tv1.tv_usec-tv.tv_usec)/(100000.0)+((tv1.tv_sec-tv.tv_sec));
            
            print_result(algo_index, testnum, count, d,thread_id);
        }
        
    }else { //如果不是RAND

        fprintf(stderr,"Not rand algo name:%s in line %d in file:\n%s\n",algo_name, __LINE__,__FILE__);
    }

}

//返回0表示成功
int test_rand_hit(const char *algo_name)
{   
    return 0;
}


