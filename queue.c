
#include "perf.h"

//修改队列描述符，增加引用计数的地址。
//多生产者入队函数，使用无锁队列实现op_datas数组
//
//pce_op_data_t **op_datas; 大小和实际队列尺寸保持一致，全局唯一，用于存放实际ops的地址。

//多线程调用入队函数时，会判断实际队列的引用计数是否为1，如果发现为1则直接入队即可，如果不为1，
//表示有多个线程在同时使用此队列，则走以下的流程具体参考dpdk无锁的实现。

//实际加入硬件队列后，也就是调用pce_enqueue，更新cons.tail,表示已经取走了。prod.tail用于表示有几个空闲。、
//多线程访问的数据，使用原子变量进行更新，需要保证全局唯一的数，采用volatile实现
//出队则不需要支持多线程同时访问，因为使用取余后，保证轮询线程数量不会大于队列数量，

//实际入队的burst数量
#define MIN_ENQUEUE_BATCH 16
#define RING_PAUSE_REP_COUNT 2 //如果重试两次后仍然没有更新当前tail,则让出当然线程，使用sched_yidld
#define ENQUEUE_PAUSE_COUNT 16

//op_datas数组的大小，可以小于硬件队列的大小
#define RING_SIZE 128

//对于只会运行一次的部分使用run_once

perf_ring *perf_rings;

//更新索引
static inline int atomic32_cmpset(volatile uint32_t *dst, uint32_t exp, uint32_t src)
{
    return __sync_bool_compare_and_swap(dst, exp, src);
}

static inline void mp_pause(void)
{
    //asm volatile("yield" ::: "memory");
}

#define smp_wmb() asm __volatile__("": : :"memory")

#define smp_rmb() asm __volatile__("" : : : "memory")


int mp_ring_init(int queue_num)
{
    int i = 0;
    //int depth;
    //生成对应数量的队列描述符
    perf_rings = malloc(sizeof(perf_ring) * queue_num); //分配内存空间

    for(i = 0 ; i < queue_num && i < MAX_QUEUE_NUM; i++){
        if(perf_rings[i].queue_handle ==  NULL){
            if (pce_request_queue(numa_node, &perf_rings[i].queue_handle)) {
                fprintf(stderr, "request_queue_failed!\n");
                exit(0);
                return -1;
            }
    
            if (pce_init_queue(perf_rings[i].queue_handle, g_queue_depth, 0)) {
                pce_release_queue(perf_rings[i].queue_handle);
                fprintf(stderr, "init_queue_failed!\n");
                exit(0);
            
                return -1;
            }
        }
        perf_rings[i].reference_count = 0;
        perf_rings[i].prod.head = 0;
        perf_rings[i].prod.tail = 0;
        perf_rings[i].prod.size = RING_SIZE;
        perf_rings[i].prod.mask = RING_SIZE-1;
        perf_rings[i].cons.head = 0;
        perf_rings[i].cons.tail = 0;
        perf_rings[i].cons.size = RING_SIZE;
        perf_rings[i].cons.mask = RING_SIZE-1;
        perf_rings[i].op_datas = NULL;

    }
    return 0;


}
int mp_ring_free(int queue_num)
{
    int i = 0;
    //释放对应数量的队列描述符
    for(i = 0 ; i < queue_num && i < MAX_QUEUE_NUM; i++){
        if(perf_rings[i].queue_handle !=  NULL){
            pce_release_queue(perf_rings[i].queue_handle); 
        }
        if(perf_rings[i].op_datas != NULL){
            free(perf_rings[i].op_datas);
            perf_rings[i].op_datas = NULL;
        }
    }
    free(perf_rings);
    return 0;
    

}

//映射线程和队列句柄的对应关系
perf_ring *get_queue_handle_from_ring(int thread_id,int thread_num,int queue_num)
{
    int i;
    
    if(queue_num > MAX_QUEUE_NUM){
        return NULL;
    }
    i = thread_id % queue_num; //将线程映射到对应的设备中，此处需要判断是否为指定映射，
    //通过取余来确定线程应当往哪个队列发送数据
    if(! atomic32_cmpset(&perf_rings[i].reference_count, 0,1)) //如果旧值为0则更新为1
    { 
        //如果旧值不为0，上述函数执行失败，表示此队列已经有一个线程在使用，此时是第二个线程，需要进行多生产者同时入队的部分
        //分配op_datas空间，如果此队列只有一个线程在使用，则不会申请此空间
        // 如果多个线程使用，分配op_datas在整个进程中只能被执行一次
        if(perf_rings[i].op_datas == NULL){
            perf_rings[i].op_datas = malloc(sizeof(pce_op_data_t *) * RING_SIZE );
        } 
        __sync_fetch_and_add(&perf_rings[i].reference_count, 1);
    }   

    return &perf_rings[i];
}

inline int mp_enqueue(perf_ring *ring, pce_op_data_t **ops,unsigned int n)
{   
    int count = 0;
    
    //如果当前队列只有一个线程在使用
    if(ring->reference_count == 1){
        //直接入队
        count = pce_enqueue(ring->queue_handle, ops, n);
        return count;
    }
    uint32_t mask = ring->prod.mask;
    uint32_t prod_head, prod_next;
    uint32_t temp_head;
    uint32_t cons_tail, free_entries;
    //uint32_t prod_tail = ring->prod.tail;
    const unsigned max = n;
    int success;
    unsigned int i=0;
    unsigned int rep = 0;
    pce_op_data_t **op_datas = ring->op_datas;
    
    /* move prod.head atomically */
        do {
            /* Reset n to the initial burst count */
            n = max;
    
            prod_head = ring->prod.head;
            temp_head = prod_head;
            cons_tail = ring->cons.tail;
            /* The subtraction is done between two unsigned 32bits value
             * (the result is always modulo 32 bits even if we have
             * prod_head > cons_tail). So 'free_entries' is always between 0
             * and size(ring)-1. */
            free_entries = (mask + cons_tail - prod_head) % RING_SIZE;
    
            /* check that we have enough room in ring */
            if (unlikely(n > free_entries)) {
                    /* No free entry available */
                    if (unlikely(free_entries == 0)) {
                        //已经满了
                        return 0;
                    }
    
                    n = free_entries;
                
            }
    
            prod_next = (prod_head + n) % RING_SIZE;
            /*
            *   rte_atomic32_cmpset(volatile uint32_t *dst, uint32_t exp, uint32_t src)
            *
            * if(dst==exp) dst=src;
            * else 
            *       return false;
            */
            success = atomic32_cmpset(&ring->prod.head, prod_head,
                              prod_next);/*此操作应该会从内存中读取值，并将不同核的修改写回到内存中*/
        } while (unlikely(success == 0));/*如果失败，更新相关指针重新操作*/
        
        smp_wmb();/*写内存屏障*/     
        //开始实际入队到op_datas中
        while(i < n){
            op_datas[temp_head] = ops[i];
            temp_head = (temp_head + 1) % RING_SIZE;
            i++;
        }

        /*
        * If there are other enqueues in progress that preceded us,
        * we need to wait for them to complete
        */
        while (unlikely(ring->prod.tail != prod_head)) {
            mp_pause();
            
        /* Set RING_PAUSE_REP_COUNT to avoid spin too long waiting
         * for other thread finish. It gives pre-empted thread a chance
         * to proceed and finish with ring dequeue operation. */
        if (RING_PAUSE_REP_COUNT &&
            ++rep == RING_PAUSE_REP_COUNT) {
            rep = 0;
            sched_yield();
        }
    }
        
    //当数量凑够后再入队
    if(prod_next - cons_tail > MIN_ENQUEUE_BATCH){
        mp_dequeue(ring, op_datas,MIN_ENQUEUE_BATCH);
    }
    
    ring->prod.tail = prod_next;    
    return n;

}

inline int mp_dequeue(perf_ring *ring, pce_op_data_t **ops,unsigned int n)
{
    uint32_t cons_head, prod_tail;//cons_tail;
    uint32_t cons_next, entries,temp;
    const unsigned max = n;
    int success;
    int enqueued_count = 0;
    unsigned rep,rep1 = 0;
    uint32_t mask = ring->prod.mask;
    pce_op_data_t **op_datas = ring->op_datas;
    //pce_op_data_t *remain;
    /* move cons.head atomically */
    do {
        /* Restore n as it may change every loop */
        n = max;

        cons_head = ring->cons.head;
        prod_tail = ring->prod.tail;
        /* The subtraction is done between two unsigned 32bits value
         * (the result is always modulo 32 bits even if we have
         * cons_head > prod_tail). So 'entries' is always between 0
         * and size(ring)-1. */
        entries = (mask +prod_tail - cons_head) % RING_SIZE;

        /* Set the actual entries for dequeue */
        if (n > entries) {
            
                if (unlikely(entries == 0)){
                    return 0;
                }

                n = entries;
            }
        

        cons_next = (cons_head + n ) % RING_SIZE;
        success = atomic32_cmpset(&ring->cons.head, cons_head,
                          cons_next);
    } while (unlikely(success == 0));
    smp_rmb();

    /*
     * If there are other dequeues in progress that preceded us,
     * we need to wait for them to complete
     */
    while (unlikely(ring->cons.tail != cons_head)) {
        mp_pause();

        /* Set RING_PAUSE_REP_COUNT to avoid spin too long waiting
         * for other thread finish. It gives pre-empted thread a chance
         * to proceed and finish with ring dequeue operation. */
        if (RING_PAUSE_REP_COUNT &&
            ++rep == RING_PAUSE_REP_COUNT) {
            rep = 0;
            sched_yield();
        }
    }
    
    //需要考虑到入队失败的处理
    if(cons_head + n < RING_SIZE){
        enqueued_count +=pce_enqueue(ring->queue_handle, &op_datas[cons_head] ,n);
    }else{
        temp = (RING_SIZE - cons_head);
        enqueued_count +=pce_enqueue(ring->queue_handle, &op_datas[cons_head] ,temp);
        enqueued_count +=pce_enqueue(ring->queue_handle, &op_datas[0] ,n - temp);
    }

    if(enqueued_count < n){ //如果未能未全部入队
        while(enqueued_count < n){
            temp = (cons_head + enqueued_count) % RING_SIZE;
            if(pce_enqueue(ring->queue_handle,  &op_datas[temp], 1) == 0){ //每次入队一个，直到入完
                mp_pause();
                //如果二十次均未成功，则让出当前处理器
                if  (ENQUEUE_PAUSE_COUNT && ++rep1 == ENQUEUE_PAUSE_COUNT) {
                rep1 = 0;
                sched_yield();
            }
            }else{
                enqueued_count ++; //入队一个成功，自增1
            } 
        }
        
    }
    
    ring->cons.tail = cons_next;

    return enqueued_count;
}


