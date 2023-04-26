#include <sys/time.h>

#include "cipher.h"
#include "perf.h"

static const unsigned char key32[32] = {
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x34, 0x56, 0x78,
    0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    0x12, 0x34, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56};

static unsigned char iv[16] = {0};

int build_cipher_cmd (pce_op_data_t *opdata, enum pce_alg cipher_alg,uint8_t *in, 
                        int inlen, uint8_t *out,int outlen ,uint8_t *key_iv, bool use_linklist);


//分配链式存储空间，头结点不存实际数据,此处需要详细检查代码
pce_link_list_item_t* malloc_linklist(pce_link_list_item_t *head,int seg_num)
{
    pce_link_list_item_t *temp = NULL;//头节点不存数据
    /*if(head == NULL){
        head = pce_alloc_mem(numa_node,sizeof(pce_link_list_item_t));
        //head = pce_alloc_mem(sizeof(pce_link_list_item_t));
        //printf("alloc head:%lx\n",head);
        head->addr =(uint64_t) NULL;
        head->len = 0;
        head->next_link_list_item = (uint64_t) NULL;
        head->link_list_end_flag = 0;
    }
    temp = head;
    while(seg_num--){
        pce_link_list_item_t *node = pce_alloc_mem(numa_node,sizeof(pce_link_list_item_t));
        //printf("alloc node:%lx\n",node);
        node->addr =(uint64_t) NULL;
        node->len = 0;
        node->next_link_list_item = (uint64_t) NULL;
        node->link_list_end_flag = 0;
        //temp为上一个结点
        temp->next_link_list_item =(uint64_t) (node);
        //printf("temp->next_link_list_item:%lx\n",temp->next_link_list_item);
        //temp更新为新结点
        temp = (pce_link_list_item_t *)temp->next_link_list_item;
        //printf("temp to next:%lx\n",temp);
    }*/
    temp = pce_alloc_mem(numa_node, sizeof(pce_link_list_item_t) * seg_num);
    if (temp == NULL)
            return -1;
    return temp;
}

//删除链式存储的空间
int free_linklist(pce_link_list_item_t *head)
{
    pce_free_mem(head);
    /*pce_link_list_item_t *node = head;
    pce_link_list_item_t *temp = NULL;
    while(node->next_link_list_item != (uint64_t)NULL){
        temp = (pce_link_list_item_t *) node->next_link_list_item; //保存下一个结点的指针
        //if(node.addr != NULL){
            //free(node.addr); //释放存放数据的段,如果存放数据的段是由malloc生成的话需要此代码，在本程序中不需要
        //}
        pce_free_mem(node); //释放当前结点
        node = temp; //往后移动一个结点
    } */  
    return 0;
}

pce_link_list_item_t * create_linklist(uint8_t *src, int srclen,pce_link_list_item_t *head, uint16_t max_segs)
{
    int divide = srclen;
    //pce_link_list_item_t *temp = head->next_link_list_item;//->next_link_list_item; //头节点不存数据

    //长度为16则不分片
    if(max_segs > srclen){
        fprintf(stderr,"num of linklist is greater than testlength, use testlength %d as max_segs!!\n",srclen);
    }

    //为使得每一分片大小不会差太多，计算每一分片的长度为比srclen大的最小能整除max_segs的值
    while(divide % max_segs != 0){
        divide ++ ;
    }
    uint32_t seglen = divide / max_segs; //分片长度整数部分
    if(seglen*(max_segs-1) >= srclen){ //如果超了则减少
        seglen--;
    }
    uint32_t lastseglen = srclen - (seglen * (max_segs-1)); //最后一片的长度,不能取余，长度为16分片为5时会出现问题
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

    /*for(i = 0; i < max_segs; i++){ //创建max_segs的链式
        if(i != (max_segs -1) ){
            printf("old-temp :%lx\n",(uint64_t)temp);
            //printf("old stemp-addr:%lx\n",temp->addr);
            temp->addr = 0;
            temp->addr =(uint64_t)pce_mem_virt2iova(src + (seglen * i)); //获得数据的地址，src为地址，seglen为当前数据
            printf("src-addr:%lx\n",src);
            temp->len = seglen;
            printf("temp--mid:%lx len %d\n",temp->addr,temp->len);
            temp->link_list_end_flag = 0;
            temp =(pce_link_list_item_t *) temp->next_link_list_item; //temp 移动到下一片
            printf("temp-next:%lx\n",temp);
        }else{ //此时移到最后一片
            temp->addr = 0;
            temp->addr =(uint64_t) (src + seglen * i);
            
            temp->len = lastseglen;
            printf("temp-last:%lx len %d\n",temp->addr,temp->len);
            temp->link_list_end_flag = 1; //表示此时已到最后一片
        }
    }   */
    pce_link_list_item_t *link = head;
    int src_link_num = max_segs;
    int msglen = seglen;
    uint64_t link_ioaddr;
    uint64_t src_ioaddr;
    int j = 0;
    src_ioaddr = pce_mem_virt2iova(src);
    //link = pce_alloc_mem(numa_node, sizeof(pce_link_list_item_t) * src_link_num);
    if (link == NULL)
            return -1;
    link_ioaddr = pce_mem_virt2iova(link);
    for (j = 0; j < src_link_num; j ++) {
        link[j].next_link_list_item = link_ioaddr + (j + 1) * sizeof(pce_link_list_item_t);
        link[j].addr = src_ioaddr + msglen / src_link_num * j;
        link[j].len = msglen / src_link_num;
        link[j].link_list_end_flag = 0;
    }
    link[j - 1].next_link_list_item = 0;
    link[j - 1].len = msglen - (msglen / src_link_num) * (j - 1);
    link[j - 1].link_list_end_flag = 1;
    return link;

}

int test_cipher_enc_loop(void *args)
{
    loopargs_t *loopargs = args;
    
    if (NULL == args) {
        return 0;
    }

    uint8_t *src = loopargs->src;
    uint8_t *dst = loopargs->dst; //此处应该根据链式进行赋值

    //pce_queue_handle queue_handle = loopargs->queue_handle;//获取队列描述符
    int i = 0;
    pce_op_data_t *cipher_datas = NULL;
    int enqueued_count = 0;
    int cipher_length = loopargs->test_length;
    int batch = loopargs->batch;
    cipher_datas = loopargs->requests;
    perf_ring *ring = loopargs->ring;
    for(i = 0; i < batch; i++){
        build_cipher_cmd (&cipher_datas[i],loopargs->cipher_algo,src, 
                                cipher_length, dst,cipher_length,loopargs->cipher_key, loopargs->use_linklist);
            
        cipher_datas[i].cipher.mode =  PCE_CIPHER_MODE_ENCRYPT; //操作模式设置为解密
        SET_CALLBACK_INIT();
        SET_CALLBACK_ALGOINDEX(loopargs->algo_index);
        SET_CALLBACK_TEST_NUM(loopargs->testnum);
        SET_CALLBACK_THREAD_ID(loopargs->thread_id);
        cipher_datas[i].cipher.tag = (uint64_t) (callback);
    
    }
    
    //入队
    enqueued_count = mp_enqueue(ring, &cipher_datas, batch);//批量入队
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
    int batch = loopargs->batch;
    perf_ring *ring = loopargs->ring;
    cipher_datas = loopargs->requests;
    
    for(i = 0; i < batch; i++){
    
        //生成模板，之后会对具体值再进行修改
        build_cipher_cmd (&cipher_datas[i],loopargs->cipher_algo,src, 
                            cipher_length, dst,cipher_length,loopargs->cipher_key, loopargs->use_linklist);
        
        cipher_datas[i].cipher.mode =  PCE_CIPHER_MODE_DECRYPT; //操作模式设置为解密
        
        SET_CALLBACK_INIT();
        SET_CALLBACK_ALGOINDEX(loopargs->algo_index);
        SET_CALLBACK_TEST_NUM(loopargs->testnum);
        SET_CALLBACK_THREAD_ID(loopargs->thread_id);
        cipher_datas[i].cipher.tag = (uint64_t) (callback);
    }

    //入队
    enqueued_count = mp_enqueue(ring, &cipher_datas, batch);//批量入队
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
                        int inlen, uint8_t *out,int outlen ,uint8_t *key_iv, bool use_linklist)
{

    pce_op_data_t *temp_op = NULL;
    temp_op = opdata;
    //temp_op->op_type = PCE_OP_TYPE_SYM;
    temp_op->session_handle = NULL;
    temp_op->packet_type = PCE_FULL_PACKET;
    
    temp_op->cipher.alg =(uint16_t)cipher_alg;

    //根据不同模式进行不同操作
    temp_op->cipher.mode = PCE_CIPHER_MODE_ENCRYPT; //默认值，需要修改
    temp_op->cipher.key_iv = (uint64_t)key_iv; 
    
    temp_op->cipher.in = (uint64_t)in;
    temp_op->cipher.in_bytes = inlen;
    temp_op->cipher.out = (uint64_t)out;
    temp_op->cipher.out_bytes = outlen;

    if(use_linklist == true ){
        temp_op->cipher.dma_mode = 2;
    }else{
        temp_op->cipher.dma_mode = 0;
    }

    return 0;

}


//目前暂时不能处理xts的密钥长度
void* setkey(uint8_t *key_iv, const uint8_t *key ,int keylen,uint8_t *iv ,int ivlen)
{
    uint8_t *temp = pce_alloc_mem(numa_node, AES_KEYSIZE_256 * 2 + 16 );//此处是最长的算法加密钥 即aes256xts的密钥和iv
    memset(temp,0 ,AES_KEYSIZE_256 * 2 + 16 );

    //暂未支持xts
    memcpy(temp + 32 - keylen , key, keylen); //按照文档79页进行填充密钥
    
    memcpy(temp + 32 ,iv, ivlen);
    return temp; //分配空间存放可以和iv
    fprintf(stderr, "set key is using virtual address!\n");
    return 0;
}

int freekey(uint8_t *key_iv){
    if(key_iv != NULL){
        pce_free_mem(key_iv);
    }
    return 0;
}

void test_cipher_perf(loopargs_t *loopargs)
{
    long count = 0;
    double d;
    int testnum = 0;
    //char *op_mode = cmd_option.op ? "decrypt" : "encrypt";
    int segnum = cmd_option.linklist;
    pce_link_list_item_t *src_head = NULL;
    pce_link_list_item_t *dst_head = NULL;
    test_fn test_cipher_fn = NULL;
    uint16_t thread_id = loopargs->thread_id;
    int length = cmd_option.test_length;    
    //获得算法参数
    algo_data_t *algo_data = (algo_data_t*)get_hash_map(g_algo_hash_table, loopargs->algo_name);
    int algo_index = algo_data->algo_index;
    char *algo_name = algo_data->algo;
    uint16_t pce_algo = algo_data->pce_algo;
    if(segnum > 1){
        loopargs->use_linklist = true;
        src_head = malloc_linklist(src_head, segnum);
        dst_head = malloc_linklist(dst_head, segnum);   
    }
    thread_run_algo[thread_id] = algo_index ;
    sem_t *start_sem = GET_START_SEM();
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
    loopargs->cipher_key = setkey(loopargs->cipher_key, key32, keysize, iv, ivsize);
    //setkey(loopargs->cipher_key, key32, keysize, iv, ivsize);     
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
        count = run_benchmark(test_cipher_fn, loopargs);
        gettimeofday(&tv1,NULL);
        d = (tv1.tv_usec-tv.tv_usec)/(100000.0)+((tv1.tv_sec-tv.tv_sec));
        print_result(algo_index, testnum, count, d,thread_id);
            //释放链式空间
        
    }
    if(segnum > 1 ){
        pce_free_mem(loopargs->src);
        pce_free_mem(loopargs->dst);
    }
    freekey(loopargs->cipher_key);

}


int test_cipher_hit(const char *algo_name)
{   
    return 0;
}


