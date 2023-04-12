#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "pce.h"
#include "pce_common.h"
#include "pce_crypto.h"
#include "pce_log.h"
#include "pce_session.h"
#include "pce_utils.h"

#define __FUNC__ __func__
int pce_request_queue(int num_node, pce_queue_handle *queue){
	fprintf(stderr, "func:%s in file:%s\n",__func__,__FILE__);
	usleep(1000);
	return 0;

}

int pce_init_queue(pce_queue_handle queue, int depth, int flags){
	fprintf(stderr, "func:%s in file:%s\n",__func__,__FILE__);
	usleep(1000);
	return 0;
}

int pce_release_queue(pce_queue_handle queue){
	fprintf(stderr, "func:%s in file:%s\n",__func__,__FILE__);
	usleep(1000);
	return 0;

}

int pce_get_queue_info(pce_queue_handle queue, struct queue_statis_info *info){
	fprintf(stderr, "func:%s in file:%s\n",__func__,__FILE__);
	usleep(1000);
	return 0;


}


pce_rsp_t response[1024] = {0};
volatile int tail =0;
volatile int head =0;;



int pce_enqueue(pce_queue_handle queue, pce_op_data_t **op_datas, int op_num){
	//fprintf(stderr, "func:%s in file:%s\n",__func__,__FILE__);
	int i;
	for(i = 0; i < op_num; i++){
		response[tail].tag = (*op_datas)->hash.tag;
		response[tail].state = CMD_SUCCESS;
		tail = (tail+1) % 1024;
		}
	//usleep(1000);
	return 1;


}

int pce_dequeue(pce_queue_handle queue, pce_rsp_t *rsp, int max_num){
	//fprintf(stderr, "func:%s in file:%s\n",__func__,__FILE__);
	int i;
	//if(response[head].state != CMD_SUCCESS){
		//	return 0;
	//}
	*rsp = response[head];
	//memcpy(rsp,&response[head],sizeof(pce_rsp_t) * max_num);
	//memset(&response[head], 0, sizeof(pce_rsp_t) * max_num); //清零
	//rsp = &response[head];
	head = (head+1) % 1024;
		//rsp++;
	
	//usleep(0);
	return 1;


}

int pce_perform_op(pce_queue_handle queue, void *op_datas, pce_callback_fn op_done, pce_op_data_t *opaque_data){

fprintf(stderr, "func:%s in file:%s\n",__func__,__FILE__);
	usleep(1000);
	return 0;

}

int pce_lib_init(pce_lib_cfg_t *cfg){
	fprintf(stderr, "func:%s in file:%s\n",__func__,__FILE__);
	usleep(1000);
	return 0;

}

void pce_lib_exit(void){
	fprintf(stderr, "func:%s in file:%s\n",__func__,__FILE__);
	usleep(1000);
	

}

void *pce_alloc_mem(int numa_node, uint32_t size){
	fprintf(stderr, "func:%s in file:%s\n",__func__,__FILE__);
	usleep(1000);
	return malloc(sizeof(uint32_t) * size);
	return NULL;


}


void pce_free_mem(void *buf){
	fprintf(stderr, "func:%s in file:%s\n",__func__,__FILE__);
	free(buf);
	usleep(1000);


}

uint64_t pce_mem_virt2iova(const void *vaddr){
	fprintf(stderr, "func:%s in file:%s\n",__func__,__FILE__);
	usleep(1000);
	return 0;

}

void pce_log_set_syslog(const char *app_name, pce_log_level_t log_level){
	fprintf(stderr, "func:%s in file:%s\n",__func__,__FILE__);
	usleep(1000);
	

}

pce_log_level_t pce_log_get_syslog(void){
	fprintf(stderr, "func:%s in file:%s\n",__func__,__FILE__);
	usleep(1000);

}


int pce_alloc_session(int numa_node, pce_session_handle *session){
	fprintf(stderr, "func:%s in file:%s\n",__func__,__FILE__);
		usleep(1000);
	return 0;


}

int pce_free_session(pce_session_handle session){

	fprintf(stderr, "func:%s in file:%s\n",__func__,__FILE__);
		usleep(1000);
		return 0;

}

int pce_attach_session(pce_session_handle session, pce_op_data_t *op){
	fprintf(stderr, "func:%s in file:%s\n",__func__,__FILE__);
		usleep(1000);
		return 0;


}

/*
int pce_init_session(pce_session_handle session, pce_session_setup_data_t *setup_data){
	fprintf(stderr, "func:%s in file:%s\n",__func__,__FILE__);
		usleep(1000);


}

int pce_prepare_session(pce_session_handle session, pce_session_prepare_data_t *prepare_data){
	fprintf(stderr, "func:%s in file:%s\n",__func__,__FILE__);
		usleep(1000);


}

int pce_update_session(pce_session_handle session, pce_session_update_data_t *update_data){

	fprintf(stderr, "func:%s in file:%s\n",__func__,__FILE__);
		usleep(1000);


}
*/
int pce_ecsign_decode(int curve_type, uint8_t *sig, uint32_t sig_len, uint8_t *out){


}
int pce_sm2decrypt_decode(uint8_t *input, uint32_t inlen, uint8_t *output, uint32_t *outlen){}


