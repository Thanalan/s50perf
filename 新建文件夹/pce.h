#ifndef _PHYTIUM_CE_H_
#define _PHYTIUM_CE_H_

#include <stdint.h>
#include "pce_common.h"
#include "pce_crypto.h"

struct queue_statis_info {
   uint32_t cmd_num;/*表示还有多少未读取走*/
   uint32_t rsp_rdptr;/*还有多少未回复*/
};

/* memory VA to DMA address map */
typedef void *(*pce_map_io)(void *usr, void *va);

/* memory from user, it is given at lib init, used to io_map */
struct pce_mm_map {
    pce_map_io iova_map; /* get iova from user space VA */
    void *usr; /* data for the above operations */
};

#define PCE_MEM_MODE_IOVA 0 /* 参数内存模型, 为io地址，无需转换 */
#define PCE_MEM_MODE_VA   1 /* 参数内存模型, 为虚拟地址，需要转换 */

typedef struct {
    uint32_t  op_addr_mode:1; // op参数地址的类型， 决定虚拟地址在最后如何转换
    uint32_t  enable_session:1; // 使能session功能，额外增加session的处理
    uint32_t  session_num:30; // session pool池大小, default 2048， 后续用宏控制，每个numa节点分配这么多 0采用默认值
    uint32_t  reserved;
    struct pce_mm_map iomap;    // 内存VA->IOVA映射, 当op_addr_mode为PCE_MEM_MODE_VA有效
} pce_lib_cfg_t;


int pce_request_queue(int num_node, pce_queue_handle *queue);

int pce_init_queue(pce_queue_handle queue, int depth, int flags);

int pce_release_queue(pce_queue_handle queue);

int pce_get_queue_info(pce_queue_handle queue, struct queue_statis_info *info);

int pce_enqueue(pce_queue_handle queue, pce_op_data_t **op_datas, int op_num);

int pce_dequeue(pce_queue_handle queue, pce_rsp_t *rsp, int max_num);

int pce_lib_init(pce_lib_cfg_t *cfg);

void pce_lib_exit(void);

void *pce_alloc_mem(int numa_node, uint32_t size);

void pce_free_mem(void *buf);

uint64_t pce_mem_virt2iova(const void *vaddr);

void pce_sm2encrypt_encode(const uint8_t *input, uint32_t inlen, uint8_t *output, uint32_t *outlen);

int pce_sm2decrypt_decode(const uint8_t *input, uint32_t inlen, uint8_t *output, uint32_t *outlen);

void pce_ecsign_encode(int curve_type, const uint8_t *input, uint8_t *sig, uint32_t *sig_len);

int pce_ecsign_decode(int curve_type, const uint8_t *sig, uint32_t sig_len, uint8_t *out);

#endif


