#ifndef _PHYTIUM_COMMON_H_
#define _PHYTIUM_COMMON_H_

#include <stdint.h>

#define CMD_INVALID (0x35)
#define CMD_ERROR (0x45)
#define CMD_KEY_ERROR (0x65)
#define CMD_SUCCESS (0xA5)

#define PCE_QUEUE_DEPTH_256 (0)
#define PCE_QUEUE_DEPTH_1024 (1)
#define PCE_QUEUE_DEPTH_8192 (2)
#define PCE_QUEUE_DEPTH_65536 (3)

#define likely(x)    (__builtin_expect(!!(x), 1))
#define unlikely(x)    (__builtin_expect(!!(x), 0))


typedef void *pce_queue_handle;

typedef struct {
    uint64_t next_link_list_item; // point to next item's phys addr
    uint64_t addr;
    uint32_t len;
    uint32_t link_list_end_flag;
}__attribute__((packed))pce_link_list_item_t;

typedef struct {
    uint64_t tag;    /* tag from pce_op_data_t */
    uint64_t state;  /* error code : CMD_SUCCESS CMD_XXX */
}__attribute__((packed))pce_rsp_t;


typedef void (*pce_callback_fn)(void *opaque_data, int op_state);


#endif
