#ifndef _PHYTIUM_CE_SESSION_H_
#define _PHYTIUM_CE_SESSION_H_

#include "pce_common.h"
#include "pce_crypto.h"


#define HMAC_SESSION_KEY_SIZE (256)
#define HASH_SESSION_BUFFER_SIZE    (512)
#define HASH_SESSION_STATE_SIZE     (256)

#define CIPHER_SESSION_KEY_SIZE (128)
#define CIPHER_SESSION_STATE_SIZE (128)

#define AEAD_SESSION_KEY_SIZE (128)
#define AEAD_SESSION_STATE_SIZE (128)


#define SCE_SESSION_BUFFER_MASK (31)
#define SCE_SESSION_BUFFER_SIZE (32)
#define SCE_SESSION_KEY_IV_SIZE (64)
#define SCE_SESSION_MIDDLE_SIZE (128)

typedef union {
    union {
        struct {            
            uint8_t state[HASH_SESSION_STATE_SIZE]; 
            uint8_t key[HMAC_SESSION_KEY_SIZE];
            uint8_t buffer[HASH_SESSION_BUFFER_SIZE];
            pce_link_list_item_t list_buf[2];
            uint64_t total;  // 已处理长度
            uint64_t session_base_ioaddr;
            int hash_flag;   // 当前分片标识
        } hash;
        struct {            
            uint8_t state[CIPHER_SESSION_STATE_SIZE];
            uint8_t key[CIPHER_SESSION_KEY_SIZE];
            uint64_t session_base_ioaddr;
        }cipher;
        struct {            
            uint8_t state[AEAD_SESSION_STATE_SIZE];
            uint8_t key[AEAD_SESSION_KEY_SIZE];
            uint64_t total_crypt_size;
            uint64_t session_base_ioaddr;
            int total_aad_size;
        }aead;
    };
}__attribute__((aligned(64)))pce_session_ctx_t;

int pce_alloc_session(int numa_node, pce_session_ctx_t **session);

int pce_free_session(pce_session_ctx_t *session);

int pce_attach_session(pce_session_ctx_t *session, pce_op_data_t *op);

#endif

