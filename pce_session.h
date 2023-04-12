#ifndef _PHYTIUM_CE_SESSION_H_
#define _PHYTIUM_CE_SESSION_H_

#include "pce_common.h"

typedef void *pce_session_handle;

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
            uint8_t key[HMAC_SESSION_KEY_SIZE];
            uint8_t buffer[HASH_SESSION_BUFFER_SIZE];
            uint8_t state[HASH_SESSION_STATE_SIZE];
            pce_link_list_item_t list_buf[2];
            uint64_t total;
            int buffer_offset;
            int buffer_data_len;
            int hash_flag;
            int alg;
            int mode;
            int block_size;
            int key_size;
            int digest_size;
        } hash;
        struct {
            uint8_t key[CIPHER_SESSION_KEY_SIZE];
            uint8_t state[CIPHER_SESSION_STATE_SIZE];
            int iv_size;
            int iv_offset;
            int alg;
            int mode;
            int block_size;
            int key_size;
        }cipher;
        struct {
            uint8_t key[AEAD_SESSION_KEY_SIZE];
            uint8_t state[AEAD_SESSION_STATE_SIZE];
            int iv_size;
            int iv_offset;
            int alg;
            int mode;
            int block_size;
            int key_size;
            int tag_size;
            int total_aad_size;
            uint64_t total_crypt_size;
        }aead;
        struct {
            uint64_t total;
            uint64_t buffer_data_len;
            pce_link_list_item_t list_buf[2];
            uint8_t buffer[SCE_SESSION_BUFFER_SIZE];
            uint8_t middle_value[SCE_SESSION_MIDDLE_SIZE];
            uint8_t key_iv[SCE_SESSION_KEY_IV_SIZE];
            uint8_t sce_flag; // 0 init, 1 update, 2 finup, 3 final
            uint8_t *cur_in_vaddr; /* vaddr point to current source data */
        } sce;
    };
    uint16_t alg;
    uint16_t hash_cipher_aead; /*0 hash 1 sym 2 aead 3 asym */
}__attribute__((aligned(64)))pce_session_ctx_t;


int pce_alloc_session(int numa_node, pce_session_handle *session);

int pce_free_session(pce_session_handle session);

int pce_attach_session(pce_session_handle session, pce_op_data_t *op);

#endif

