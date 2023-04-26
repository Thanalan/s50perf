#ifndef _PHYTIUM_CE_CRYPTO_H_
#define _PHYTIUM_CE_CRYPTO_H_

#include "pce_common.h"

/* stream flag*/
enum pce_sce_flag {
    PCE_SCE_INIT = 0,
    PCE_SCE_UPDATE = 1,
    PCE_SCE_FINAL = 2,
    PCE_SCE_FINUP = 3,
};

enum pce_digest_mode {
    PCE_DIGEST_MODE_NORMAL,
    PCE_DIGEST_MODE_HMAC
};
enum pce_cmac_mode {
	PCE_CMAC_MODE_GENERATE,
	PCE_CMAC_MODE_VERIFY,
};
enum pce_cbcmac_mode {
	PCE_CBCMAC_MODE_GENERATE,
	PCE_CBCMAC_MODE_VERIFY,
};
typedef struct {
	uint16_t alg;/*denoted by enum crypto_auth_algorithm*/
    uint16_t reserved;
	uint32_t out_bytes;/*output data bytes*/
	uint64_t out;/* Output data, the first address of the physical address */
	uint64_t tag;/* */
} pce_rand_op_t;

typedef struct {
    uint16_t alg;/*denoted by enum crypto_auth_algorithm */
    uint8_t mode;/*denoted by enum phytium_ce_digest_mode */    
    uint8_t dma_mode;/* [7:1]:Reserved  [0]: 1 link list enable*/    
    uint16_t key_bytes;/*key size*/
    uint16_t digest_len;/* digest length */
    uint64_t key_iv;/* Storage Physical Address*/
    uint64_t in;/* Input data, the first address of the physical address*/
    uint64_t out;/* Output data, the first address of the physical address */
    uint32_t in_bytes;/*input data bytes*/
    uint64_t tag;/* */
} pce_hash_op_t;

enum pce_cipher_mode {
    PCE_CIPHER_MODE_ENCRYPT,
    PCE_CIPHER_MODE_DECRYPT
};

typedef struct {
    uint16_t alg;/*denoted by enum rte_crypto_cipher_algorithm */
    uint8_t mode;/*denoted by enum phytium_ce_cipher_mode */
    uint8_t dma_mode;/* [7:2]:Reserved [1]: 1 dst link list enable  [0]: 1 src link list enable*/
    uint64_t key_iv;/* Storage Physical Address*/
    uint64_t in;/* Input data, the first address of the physical address*/
    uint64_t out;/* Output data, the first address of the physical address */
    uint32_t in_bytes;/*input data bytes*/
    uint32_t out_bytes;/*output data bytes*/
    uint64_t tag;/* */
} pce_cipher_op_t;

enum pce_aead_mode {
    PCE_AEAD_MODE_ENCRYPT,
    PCE_AEAD_MODE_DECRYPT
};

typedef struct {
    uint16_t alg;/*denoted by enum rte_crypto_aead_algorithm */
    uint8_t mode;/*denoted by enum phytium_ce_aead_mode */
    uint8_t dma_mode;/* [7:2]:Reserved [1]: 1 dst link list enable  [0]: 1 src link list enable*/
    uint16_t tag_size;/*authsize*/
    uint16_t aad_size;/*aad len*/
    uint64_t key_iv;/* Storage Physical Address*/
    uint64_t in;/* Input data, the first address of the physical address*/
    uint64_t out;/* Output data, the first address of the physical address */
    uint32_t in_bytes;/*input data bytes*/
    uint32_t out_bytes;/*output data bytes*/
    uint64_t tag;/* */
} pce_aead_op_t;

typedef struct pce_rsa_op {
    uint16_t alg;
    uint16_t reserved;
	uint64_t tag;

    union {
        struct {
            uint16_t e_bit_length; // if set 17, then e_addr content will be 65537 (0x10001)
			uint16_t n_bit_length; // must be multiple of 1024 and <=4096
			uint64_t e_addr;       //   out
			uint64_t d_addr;        //  out
			uint64_t n_addr;        //  out
		} genkey;
		struct {
			uint16_t e_bit_length;
			uint16_t n_bit_length;
			uint64_t data_addr;     // data length should be n_bit_length byte length,  input
			uint64_t e_addr;        // data length should be e_bit_length byte length,  input
			uint64_t n_addr;        // data length should be n_bit_length byte length,  input
			uint64_t result_addr;   //  out
		} encrypt;
		struct {
			uint16_t e_bit_length;
			uint16_t n_bit_length;
			uint64_t data_addr;     // length = n_bit_length
			uint64_t key_addr;
			uint64_t result_addr;
		}decrypt;
		struct {
			uint16_t e_bit_length;
			uint16_t n_bit_length;
			uint64_t data_addr;
			uint64_t key_addr;
			uint64_t result_addr;
		}sign;
		struct {
			uint16_t e_bit_length;
			uint16_t n_bit_length;
			uint64_t signature_addr;
			uint64_t e_addr;
			uint64_t n_addr;
			uint64_t result_addr;
		}verify;
    };
} pce_rsa_op_t; /* all data should be little endian */

enum pce_curve_type {
    PCE_ECC_CURVE_SECP192R1 = 0,
    PCE_ECC_CURVE_SECP224R1 = 1,
    PCE_ECC_CURVE_SECP256R1 = 2,
    PCE_ECC_CURVE_SECP384R1 = 3,
    PCE_ECC_CURVE_SECP521R1 = 4,
    PCE_SM2_CURVE_P256   = 5
};

typedef struct pce_ecc_op {
    uint16_t alg;
    uint16_t curve_id;
	uint64_t tag;

    union {
        struct {
			uint32_t reserved;
			uint64_t priv_key_addr;
			uint64_t pub_key_addr;
		} genkey;
		struct {
			uint32_t e_byte_length;
			uint64_t e_addr;
			uint64_t priv_key_addr;
			uint64_t result_addr;
		} sign;
		struct {
			uint32_t e_byte_length;
			uint64_t e_signature_addr;
			uint64_t pub_key_addr;
		} verify;
		struct {
			uint32_t reserved;
			uint64_t peer_pub_key_addr;
			uint64_t priv_key_addr;
			uint64_t result_addr;
		} ecdh;
    };
} pce_ecc_op_t;

typedef struct pce_sm2_op {
	uint16_t alg;
	uint16_t reserved;
	
	union {
		struct {		
			uint32_t reserved;
			uint64_t priv_key_addr;
			uint64_t pub_key_addr;
		}genkey;
		struct {
			uint32_t reserved;
			uint64_t e_addr;
			uint64_t priv_key_addr;
			uint64_t result_addr;
		}sign;
		struct {
			uint32_t reserved;
			uint64_t e_signature_addr;
			uint64_t pub_key_addr;
		}verify;
		struct {
			uint16_t role;
			uint16_t key_length;
			uint64_t key_z_addr;
			uint64_t result_addr;
		}exchange;
		struct {
			uint32_t msg_length;
			uint64_t msg_addr;
			uint64_t pub_key_addr;
			uint64_t result_addr;
		}encrypt;
		struct {
			uint32_t cipher_length;
			uint64_t cipher_addr;
			uint64_t priv_key_addr;
			uint64_t result_addr;
		}decrypt;
	};	
    uint64_t tag;
} pce_sm2_op_t;

enum pce_packet_type {
    PCE_FIRST_PACKET = 1,
    PCE_MIDDLE_PACKET = 2,
    PCE_LAST_PACKET = 3,
    PCE_FULL_PACKET = 4,
};

typedef struct {
    void *session_handle; /*分片包使用，单包设为NULL*/
    uint8_t packet_type; // 1 first pkt, 2 middle pkt, 3, last pkt, 4 full pkt
    uint8_t reserved0[7];
    union {
        pce_hash_op_t hash;
        pce_cipher_op_t cipher;
        pce_aead_op_t aead;
	    pce_rand_op_t rand;
        pce_rsa_op_t rsa;
        pce_ecc_op_t ecc;
        pce_sm2_op_t sm2;

        uint16_t alg;
        struct {
            uint8_t alg_type; // readonly
            uint8_t cmd_type; // readonly
        };
    };
} __attribute__((aligned(64))) pce_op_data_t;



enum PCE_SYM_MODE {
    PCE_SYM_ENC = 0x10000,
    PCE_SYM_DEC = 0x100,
};


// 引擎类型，用于快速索引命令函数 -- build_cmd
enum pce_alg_cmd_type {
    PCE_ALG_CMD_TYPE_RANDOM = 0x00,   // cmd 0x03
    PCE_ALG_CMD_TYPE_HFE_HASH = 0x01, // cmd 0xA1
    PCE_ALG_CMD_TYPE_HFE_HMAC = 0x02, // cmd 0xA2  0xA3
    PCE_ALG_CMD_TYPE_SKE_CMAC_CBCMAC = 0x03, // cmd 0x21 0x22
    PCE_ALG_CMD_TYPE_SKE_CIPHER = 0x04, // cmd 0x23 0x24
    PCE_ALG_CMD_TYPE_SKE_AEAD = 0x05,  // cmd 0x25 0x26
    PCE_ALG_CMD_TYPE_SKE_AEAD_CCM = 0x06, // 0x27 0x28
    PCE_ALG_CMD_TYPE_SCE = 0x07, // cmd 0x29
    PCE_ALG_CMD_TYPE_PKE_RSA = 0x08,   // cmd 0x81 ~ 0x88
    PCE_ALG_CMD_TYPE_PKE_ECC = 0x09, // cmd 0x61 ~ 0x65
    PCE_ALG_CMD_TYPE_PKE_SM2 = 0x0a, // cmd 0x43 ~ 0x4C   
    PCE_ALG_CMD_TYPE_COUNT
};


enum pce_alg {
    PCE_RANDOM = 0x0001,

    PCE_HASH_SM3 = 0x0100,
    PCE_HASH_MD5 = 0x0101,
    PCE_HASH_SHA256 = 0x0102,
    PCE_HASH_SHA384 = 0x0103,
    PCE_HASH_SHA512 = 0x0104,
    PCE_HASH_SHA1 = 0x0105,
    PCE_HASH_SHA224 = 0x0106,
    PCE_HASH_SHA512_224 = 0x0107,
    PCE_HASH_SHA512_256 = 0x0108,
    PCE_HASH_SHA3_224 = 0x0109,
    PCE_HASH_SHA3_256 = 0x010A,
    PCE_HASH_SHA3_384 = 0x010B,
    PCE_HASH_SHA3_512 = 0x010C,

    PCE_HMAC_SM3 = 0x0200,
    PCE_HMAC_MD5 = 0x0201,
    PCE_HMAC_SHA256 = 0x0202,
    PCE_HMAC_SHA384 = 0x0203,
    PCE_HMAC_SHA512 = 0x0204,
    PCE_HMAC_SHA1 = 0x0205,
    PCE_HMAC_SHA224 = 0x0206,
    PCE_HMAC_SHA512_224 = 0x0207,
    PCE_HMAC_SHA512_256 = 0x0208,

    PCE_CBC_MAC_AES_128 = 0x0312,
    PCE_CBC_MAC_AES_192 = 0x0313,
    PCE_CBC_MAC_AES_256 = 0x0314,
    PCE_CBC_MAC_SM4 = 0x0315,

    PCE_CMAC_AES_128 = 0x0316,
    PCE_CMAC_AES_192 = 0x0317,
    PCE_CMAC_AES_256 = 0x0318,
    PCE_CMAC_SM4 = 0x0319,

    PCE_DES_ECB = 0x041A,
    PCE_DES_CBC = 0x041B,
    PCE_DES_CFB = 0x041C,
    PCE_DES_OFB = 0x041D,
    PCE_DES_CTR = 0x041E,

    PCE_TDES_128_ECB = 0x041F,// 3DES
    PCE_TDES_128_CBC = 0x0420,
    PCE_TDES_128_CFB = 0x0421,
    PCE_TDES_128_OFB = 0x0422,
    PCE_TDES_128_CTR = 0x0423,
    PCE_TDES_192_ECB = 0x0424,
    PCE_TDES_192_CBC = 0x0425,
    PCE_TDES_192_CFB = 0x0426,
    PCE_TDES_192_OFB = 0x0427,
    PCE_TDES_192_CTR = 0x0428,

    PCE_AES_128_ECB = 0x0429,
    PCE_AES_128_CBC = 0x042A,
    PCE_AES_128_CFB = 0x042B,
    PCE_AES_128_OFB = 0x042C,
    PCE_AES_128_CTR = 0x042D,
    PCE_AES_128_XTS = 0x042E,

    
    PCE_AES_192_ECB = 0x0430,
    PCE_AES_192_CBC = 0x0431,
    PCE_AES_192_CFB = 0x0432,
    PCE_AES_192_OFB = 0x0433,
    PCE_AES_192_CTR = 0x0434,

    PCE_AES_256_ECB = 0x0437,
    PCE_AES_256_CBC = 0x0438,
    PCE_AES_256_CFB = 0x0439,
    PCE_AES_256_OFB = 0x043A,
    PCE_AES_256_CTR = 0x043B,
    PCE_AES_256_XTS = 0x043C,

    PCE_SM4_ECB = 0x043E,
    PCE_SM4_CBC = 0x043F,
    PCE_SM4_CFB = 0x0440,
    PCE_SM4_OFB = 0x0441,
    PCE_SM4_CTR = 0x0442,
    PCE_SM4_XTS = 0x0443,

    PCE_AES_128_GCM = 0x0500,
    PCE_AES_192_GCM = 0x0501,
    PCE_AES_256_GCM = 0x0502,
    PCE_SM4_GCM = 0x0503,

    PCE_AES_128_CCM = 0x0600,
    PCE_AES_192_CCM = 0x0601,
    PCE_AES_256_CCM = 0x0602,
    PCE_SM4_CCM = 0x0603,

    PCE_UIA2 = 0x0700,
    PCE_EIA3 = 0x0701,
    PCE_EEA3 = 0x0704,
    PCE_UEA2 = 0x0705,

    PCE_RSA_KEY =       0x0800,
    PCE_RSA_CRT_KEY =   0x0801,
    PCE_RSA_ENC =       0x0802,
    PCE_RSA_DEC =       0x0803,
    PCE_RSA_CRT_DEC =   0x0804,
    PCE_RSA_CRT_SIGN =  0x0805,
    PCE_RSA_SIGN =      0x0806,
    PCE_RSA_VERIFY =    0x0807,

    PCE_ECC_PUBKEY =    0x0900,
    PCE_ECC_KEY =       0x0901,
    PCE_ECDSA_SIGN =    0x0902,
    PCE_ECDSA_VERIFY =  0x0903,
    PCE_ECDH_EXCHANGE = 0x0904,

    PCE_SM2_PUBKEY =    0x0A00,
    PCE_SM2_KEY =       0x0A01,
    PCE_SM2_SIGN =      0x0A02,
    PCE_SM2_VERIFY =    0x0A03,
    PCE_SM2_EXCHANGE =  0x0A04,
    PCE_SM2_ENC =       0x0A05,
    PCE_SM2_DEC =       0x0A06,

    PCE_INVALID_ALG = 0xFFFF,
};


#endif

