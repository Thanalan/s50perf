#include <stdint.h>
#include <unistd.h>


#include "command.h"
#include "lib.h"
#include "ecc.h"
#include "perf.h"
typedef struct {
    char algo_name[64];
    uint16_t alg;
    uint16_t reserved;
    uint8_t *result;
    uint8_t *src;
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
} sm2_test_data_t;


#if 0
typedef struct {
    unsigned char *pubkey;
    unsigned char *prikey;
    const unsigned char *m;
    unsigned char *c;
    unsigned int m_size;
    unsigned int c_size;
    int algo;
}sm2_testvec_t;



static sm2_testvec_t sm2_tv_template[] = {
    { /* Generated from openssl */
    .m_size = 32,
    .c_size = 71,
    .pubkey =
    "\x8e\xa0\x33\x69\x91\x7e\x3d\xec\xad\x8e\xf0\x45\x5e\x13\x3e\x68"
    "\x5b\x8c\xab\x5c\xc6\xc8\x50\xdf\x91\x00\xe0\x24\x73\x4d\x31\xf2"
    "\x2e\xc0\xd5\x6b\xee\xda\x98\x93\xec\xd8\x36\xaa\xb9\xcf\x63\x82"
    "\xef\xa7\x1a\x03\xed\x16\xba\x74\xb8\x8b\xf9\xe5\x70\x39\xa4\x70", 
    .c =
    "\x30\x45"
    "\x02\x20"
    "\x70\xab\xb6\x7d\xd6\x54\x80\x64\x42\x7e\x2d\x05\x08\x36\xc9\x96"
    "\x25\xc2\xbb\xff\x08\xe5\x43\x15\x5e\xf3\x06\xd9\x2b\x2f\x0a\x9f"
    "\x02\x21"
    "\x00"
    "\xbf\x21\x5f\x7e\x5d\x3f\x1a\x4d\x8f\x84\xc2\xe9\xa6\x4c\xa4\x18"
    "\xb2\xb8\x46\xf4\x32\x96\xfa\x57\xc6\x29\xd4\x89\xae\xcc\xda\xdb",
    .algo = PCE_SM2_VERIFY,
    .m =
    "\x47\xa7\xbf\xd3\xda\xc4\x79\xee\xda\x8b\x4f\xe8\x40\x94\xd4\x32"
    "\x8f\xf1\xcd\x68\x4d\xbd\x9b\x1d\xe0\xd8\x9a\x5d\xad\x85\x47\x5c",
    },
    { /* From libgcrypt */
    .m_size = 32,
    .c_size = 70,
    .pubkey =
    "\x87\x59\x38\x9a\x34\xaa\xad\x07\xec\xf4\xe0\xc8\xc2\x65\x0a\x44"
    "\x59\xc8\xd9\x26\xee\x23\x78\x32\x4e\x02\x61\xc5\x25\x38\xcb\x47"
    "\x75\x28\x10\x6b\x1e\x0b\x7c\x8d\xd5\xff\x29\xa9\xc8\x6a\x89\x06"
    "\x56\x56\xeb\x33\x15\x4b\xc0\x55\x60\x91\xef\x8a\xc9\xd1\x7d\x78",
    .c =
    "\x30\x44"
    "\x02\x20"
    "\xd9\xec\xef\xe8\x5f\xee\x3c\x59\x57\x8e\x5b\xab\xb3\x02\xe1\x42"
    "\x4b\x67\x2c\x0b\x26\xb6\x51\x2c\x3e\xfc\xc6\x49\xec\xfe\x89\xe5"
    "\x02\x20"
    "\x43\x45\xd0\xa5\xff\xe5\x13\x27\x26\xd0\xec\x37\xad\x24\x1e\x9a"
    "\x71\x9a\xa4\x89\xb0\x7e\x0f\xc4\xbb\x2d\x50\xd0\xe5\x7f\x7a\x68",
    .algo = PCE_SM2_VERIFY,
    .m =
    "\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00"
    "\x12\x34\x56\x78\x9a\xbc\xde\xf0\x12\x34\x56\x78\x9a\xbc\xde\xf0",
    },
    { /* From gmssl */
    .m_size = 112,
    .c_size = 220,
    .pubkey =
    "\xd7\x4e\xd1\x3e\x2d\xc9\x91\x14\x73\x16\x38\x5b\x67\x4b\xd5\x60"
    "\x01\xa6\x0f\x03\x9b\xfc\x01\x88\x6a\xeb\x52\xa3\x43\x0c\xdc\xbc"
    "\xbc\x01\xa4\x1e\x32\xce\x92\xb9\x4e\x50\x44\x2e\xb1\x5c\xd4\x24"
    "\xc1\x23\x7e\xc4\x2e\x44\x2c\x90\x95\x6a\x26\x46\x43\x93\x12\x26",
    .prikey = 
    "\x83\xdc\xa0\xad\xa3\xd7\x7e\xa4\xed\x20\x89\x56\x1d\xc3\x96\x37"
    "\x5e\xa9\xce\x50\x63\x29\xe4\x9c\x0d\xe4\x99\x49\x0a\xcd\x03\x78",
    .c =
    "\x30\x81\xd9\x02\x20\x0c\xa3\x62\x62\xe4\xcf\xda\x5b\xfc\x6d\x90"
    "\xe2\xc7\xa9\x49\x5b\x80\xcf\x20\xef\x9b\x4f\xff\xef\xa0\xae\x40"
    "\xbf\xe4\x68\x84\x8c\x02\x21\x00\x87\xc6\x20\xf0\x2f\xb9\xf0\x22"
    "\x17\x6b\x27\x50\x7d\xcd\x8c\x8d\x9b\xa6\xf3\x4d\xb1\xc9\x4a\x3a"
    "\xe0\x94\x41\xb2\x4c\x24\x00\x98\x04\x20\x4b\xc9\x6b\xe0\xf9\xdf"
    "\xc7\xe5\x57\xe9\x6b\x0d\xa2\xd7\x75\xf9\x14\x8e\xef\xdb\x1b\xcd"
    "\xf8\x18\xb0\x71\x7f\x3b\x92\xf3\xf9\xf3\x04\x70\x86\x7e\x7c\x9f"
    "\xff\xa2\x1b\xfa\xc1\xac\xbb\x0a\x5c\xe6\xc0\x51\x4a\x37\x33\x76"
    "\x4d\x51\x40\xfc\xb8\x20\x9d\x4f\xe3\x12\xe5\xfe\xa1\xc3\x59\x4c"
    "\xd4\x1f\xae\x92\xaa\x44\x26\x76\x17\x67\xce\xb0\x2e\x88\x17\x6c"
    "\x4c\xb5\x4f\x0d\x94\x96\x97\x5a\x8b\x17\x33\x36\x26\x06\x17\xd4"
    "\x4a\x36\x29\x3c\x46\x52\x54\x95\xbf\x9f\xe2\x55\xfc\x9e\x39\x65"
    "\xd8\x64\xe3\x8f\xe2\x97\xa7\xb8\x5b\xd4\xc3\x63\xdf\xdd\x01\x32"
    "\x9e\x07\xa3\xd2\xe5\xc4\x97\xbb\xb0\x95\x27\xa3",
    .algo = PCE_SM2_DEC,
    .m =
    "\x42\x47\x30\x77\x61\x77\x49\x42\x41\x51\x51\x67\x67\x39\x79\x67"
    "\x72\x61\x50\x58\x66\x71\x54\x74\x49\x49\x6c\x57\x0a\x48\x63\x4f"
    "\x57\x4e\x31\x36\x70\x7a\x6c\x42\x6a\x4b\x65\x53\x63\x44\x65\x53"
    "\x5a\x53\x51\x72\x4e\x41\x33\x69\x68\x52\x41\x4e\x43\x41\x41\x54"
    "\x58\x54\x74\x45\x2b\x4c\x63\x6d\x52\x46\x48\x4d\x57\x4f\x46\x74"
    "\x6e\x53\x39\x56\x67\x41\x61\x59\x50\x41\x35\x76\x38\x0a\x41\x59"
    "\x68\x71\x36\x31\x4b\x6a\x51\x77\x7a\x63\x76\x4c\x77\x42\x70\x42",
    },
    {
    .m_size = 220,
    .pubkey =
    "\xd7\x4e\xd1\x3e\x2d\xc9\x91\x14\x73\x16\x38\x5b\x67\x4b\xd5\x60"
    "\x01\xa6\x0f\x03\x9b\xfc\x01\x88\x6a\xeb\x52\xa3\x43\x0c\xdc\xbc"
    "\xbc\x01\xa4\x1e\x32\xce\x92\xb9\x4e\x50\x44\x2e\xb1\x5c\xd4\x24"
    "\xc1\x23\x7e\xc4\x2e\x44\x2c\x90\x95\x6a\x26\x46\x43\x93\x12\x26",
    .prikey = 
    "\x83\xdc\xa0\xad\xa3\xd7\x7e\xa4\xed\x20\x89\x56\x1d\xc3\x96\x37"
    "\x5e\xa9\xce\x50\x63\x29\xe4\x9c\x0d\xe4\x99\x49\x0a\xcd\x03\x78",
    .algo = PCE_SM2_ENC,
    .m =
    "\x30\x81\xd9\x02\x20\x0c\xa3\x62\x62\xe4\xcf\xda\x5b\xfc\x6d\x90"
    "\xe2\xc7\xa9\x49\x5b\x80\xcf\x20\xef\x9b\x4f\xff\xef\xa0\xae\x40"
    "\xbf\xe4\x68\x84\x8c\x02\x21\x00\x87\xc6\x20\xf0\x2f\xb9\xf0\x22"
    "\x17\x6b\x27\x50\x7d\xcd\x8c\x8d\x9b\xa6\xf3\x4d\xb1\xc9\x4a\x3a"
    "\xe0\x94\x41\xb2\x4c\x24\x00\x98\x04\x20\x4b\xc9\x6b\xe0\xf9\xdf"
    "\xc7\xe5\x57\xe9\x6b\x0d\xa2\xd7\x75\xf9\x14\x8e\xef\xdb\x1b\xcd"
    "\xf8\x18\xb0\x71\x7f\x3b\x92\xf3\xf9\xf3\x04\x70\x86\x7e\x7c\x9f"
    "\xff\xa2\x1b\xfa\xc1\xac\xbb\x0a\x5c\xe6\xc0\x51\x4a\x37\x33\x76"
    "\x4d\x51\x40\xfc\xb8\x20\x9d\x4f\xe3\x12\xe5\xfe\xa1\xc3\x59\x4c"
    "\xd4\x1f\xae\x92\xaa\x44\x26\x76\x17\x67\xce\xb0\x2e\x88\x17\x6c"
    "\x4c\xb5\x4f\x0d\x94\x96\x97\x5a\x8b\x17\x33\x36\x26\x06\x17\xd4"
    "\x4a\x36\x29\x3c\x46\x52\x54\x95\xbf\x9f\xe2\x55\xfc\x9e\x39\x65"
    "\xd8\x64\xe3\x8f\xe2\x97\xa7\xb8\x5b\xd4\xc3\x63\xdf\xdd\x01\x32"
    "\x9e\x07\xa3\xd2\xe5\xc4\x97\xbb\xb0\x95\x27\xa3",
    },
    { 
    .m_size = 32,
    .pubkey =
    "\xd7\x4e\xd1\x3e\x2d\xc9\x91\x14\x73\x16\x38\x5b\x67\x4b\xd5\x60"
    "\x01\xa6\x0f\x03\x9b\xfc\x01\x88\x6a\xeb\x52\xa3\x43\x0c\xdc\xbc"
    "\xbc\x01\xa4\x1e\x32\xce\x92\xb9\x4e\x50\x44\x2e\xb1\x5c\xd4\x24"
    "\xc1\x23\x7e\xc4\x2e\x44\x2c\x90\x95\x6a\x26\x46\x43\x93\x12\x26",
    .prikey = 
    "\x83\xdc\xa0\xad\xa3\xd7\x7e\xa4\xed\x20\x89\x56\x1d\xc3\x96\x37"
    "\x5e\xa9\xce\x50\x63\x29\xe4\x9c\x0d\xe4\x99\x49\x0a\xcd\x03\x78",
    .algo = PCE_SM2_SIGN,
    .m =
    "\x30\x81\xd9\x02\x20\x0c\xa3\x62\x62\xe4\xcf\xda\x5b\xfc\x6d\x90"
    "\xe2\xc7\xa9\x49\x5b\x80\xcf\x20\xef\x9b\x4f\xff\xef\xa0\xae\x40",
    },

    {
    .pubkey =
    "\xd7\x4e\xd1\x3e\x2d\xc9\x91\x14\x73\x16\x38\x5b\x67\x4b\xd5\x60"
    "\x01\xa6\x0f\x03\x9b\xfc\x01\x88\x6a\xeb\x52\xa3\x43\x0c\xdc\xbc"
    "\xbc\x01\xa4\x1e\x32\xce\x92\xb9\x4e\x50\x44\x2e\xb1\x5c\xd4\x24"
    "\xc1\x23\x7e\xc4\x2e\x44\x2c\x90\x95\x6a\x26\x46\x43\x93\x12\x26",
    .prikey = 
    "\x83\xdc\xa0\xad\xa3\xd7\x7e\xa4\xed\x20\x89\x56\x1d\xc3\x96\x37"
    "\x5e\xa9\xce\x50\x63\x29\xe4\x9c\x0d\xe4\x99\x49\x0a\xcd\x03\x78",
    .algo = PCE_SM2_PUBKEY,
    },

    {
    .m_size = 220,
    .algo = PCE_SM2_KEY,
    .m =
    "\x30\x81\xd9\x02\x20\x0c\xa3\x62\x62\xe4\xcf\xda\x5b\xfc\x6d\x90"
    "\xe2\xc7\xa9\x49\x5b\x80\xcf\x20\xef\x9b\x4f\xff\xef\xa0\xae\x40"
    "\xbf\xe4\x68\x84\x8c\x02\x21\x00\x87\xc6\x20\xf0\x2f\xb9\xf0\x22"
    "\x17\x6b\x27\x50\x7d\xcd\x8c\x8d\x9b\xa6\xf3\x4d\xb1\xc9\x4a\x3a"
    "\xe0\x94\x41\xb2\x4c\x24\x00\x98\x04\x20\x4b\xc9\x6b\xe0\xf9\xdf"
    "\xc7\xe5\x57\xe9\x6b\x0d\xa2\xd7\x75\xf9\x14\x8e\xef\xdb\x1b\xcd"
    "\xf8\x18\xb0\x71\x7f\x3b\x92\xf3\xf9\xf3\x04\x70\x86\x7e\x7c\x9f"
    "\xff\xa2\x1b\xfa\xc1\xac\xbb\x0a\x5c\xe6\xc0\x51\x4a\x37\x33\x76"
    "\x4d\x51\x40\xfc\xb8\x20\x9d\x4f\xe3\x12\xe5\xfe\xa1\xc3\x59\x4c"
    "\xd4\x1f\xae\x92\xaa\x44\x26\x76\x17\x67\xce\xb0\x2e\x88\x17\x6c"
    "\x4c\xb5\x4f\x0d\x94\x96\x97\x5a\x8b\x17\x33\x36\x26\x06\x17\xd4"
    "\x4a\x36\x29\x3c\x46\x52\x54\x95\xbf\x9f\xe2\x55\xfc\x9e\x39\x65"
    "\xd8\x64\xe3\x8f\xe2\x97\xa7\xb8\x5b\xd4\xc3\x63\xdf\xdd\x01\x32"
    "\x9e\x07\xa3\xd2\xe5\xc4\x97\xbb\xb0\x95\x27\xa3",
    }
};
#endif

#if 0
typedef struct {
    int alg;
    uint8_t *result;
    uint8_t *src ;
    uint8_t *privkey ;
    uint8_t *pubkey;

    uint8_t *peer_pub_key_addr;
    sm2_testvec_t *testvec;
}sm2_test_data_t;
#endif

static const char *test_sm2_curves_names[SM2_NUM] = {
    "sm2p256v1",
};
static const int test_sm2_curves_bits[SM2_NUM] = {
    256,
};
int sm2sign_doit[MAX_THREAD_NUM][SM2_NUM] = {0};
int sm2enc_doit[SM2_NUM] = {0};

static double sm2sign_results[MAX_THREAD_NUM][6];
static double sm2enc_results[SM2_NUM][6];


//static char *d_hex =
 //   "F4A115840CE610EAEBE6682230D072E88AE891CA803EBB75769A9300E8062742";
//static char *xP_hex =
//    "9C5DA2F1C38A3BB26334EA02690FF97E41C5DA5BD9C95C9E4FA80C9E7CE9422D";
//static char *yP_hex =
 //   "9299E518237A7E617F3C4547D98E4A9667F774CC67999003BFE4C27FA8D2DF22";
/* e = H(ZA||M)
 * ID = "ALICE123@YAHOO.COM" 414c494345313233405941484f4f2e434f4d
 * ZA = "C6BEEE2E0DCA43B03CAF0DB1CFD0985C217DB7872F1C10404D5AA7B0978F28DF"
 * M  = "message digest digest" 6d6573736167652064696765737420646967657374
 * e  = 9C06F28DE722B449DF3D664F7A64A239AF88A9651993CE1ECF25337178375E27
 */
//static char *e_hex =
    //"9C06F28DE722B449DF3D664F7A64A239AF88A9651993CE1ECF25337178375E27";

int numa_id = 0;


#define TEST_MAX_LENGTH 1024

static int init_sm2_test_data(sm2_test_data_t *test_data, uint16_t op_type)
{
    sm2_test_data_t *ctx = test_data;
    int ret = 0;
    if (!ctx) {
        return -1;
    }

    ctx->result = pce_alloc_mem(numa_node,TEST_MAX_LENGTH);
    if (NULL == ctx->result) {
        fprintf(stderr, "alloc mem from numa_id %d failed\n", numa_id);
        return -1;
    }

    memset(ctx->result, 0, TEST_MAX_LENGTH);

    ctx->src = pce_alloc_mem(numa_node,TEST_MAX_LENGTH);
    if (NULL == ctx->src) {
        fprintf(stderr, "alloc mem from numa_id %d failed\n", numa_id);
        return -1;
    }

    memset(ctx->src, 0, TEST_MAX_LENGTH);

    //strcpy(ctx->algo_name, args->algo_name);

    if(op_type == PCE_SM2_KEY){
             ctx->genkey.priv_key_addr = (uint64_t)ctx->src;
            ctx->genkey.pub_key_addr = (uint64_t)ctx->result;
            ctx->alg = PCE_SM2_KEY;
        }else if(op_type == PCE_SM2_ENC){
            const uint8_t *orig_msg = "\x42\x47\x30\x77\x61\x77\x49\x42\x41\x51\x51\x67\x67\x39\x79\x67"
                            "\x72\x61\x50\x58\x66\x71\x54\x74\x49\x49\x6c\x57\x0a\x48\x63\x4f"
                            "\x57\x4e\x31\x36\x70\x7a\x6c\x42\x6a\x4b\x65\x53\x63\x44\x65\x53"
                            "\x5a\x53\x51\x72\x4e\x41\x33\x69\x68\x52\x41\x4e\x43\x41\x41\x54"
                            "\x58\x54\x74\x45\x2b\x4c\x63\x6d\x52\x46\x48\x4d\x57\x4f\x46\x74"
                            "\x6e\x53\x39\x56\x67\x41\x61\x59\x50\x41\x35\x76\x38\x0a\x41\x59"
                            "\x68\x71\x36\x31\x4b\x6a\x51\x77\x7a\x63\x76\x4c\x77\x42\x70\x42";
            uint32_t orig_msg_len = 112;
            const uint8_t *pubkey =
                                "\xd7\x4e\xd1\x3e\x2d\xc9\x91\x14\x73\x16\x38\x5b\x67\x4b\xd5\x60"
                                "\x01\xa6\x0f\x03\x9b\xfc\x01\x88\x6a\xeb\x52\xa3\x43\x0c\xdc\xbc"
                                "\xbc\x01\xa4\x1e\x32\xce\x92\xb9\x4e\x50\x44\x2e\xb1\x5c\xd4\x24"
                                "\xc1\x23\x7e\xc4\x2e\x44\x2c\x90\x95\x6a\x26\x46\x43\x93\x12\x26";
            ctx->encrypt.msg_length = orig_msg_len;

            ctx->encrypt.msg_addr = (uint64_t)ctx->src+80;
            ctx->encrypt.pub_key_addr = (uint64_t)ctx->src;
            ctx->encrypt.result_addr = (uint64_t)ctx->result;
            memcpy(ctx->src, pubkey, 65);
            memcpy(ctx->src+80, orig_msg, orig_msg_len);
            ctx->alg = PCE_SM2_ENC;
            }
        else if(op_type == PCE_SM2_DEC){
            uint32_t cipher_len = 220;
            uint8_t *cipher = "\x30\x81\xd9\x02\x20\x0c\xa3\x62\x62\xe4\xcf\xda\x5b\xfc\x6d\x90"
                            "\xe2\xc7\xa9\x49\x5b\x80\xcf\x20\xef\x9b\x4f\xff\xef\xa0\xae\x40"
                            "\xbf\xe4\x68\x84\x8c\x02\x21\x00\x87\xc6\x20\xf0\x2f\xb9\xf0\x22"
                            "\x17\x6b\x27\x50\x7d\xcd\x8c\x8d\x9b\xa6\xf3\x4d\xb1\xc9\x4a\x3a"
                            "\xe0\x94\x41\xb2\x4c\x24\x00\x98\x04\x20\x4b\xc9\x6b\xe0\xf9\xdf"
                            "\xc7\xe5\x57\xe9\x6b\x0d\xa2\xd7\x75\xf9\x14\x8e\xef\xdb\x1b\xcd"
                            "\xf8\x18\xb0\x71\x7f\x3b\x92\xf3\xf9\xf3\x04\x70\x86\x7e\x7c\x9f"
                            "\xff\xa2\x1b\xfa\xc1\xac\xbb\x0a\x5c\xe6\xc0\x51\x4a\x37\x33\x76"
                            "\x4d\x51\x40\xfc\xb8\x20\x9d\x4f\xe3\x12\xe5\xfe\xa1\xc3\x59\x4c"
                            "\xd4\x1f\xae\x92\xaa\x44\x26\x76\x17\x67\xce\xb0\x2e\x88\x17\x6c"
                            "\x4c\xb5\x4f\x0d\x94\x96\x97\x5a\x8b\x17\x33\x36\x26\x06\x17\xd4"
                            "\x4a\x36\x29\x3c\x46\x52\x54\x95\xbf\x9f\xe2\x55\xfc\x9e\x39\x65"
                            "\xd8\x64\xe3\x8f\xe2\x97\xa7\xb8\x5b\xd4\xc3\x63\xdf\xdd\x01\x32"
                            "\x9e\x07\xa3\xd2\xe5\xc4\x97\xbb\xb0\x95\x27\xa3";
            const uint8_t *prikey = "\x83\xdc\xa0\xad\xa3\xd7\x7e\xa4\xed\x20\x89\x56\x1d\xc3\x96\x37"
                                "\x5e\xa9\xce\x50\x63\x29\xe4\x9c\x0d\xe4\x99\x49\x0a\xcd\x03\x78";

            memcpy(ctx->src, prikey, 32);
            pce_sm2decrypt_decode(cipher, cipher_len, ctx->src + 80, &ctx->decrypt.cipher_length);
            ctx->decrypt.cipher_addr = (uint64_t)ctx->src+80;
            ctx->decrypt.priv_key_addr = (uint64_t)ctx->src;
            ctx->decrypt.result_addr = (uint64_t)ctx->result;
            ctx->alg = PCE_SM2_DEC;
            }
        else if(op_type ==PCE_SM2_SIGN){
            uint8_t e[32] = "\x30\x81\xd9\x02\x20\x0c\xa3\x62\x62\xe4\xcf\xda\x5b\xfc\x6d\x90"
                    "\xe2\xc7\xa9\x49\x5b\x80\xcf\x20\xef\x9b\x4f\xff\xef\xa0\xae\x40";
            uint8_t *prikey = "\x83\xdc\xa0\xad\xa3\xd7\x7e\xa4\xed\x20\x89\x56\x1d\xc3\x96\x37"
                          "\x5e\xa9\xce\x50\x63\x29\xe4\x9c\x0d\xe4\x99\x49\x0a\xcd\x03\x78";
        
            memcpy(ctx->src, prikey, 32);
            memcpy(ctx->src+64, e, 32);
            ctx->sign.e_addr = (uint64_t)ctx->src+64;
            ctx->sign.priv_key_addr = (uint64_t)ctx->src;
            ctx->sign.result_addr = (uint64_t)ctx->result;
            ctx->alg = PCE_SM2_SIGN;
            }
        else if(op_type ==PCE_SM2_VERIFY){
            uint8_t e[32] = "\x47\xa7\xbf\xd3\xda\xc4\x79\xee\xda\x8b\x4f\xe8\x40\x94\xd4\x32"
            "\x8f\xf1\xcd\x68\x4d\xbd\x9b\x1d\xe0\xd8\x9a\x5d\xad\x85\x47\x5c";
            uint8_t *pubkey = "\x8e\xa0\x33\x69\x91\x7e\x3d\xec\xad\x8e\xf0\x45\x5e\x13\x3e\x68"
            "\x5b\x8c\xab\x5c\xc6\xc8\x50\xdf\x91\x00\xe0\x24\x73\x4d\x31\xf2"
            "\x2e\xc0\xd5\x6b\xee\xda\x98\x93\xec\xd8\x36\xaa\xb9\xcf\x63\x82"
            "\xef\xa7\x1a\x03\xed\x16\xba\x74\xb8\x8b\xf9\xe5\x70\x39\xa4\x70";
            uint8_t *sig = "\x30\x45"
                    "\x02\x20"
                    "\x70\xab\xb6\x7d\xd6\x54\x80\x64\x42\x7e\x2d\x05\x08\x36\xc9\x96"
                    "\x25\xc2\xbb\xff\x08\xe5\x43\x15\x5e\xf3\x06\xd9\x2b\x2f\x0a\x9f"
                    "\x02\x21"
                    "\x00"
                    "\xbf\x21\x5f\x7e\x5d\x3f\x1a\x4d\x8f\x84\xc2\xe9\xa6\x4c\xa4\x18"
                    "\xb2\xb8\x46\xf4\x32\x96\xfa\x57\xc6\x29\xd4\x89\xae\xcc\xda\xdb";

            uint32_t siglen = 71;
            memcpy(ctx->src, pubkey, 65);
            memcpy(ctx->src+80, e, 32);
            pce_ecsign_decode(PCE_SM2_CURVE_P256, sig, siglen, ctx->src+80+32);
            ctx->verify.e_signature_addr = (uint64_t)ctx->src+80;
            ctx->verify.pub_key_addr = (uint64_t)ctx->src;
            ctx->alg = PCE_SM2_VERIFY;
            }
        else if(op_type == PCE_SM2_EXCHANGE){
            uint32_t c_len = 128;
            uint8_t *Aprikey = "\x5d\xfb\xc2\x8c\xe0\x8f\x54\x13\xf0\x56\xf4\x26\xd5\x2b\x76"
                "\xce\xdf\x45\xf2\xfb\xc4\x76\x22\xfd\x03\x0e\x76\xb3\xbf\xdf"
                "\x76\xb5";
            uint8_t *apubkey = 
                "\x61\x24\xb7\x95\xf2\xc4\x5f\xa9\xe6\x04\x25\xe0\xbe\x34"
                "\xfa\x3b\x4b\x1c\x9e\xe2\x9b\x75\xb6\xa7\x2a\xef\xc7\xaa\xd5"
                "\xc3\x25\x28\xee\x0a\x93\x33\xa6\x3b\xfd\x3b\xef\x32\xff\x33"
                "\x4d\x9f\x85\xbb\x99\xd5\x3e\x99\xc1\xf2\xfc\x17\xb5\x07\x73"
                "\x64\xed\x63\x2f\x64";
            uint8_t *aprikey = 
                "\x83\x13\x7c\x40\x0b\xef\xf2\x4d\x1e\x8c\x02\xb5\x5b\xd1\xb1"
                "\x69\x01\x74\x1d\x79\x5d\x70\x02\x25\x6a\xd3\xaf\x3c\x8a\x43"
                "\xe4\x6e";
            uint8_t *Bpubkey = 
                "\x02\x36\x14\xa8\x8e\x5d\x22\xb2\x39\x83\x7c\x8b\x8c\x5d"
                "\xf9\xe2\xa0\xc5\xe2\x90\x2d\x86\xd5\x93\xb5\xb8\x44\x26\xd3"
                "\x6e\xed\x7b\xcc\xcc\x31\xdb\x97\x34\xad\xe2\x64\xf0\x18\x9b"
                "\xd1\x6e\xc2\x18\xbe\xf7\x26\x1f\xdb\x6b\x58\x5c\x4c\x6c\x9c"
                "\x14\x23\xb4\x10\xca";
            uint8_t *bpubkey = 
                "\x8d\xdf\x78\x64\x1f\xa4\x8d\xf6\xea\x84\xd5\x7a\x2e\x96"
                "\x4b\xa1\x13\x54\xa1\xa9\x3b\x94\x09\x61\xcd\x5d\xf8\x3b\x89"
                "\x1c\xa3\x6d\xd6\xdb\x53\xcb\x59\xd6\xa2\x6d\xbd\xe0\xcf\xd9"
                "\xe0\xb6\x56\x33\x2e\x5d\xf0\xeb\x57\x6a\xa7\x7b\xae\x2e\x38"
                "\xba\x34\x0a\x7d\xed";

            uint8_t *ZA = 
                "\x7a\x1d\xd2\x04\x0d\xbd\xbc\xba\xae\xa0\xce\xe3\x42\x4a\x92\xfb"
                "\x3a\xd2\x29\x76\x45\xfa\xaa\xe9\x51\x72\xa8\x2f\x83\xb4\x8d\x6d";
            uint8_t *ZB = 
                "\x66\x31\x6d\x22\x9e\x63\x5c\x4e\x65\x2f\xde\x44\xf7\xae\x1a\xab"
                "\xed\x5b\x7b\x7c\xb7\x59\x1b\x7b\xab\x5b\x0a\x47\xb1\xf7\x8d\x11";

            memcpy(ctx->src, Aprikey, 32);
            //memcpy(src + 32, testvec->Apubkey, 64);
            memcpy(ctx->src + 96, aprikey, 32);
            memcpy(ctx->src + 128, apubkey, 64);
            memcpy(ctx->src + 192, Bpubkey, 64);
            memcpy(ctx->src + 256, bpubkey, 64);
            memcpy(ctx->src + 320, ZA, 32);
            memcpy(ctx->src + 352, ZB, 32);

            ctx->exchange.role = 0;
            ctx->exchange.key_length = c_len;
            ctx->exchange.key_z_addr = (uint64_t)ctx->src;
            ctx->exchange.result_addr = (uint64_t)ctx->result;
            ctx->alg = PCE_SM2_EXCHANGE;
            }
        else{
            fprintf(stderr,"unsupported sm2 op_type in func:%s\n",__func__);
            //free_data_sm2(loopargs);
            ret = -1;
        
            
    }
    return ret;
    
}


static void free_sm2_test_data(sm2_test_data_t *test_data)
{
    if(test_data != NULL){
        pce_free_mem(test_data->result);
        pce_free_mem(test_data->src);
        //free(test_data);
    }
}


void fill_op_data_sm2(pce_op_data_t *op_data, sm2_test_data_t *test_data)
{
    sm2_test_data_t *ctx = test_data;
    if (!ctx) {
        return;
    }

    op_data->sm2.alg = ctx->alg;
   
    switch (ctx->alg)
    {
    case PCE_SM2_KEY:
        op_data->sm2.genkey.priv_key_addr = ctx->genkey.priv_key_addr;
        op_data->sm2.genkey.pub_key_addr = ctx->genkey.pub_key_addr;
        break;
    case PCE_SM2_SIGN:
        op_data->sm2.sign.e_addr = ctx->sign.e_addr;
        op_data->sm2.sign.priv_key_addr = ctx->sign.priv_key_addr;
        op_data->sm2.sign.result_addr = ctx->sign.result_addr;
        break;
    case PCE_SM2_VERIFY:
        op_data->sm2.verify.e_signature_addr = ctx->verify.e_signature_addr;
        op_data->sm2.verify.pub_key_addr =  ctx->verify.pub_key_addr;

        /* code */
        break;
    case PCE_SM2_EXCHANGE:
        op_data->sm2.exchange.role = ctx->exchange.role;
        op_data->sm2.exchange.key_length = ctx->exchange.key_length;
        op_data->sm2.exchange.key_z_addr = ctx->exchange.key_z_addr;
        op_data->sm2.exchange.result_addr = ctx->exchange.result_addr;
        /* code */
        break;
    case PCE_SM2_ENC:
        op_data->sm2.encrypt.msg_length = ctx->encrypt.msg_length;
        op_data->sm2.encrypt.msg_addr = ctx->encrypt.msg_addr;
        op_data->sm2.encrypt.pub_key_addr = ctx->encrypt.pub_key_addr;
        op_data->sm2.encrypt.result_addr = ctx->encrypt.result_addr;
        /* code */
        break;
    case PCE_SM2_DEC:
        op_data->sm2.decrypt.cipher_addr = ctx->decrypt.cipher_addr;
        op_data->sm2.decrypt.priv_key_addr = ctx->decrypt.priv_key_addr;
        op_data->sm2.decrypt.result_addr = ctx->decrypt.result_addr;
        op_data->sm2.decrypt.cipher_length = ctx->decrypt.cipher_length;
        /* code */
        break;
    default:
        break;
    }
}

#if 0

static int init_sm2_test_data(sm2_test_data_t *test_data, enum pce_alg algo)
{
    int i;
    //查找算法
    test_data->testvec = NULL;
    for (i = 0; i < ARRAY_SIZE(sm2_tv_template); i++){
        if(sm2_tv_template[i].algo == algo ){
            test_data->testvec = &sm2_tv_template[i];
            break;
        }
    }
    
    test_data->result = pce_alloc_mem(numa_node, 0x10000);
    if (NULL == test_data->result) {
        goto out;
    }
    memset(test_data->result, 0, 0x10000);
        
    test_data->src = pce_alloc_mem(numa_node,0x10000);
    if (NULL == test_data->src) {
        goto out;
    }
    memset(test_data->src, 0, 0x10000);
    
    test_data->privkey = pce_alloc_mem(numa_node,0x10000);
    if (NULL == test_data->privkey) {
        goto out;
    }
    memset(test_data->privkey, 0, 0x10000);
    
    test_data->pubkey = pce_alloc_mem(numa_node,0x10000);
    if (NULL == test_data->pubkey) {
        goto out;
    }
    memset(test_data->pubkey, 0, 0x10000);
 
    out:
    return 0;
}


static void free_sm2_test_data(sm2_test_data_t *test_data)
{
    
    if (test_data->pubkey)
        pce_free_mem(test_data->pubkey);

    if (test_data->privkey)
        pce_free_mem(test_data->privkey);

    if (test_data->result)
        pce_free_mem(test_data->result);
    
    /*if (test_data->peer_pub_key_addr)
        pce_free_mem(test_data->peer_pub_key_addr);*/

    
    if (test_data->src)
        pce_free_mem(test_data->src);
        
}

void fill_op_data_sm2(pce_op_data_t *op_data, sm2_test_data_t *test_data)
{
    sm2_test_data_t *ctx = test_data;
    if (!ctx) {
        return;
    }
    sm2_testvec_t *testvec = test_data->testvec;
    uint8_t *src = test_data->src;
    uint8_t *result = test_data->result;
    uint8_t *privkey = test_data->privkey;
    uint8_t *pubkey = test_data->pubkey;

    
    op_data->sm2.alg = testvec->algo;
    
     switch (testvec->algo)
        {
        case PCE_SM2_SIGN:
            {
                memcpy(test_data->src, testvec->m, testvec->m_size);
                memcpy(privkey, testvec->prikey, 32);
                //printf("src addr:%lx\n",src);
                op_data->sm2.sign.e_addr = (uint64_t)test_data->src;
                //printf("priv addr:%lx\n",privkey);
                op_data->sm2.sign.priv_key_addr = (uint64_t)privkey;
                //printf("result addr:%lx\n",result);
                op_data->sm2.sign.result_addr = (uint64_t)result;
            }
            break;
        
        case PCE_SM2_VERIFY:
            {
                memcpy(src, testvec->m, testvec->m_size);
                if (pce_ecsign_decode(PCE_SM2_CURVE_P256, testvec->c, testvec->c_size, src + testvec->m_size))
                    break;
                memcpy(pubkey, testvec->pubkey, 64);
                op_data->sm2.verify.pub_key_addr = (uint64_t)pubkey;
                op_data->sm2.verify.e_signature_addr = (uint64_t)src;
            }
            break; 
        case PCE_SM2_EXCHANGE:
            {
               // DO IN sm2_exchange_test

               ;
            }
            break;
        case PCE_SM2_ENC:
            {
                memcpy(src, testvec->m, testvec->m_size);
                memcpy(pubkey, testvec->pubkey, 64);
                op_data->sm2.encrypt.msg_length = testvec->m_size;
                op_data->sm2.encrypt.msg_addr = (uint64_t)src;
                op_data->sm2.encrypt.pub_key_addr = (uint64_t)pubkey;
                op_data->sm2.encrypt.result_addr = (uint64_t)result;
            }
            break;
        case PCE_SM2_DEC:
            {

                if (pce_sm2decrypt_decode(testvec->c, testvec->c_size, src, &op_data->sm2.decrypt.cipher_length))
                    break;
                memcpy(privkey, testvec->prikey, 32);
                op_data->sm2.decrypt.cipher_addr = (uint64_t)src;
                op_data->sm2.decrypt.priv_key_addr = (uint64_t)privkey;
                op_data->sm2.decrypt.result_addr = (uint64_t)result;
            }
            break;
        default:
            break;
        }
}
    
#endif


// 0 fail  1 success
static int test_sm2_loop(void *args)
{
    loopargs_t *loopargs = args;
    if(args == NULL){
        return 0;
    }
    int i;
    int batch = 1;
    sm2_test_data_t *data = (sm2_test_data_t *)loopargs->asym_data;

    int enqueued_count = 0;
    pce_op_data_t *sm2_datas = NULL;
    perf_ring *ring = loopargs->ring;
    sm2_datas = loopargs->requests;
    //pce_queue_handle *queue = loopargs->queue_handle;
    
    for(i = 0; i < batch; i++){
        fill_op_data_sm2(&sm2_datas[i], data);
            
        SET_CALLBACK_INIT();
        SET_CALLBACK_ALGOINDEX(loopargs->algo_index);
        SET_CALLBACK_TEST_NUM(loopargs->testnum);
        SET_CALLBACK_THREAD_ID(loopargs->thread_id);
        sm2_datas[i].sm2.tag = (uint64_t) (callback);
        //printf("sm2_tag:%lx\n",callback);
    
    }
    enqueued_count = mp_enqueue(ring,&sm2_datas, batch);//入队一个,此处队列句柄来源错误
    //enqueued_count = pce_enqueue(queue,&sm2_datas, batch);//入队一个,此处队列句柄来源错误
    return 1;
    if (0 == enqueued_count) {
         goto out;
    }
    out:

    return 1;
    
}



/**
 *
 *@ Description: 根据输入的算法名，确认是否执行相关算法， 并自行设置标记
 *
 *
 *@ return 0: 匹配到执行算法，不用继续验证 其他：没有匹配
 */
int test_hit_for_sm2(const char *algo_name)
{
    /*int ret = -1;

    int i;
    if (!strcmp(algo_name, "sm2")) {
    for (i = 0; i < SM2_NUM; i++) {
        sm2sign_doit[i] = sm2enc_doit[i] = 1;
    }

    ret = 0;
    }

    if (strcmp(algo_name, "sm2sign") == 0) {
    for (i = 0; i < SM2_NUM; i++)
        sm2sign_doit[i] = 1;

    ret = 0;
    }

    if (strcmp(algo_name, "sm2enc") == 0) {
    for (i = 0; i < SM2_NUM; i++)
        sm2enc_doit[i] = 1;

    ret = 0;
    }

    return ret;*/
    return 0;
}

void test_perf_for_sm2(loopargs_t *loopargs)
{
    long count = 0;
    double d;
    uint16_t testnum = 0;
    loopargs->batch = cmd_option.batch;
    uint16_t thread_id = loopargs->thread_id;
    algo_data_t *algo_data = (algo_data_t*)get_hash_map(g_algo_hash_table, loopargs->algo_name);
    sem_t *start_sem = GET_START_SEM();
    uint16_t algo_index = algo_data->algo_index;
    sm2_test_data_t *sm2_data = malloc(sizeof(sm2_test_data_t) * 2);
    uint16_t sm2_operations[] = {PCE_SM2_SIGN, PCE_SM2_VERIFY, PCE_SM2_KEY, 0 };
    char *sm2_ops[]={"sign","verify","genkey",NULL};
    loopargs->algo_index = algo_index;

    show_results_funcs[thread_id] = show_results_for_sm2;
    
    for (testnum = 0; sm2_operations[testnum] != 0; testnum++) {
        //if (!sm2sign_doit[testnum]) {
        //  continue;
        //}
    
        // SIGN性能测试
        memset(sm2_data, 0, sizeof(sm2_test_data_t));
        init_sm2_test_data(sm2_data,sm2_operations[testnum]);
        loopargs->asym_data = sm2_data;
        
        pkey_print_message(sm2_ops[testnum], "sm2", 0, test_sm2_curves_bits[testnum],
                   cmd_option.duration);
        
        loopargs->testnum = testnum;
        sem_post(start_sem);
        gettimeofday(&tv,NULL); 
        count = run_benchmark(test_sm2_loop, loopargs);
        gettimeofday(&tv1,NULL);
        
        //由于sm2即使算法成功也没有将tag带回，所以只能使用result的[0][0][0]成员进行计数！！
        
        d = (tv1.tv_usec-tv.tv_usec)/(100000.0)+((tv1.tv_sec-tv.tv_sec));
        count = results[thread_id][0];
        fprintf(stderr,
            mr ? "+R7:%ld:%d:%.2f\n"
               : "%ld %d bit SM2 signs in %.2fs \n",
            count, test_sm2_curves_bits[testnum], d);
        sm2sign_results[thread_id][testnum] = d / (double)count; // 每次签名运算耗时
        free_sm2_test_data(sm2_data);
        }
    
    free(sm2_data);
}


/**
 *
 *@ Description: 输出sm2算法的执行结果
 *
 * 示例：
 *
 *  Doing 256 bit sign sm2's for 2s: 31593 256 bit SM2 signs in 1.97s
Doing 256 bit verify sm2's for 2s: 5882 256 bit SM2 verify in 2.00s
                  sign    verify    sign/s verify/s
 256 bit sm2 (sm2p256v1)   0.0001s   0.0003s  16037.1   2941.0
 *
 * +F6:0:256:0.000063:0.000345 // +F6表示类型， 0：位数索引，位数，签名耗时，
验签耗时
 *@ return void
 */
void show_results_for_sm2(uint16_t thread_id)
{
    int testnum = 1;
    int k,i;
    char *sm2_ops[]={"sign","verify","genkey",NULL};
    for (k = 0; k < SM2_NUM; k++) {
        //if (!sm2sign_doit[k])
            // continue;
        if (testnum && !mr) {
            printf("%25s"," ");
            for(i = 0;sm2_ops[i]!=NULL;i++){
                printf("    %s",sm2_ops[i]);
            }
            for(i = 0;sm2_ops[i]!=NULL;i++){
                printf("  %s/s",sm2_ops[i]);
            }
            printf("\n");
            testnum = 0;
        }

        if (mr)
            printf("+F6:%u:%u:%f:%f\n", k, test_sm2_curves_bits[k],
            sm2sign_results[thread_id][0], sm2sign_results[thread_id][1]);
        else{
            printf("%4u bit sm2 (%s)",test_sm2_curves_bits[k], test_sm2_curves_names[k]);
            for(i = 0;sm2_ops[i]!=NULL;i++){
                printf(" %8.5fs",sm2sign_results[thread_id][i]);
            }
            for(i = 0;sm2_ops[i]!=NULL;i++){
                printf(" %8.2f",1.0 / sm2sign_results[thread_id][i]);
            }
            printf("\n");
        }
    }

}

/**
 *
 *@ Description: 解析不同进程的输出，并汇总计算平均每个运算的耗时
        F6: 签名验签  F7:加密
 *@ buf:       [in] 输出内容
 *@ n:         [in] 进程号
 *@ return 0:已处理  其他：未处理
 */
int do_multi_buf_sm2(char *buf, int n)
{
    int ret = -1;

    char *p;
    static char sep[] = ":";
    int k;
    double d;

    if (strncmp(buf, "+F6:", 4) == 0) {
    p = buf + 4;
    k = atoi(sstrsep(&p, sep));
    sstrsep(&p, sep);

    d = atof(sstrsep(&p, sep));
    if (n)
        sm2sign_results[k][0] = 1 / (1 / sm2sign_results[k][0] + 1 / d);
    else
        sm2sign_results[k][0] = d;

    d = atof(sstrsep(&p, sep));
    if (n)
        sm2sign_results[k][1] = 1 / (1 / sm2sign_results[k][1] + 1 / d);
    else
        sm2sign_results[k][1] = d;
    ret = 0;
    } else if (strncmp(buf, "+F7:", 4) == 0) {
    p = buf + 4;
    k = atoi(sstrsep(&p, sep));
    sstrsep(&p, sep);

    d = atof(sstrsep(&p, sep));
    if (n)
        sm2enc_results[k][0] = 1 / (1 / sm2enc_results[k][0] + 1 / d);
    else
        sm2enc_results[k][0] = d;

    d = atof(sstrsep(&p, sep));
    if (n)
        sm2enc_results[k][1] = 1 / (1 / sm2enc_results[k][1] + 1 / d);
    else
        sm2enc_results[k][1] = d;

    ret = 0;
    }

    return ret;
}

