#include "sm3.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <pacc/sm3.h>
uint64_t local_to_be(uint64_t data) {
#ifdef SM3_BIG_ENDIAN
    return data;
#else
    uint64_t ret;
    ret = (data >> 56) |
          ((data<<40) & 0x00FF000000000000UL) |
          ((data<<24) & 0x0000FF0000000000UL) |
          ((data<<8) & 0x000000FF00000000UL) |
          ((data>>8) & 0x00000000FF000000UL) |
          ((data>>24) & 0x0000000000FF0000UL) |
          ((data>>40) & 0x000000000000FF00UL) |
          (data << 56);
    return ret;
#endif // SM3_BIG_ENDIAN
}

uint32_t local_to_be32(uint32_t data) {
#ifdef SM3_BIG_ENDIAN
    return data;
#else
    uint32_t ret;
    ret = (data >> 24) |
          ((data<<8) & 0x00FF0000) |
          ((data>>8) & 0x0000FF00) |
          (data << 24);
    return ret;
#endif // SM3_BIG_ENDIAN
}

/*
 * Most machines that sm3sum intends to run on is little endian
 * However to be secure, check if we are wrong
 */
bool endian_check() {
    uint32_t n = 1;
    // little endian if true
    if(*(char *)&n == 1) {
        return true;
    } else {
        return false;
    }   
}

uint8_t V[32];
/*
 * There can be re-run, V should be able to be reset
 */
void V_init() {
    V[0] = local_to_be32(IV0);
    V[1] = local_to_be32(IV1);
    V[2] = local_to_be32(IV2);
    V[3] = local_to_be32(IV3);
    V[4] = local_to_be32(IV4);
    V[5] = local_to_be32(IV5);
    V[6] = local_to_be32(IV6);
    V[7] = local_to_be32(IV7);
}

void print_buf(uint8_t *buf, uint32_t len)
{
    uint32_t i;
    for (i = 0; i < len; i += 16) {
        printf("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x""",
               buf[i + 0], buf[i + 1], buf[i + 2], buf[i + 3], buf[i + 4],
               buf[i + 5], buf[i + 6], buf[i + 7], buf[i + 8], buf[i + 9],
               buf[i + 10], buf[i + 11], buf[i + 12], buf[i + 13], buf[i + 14],
               buf[i + 15]);
    }
}


extern sm3_arguments sm3_args;
/*
 * function: print the sm3 result
 */
void sm3_print(char *file_name) {
    if (sm3_args.bsd_tag) {
        printf("SM3 (%s) = ", file_name);
    }
    print_buf(V,32);
    if (!sm3_args.bsd_tag) {
        printf(" %s", file_name);
    }
    printf("\n");
}

/* 
 * buf: buffer that contains content
 * bsize: buffer size in BITS
 * function: main function of sm3 algorithm
 */
void sm3(uint8_t *buf, size_t *bsize) {
    //sm3_padding(buf, bsize, *bsize);
    struct pacc_sm3_context ctx;
    pacc_sm3_init(&ctx);
    //assert(*bsize % BLOCK_SIZE == 0); // must have been padded
    pacc_sm3_update(&ctx, buf, (*bsize)/8);
    pacc_sm3_final(&ctx, V);

}

