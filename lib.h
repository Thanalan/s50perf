#ifndef __THIRD_LIB_H__
#define __THIRD_LIB_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char u8;
typedef unsigned int u32;

char *bin2hexchar(unsigned char *md, u32 len);

char *hexchar2bin(u8 *hex, u32 *len);
#endif
