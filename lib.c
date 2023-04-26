#include "lib.h"

int hexchar2int(unsigned char c)
{
    switch (c) {
    case '0':
        return 0;
    case '1':
        return 1;
    case '2':
        return 2;
    case '3':
        return 3;
    case '4':
        return 4;
    case '5':
        return 5;
    case '6':
        return 6;
    case '7':
        return 7;
    case '8':
        return 8;
    case '9':
        return 9;
    case 'a':
    case 'A':
        return 0x0A;
    case 'b':
    case 'B':
        return 0x0B;
    case 'c':
    case 'C':
        return 0x0C;
    case 'd':
    case 'D':
        return 0x0D;
    case 'e':
    case 'E':
        return 0x0E;
    case 'f':
    case 'F':
        return 0x0F;
    }
    return -1;
}

char *hexchar2bin(u8 *hex, u32 *len)
{
    u8 cl, ch, *p, *q, *hex_buf;
    int chi, cli;
    int hex_len;

    hex_len = strlen((char *)hex);
    *len = hex_len >> 1;
    if (hex_len & 1)
        return NULL;
    if (!(hex_buf = malloc(*len)))
        return NULL;

    for (p = hex, q = hex_buf; *p;) {
        ch = *p++;
        cl = *p++;
        chi = hexchar2int(ch);
        cli = hexchar2int(cl);
        if (chi < 0 || cli < 0) {
            free(q);
            q = NULL;
            *len = 0;
            return NULL;
        }
        *q++ = (u8)((chi << 4) | cli);
    }

    return (char*)hex_buf;
}

char *bin2hexchar(unsigned char *md, u32 len)
{
    u32 i;
    char *buf = (char *)malloc(len * 2 + 1);
    char *p = NULL;

    for (i = 0, p = buf; i < len; i++, p += 2) {
        sprintf(p, "%02x", md[i]);
    }
    *(p + 2) = '\0';
    return (buf);
}
