#include <stdint.h>
#include <unistd.h>


#include "command.h"
#include "lib.h"
#include "ecc.h"


typedef struct {
    const unsigned char *pubkey;
    const unsigned char *prikey;
    const unsigned char *m;
    unsigned char *c;
    unsigned int m_size;
    unsigned int c_size;
    unsigned int pubk_size;
    int curve_type;
    int algo;
}ecdsa_testvec_t;

static ecdsa_testvec_t ecdsa_tv_template[] = {
{
    .pubk_size = 48,
    .m_size = 20,
    .c_size = 55,
    .curve_type = PCE_ECC_CURVE_SECP192R1,
    .algo = PCE_ECDSA_VERIFY,
    .pubkey =
    "\xf7\x46\xf8\x2f\x15\xf6\x22\x8e\xd7\x57\x4f\xcc\xe7\xbb\xc1"
    "\xd4\x09\x73\xcf\xea\xd0\x15\x07\x3d\xa5\x8a\x8a\x95\x43\xe4\x68"
    "\xea\xc6\x25\xc1\xc1\x01\x25\x4c\x7e\xc3\x3c\xa6\x04\x0a\xe7\x08"
    "\x98",
    .m =
    "\xcd\xb9\xd2\x1c\xb7\x6f\xcd\x44\xb3\xfd\x63\xea\xa3\x66\x7f\xae"
    "\x63\x85\xe7\x82",
    .c =
    "\x30\x35\x02\x19\x00\xba\xe5\x93\x83\x6e\xb6\x3b\x63\xa0\x27\x91"
    "\xc6\xf6\x7f\xc3\x09\xad\x59\xad\x88\x27\xd6\x92\x6b\x02\x18\x10"
    "\x68\x01\x9d\xba\xce\x83\x08\xef\x95\x52\x7b\xa0\x0f\xe4\x18\x86"
    "\x80\x6f\xa5\x79\x77\xda\xd0",
    }, {
    .pubk_size = 48,
    .m_size = 28,
    .c_size = 54,
    .curve_type = PCE_ECC_CURVE_SECP192R1,
    .algo = PCE_ECDSA_VERIFY,
    .pubkey =
    "\xb6\x4b\xb1\xd1\xac\xba\x24\x8f\x65\xb2\x60\x00\x90\xbf\xbd"
    "\x78\x05\x73\xe9\x79\x1d\x6f\x7c\x0b\xd2\xc3\x93\xa7\x28\xe1\x75"
    "\xf7\xd5\x95\x1d\x28\x10\xc0\x75\x50\x5c\x1a\x4f\x3f\x8f\xa5\xee"
    "\xa3",
    .m =
    "\x8d\xd6\xb8\x3e\xe5\xff\x23\xf6\x25\xa2\x43\x42\x74\x45\xa7\x40"
    "\x3a\xff\x2f\xe1\xd3\xf6\x9f\xe8\x33\xcb\x12\x11",
    .c =
    "\x30\x34\x02\x18\x5a\x8b\x82\x69\x7e\x8a\x0a\x09\x14\xf8\x11\x2b"
    "\x55\xdc\xae\x37\x83\x7b\x12\xe6\xb6\x5b\xcb\xd4\x02\x18\x6a\x14"
    "\x4f\x53\x75\xc8\x02\x48\xeb\xc3\x92\x0f\x1e\x72\xee\xc4\xa3\xe3"
    "\x5c\x99\xdb\x92\x5b\x36",
    }, {
    .pubk_size = 48,
    .m_size = 32,
    .c_size = 55,
    .curve_type = PCE_ECC_CURVE_SECP192R1,
    .algo = PCE_ECDSA_VERIFY,
    .pubkey =
    "\xe2\x51\x24\x9b\xf7\xb6\x32\x82\x39\x66\x3d\x5b\xec\x3b\xae"
    "\x0c\xd5\xf2\x67\xd1\xc7\xe1\x02\xe4\xbf\x90\x62\xb8\x55\x75\x56"
    "\x69\x20\x5e\xcb\x4e\xca\x33\xd6\xcb\x62\x6b\x94\xa9\xa2\xe9\x58"
    "\x91",
    .m =
    "\x35\xec\xa1\xa0\x9e\x14\xde\x33\x03\xb6\xf6\xbd\x0c\x2f\xb2\xfd"
    "\x1f\x27\x82\xa5\xd7\x70\x3f\xef\xa0\x82\x69\x8e\x73\x31\x8e\xd7",
    .c =
    "\x30\x35\x02\x18\x3f\x72\x3f\x1f\x42\xd2\x3f\x1d\x6b\x1a\x58\x56"
    "\xf1\x8f\xf7\xfd\x01\x48\xfb\x5f\x72\x2a\xd4\x8f\x02\x19\x00\xb3"
    "\x69\x43\xfd\x48\x19\x86\xcf\x32\xdd\x41\x74\x6a\x51\xc7\xd9\x7d"
    "\x3a\x97\xd9\xcd\x1a\x6a\x49",
    }, {
    .pubk_size = 48,
    .m_size = 48,
    .c_size = 55,
    .curve_type = PCE_ECC_CURVE_SECP192R1,
    .algo = PCE_ECDSA_VERIFY,
    .pubkey =
    "\x5a\x13\xfe\x68\x86\x4d\xf4\x17\xc7\xa4\xe5\x8c\x65\x57\xb7"
    "\x03\x73\x26\x57\xfb\xe5\x58\x40\xd8\xfd\x49\x05\xab\xf1\x66\x1f"
    "\xe2\x9d\x93\x9e\xc2\x22\x5a\x8b\x4f\xf3\x77\x22\x59\x7e\xa6\x4e"
    "\x8b",
    .m =
    "\x9d\x2e\x1a\x8f\xed\x6c\x4b\x61\xae\xac\xd5\x19\x79\xce\x67\xf9"
    "\xa0\x34\xeb\xb0\x81\xf9\xd9\xdc\x6e\xb3\x5c\xa8\x69\xfc\x8a\x61"
    "\x39\x81\xfb\xfd\x5c\x30\x6b\xa8\xee\xed\x89\xaf\xa3\x05\xe4\x78",
    .c =
    "\x30\x35\x02\x19\x00\xf0\xa3\x38\xce\x2b\xf8\x9d\x1a\xcf\x7f\x34"
    "\xb4\xb4\xe5\xc5\x00\xdd\x15\xbb\xd6\x8c\xa7\x03\x78\x02\x18\x64"
    "\xbc\x5a\x1f\x82\x96\x61\xd7\xd1\x01\x77\x44\x5d\x53\xa4\x7c\x93"
    "\x12\x3b\x3b\x28\xfb\x6d\xe1",
    }, {
    .pubk_size = 48,
    .m_size = 64,
    .c_size = 55,
    .curve_type = PCE_ECC_CURVE_SECP192R1,
    .algo = PCE_ECDSA_VERIFY,
    .pubkey =
    "\xd5\xf2\x6e\xc3\x94\x5c\x52\xbc\xdf\x86\x6c\x14\xd1\xca\xea"
    "\xcc\x72\x3a\x8a\xf6\x7a\x3a\x56\x36\x3b\xca\xc6\x94\x0e\x17\x1d"
    "\x9e\xa0\x58\x28\xf9\x4b\xe6\xd1\xa5\x44\x91\x35\x0d\xe7\xf5\x11"
    "\x57",
    .m =
    "\xd5\x4b\xe9\x36\xda\xd8\x6e\xc0\x50\x03\xbe\x00\x43\xff\xf0\x23"
    "\xac\xa2\x42\xe7\x37\x77\x79\x52\x8f\x3e\xc0\x16\xc1\xfc\x8c\x67"
    "\x16\xbc\x8a\x5d\x3b\xd3\x13\xbb\xb6\xc0\x26\x1b\xeb\x33\xcc\x70"
    "\x4a\xf2\x11\x37\xe8\x1b\xba\x55\xac\x69\xe1\x74\x62\x7c\x6e\xb5",
    .c =
    "\x30\x35\x02\x19\x00\x88\x5b\x8f\x59\x43\xbf\xcf\xc6\xdd\x3f\x07"
    "\x87\x12\xa0\xd4\xac\x2b\x11\x2d\x1c\xb6\x06\xc9\x6c\x02\x18\x73"
    "\xb4\x22\x9a\x98\x73\x3c\x83\xa9\x14\x2a\x5e\xf5\xe5\xfb\x72\x28"
    "\x6a\xdf\x97\xfd\x82\x76\x24",
    },

    {
    .pubk_size = 64,
    .m_size = 20,
    .c_size = 72,
    .curve_type = PCE_ECC_CURVE_SECP256R1,
    .algo = PCE_ECDSA_VERIFY,
    .pubkey =
    "\xb9\x7b\xbb\xd7\x17\x64\xd2\x7e\xfc\x81\x5d\x87\x06\x83\x41"
    "\x22\xd6\x9a\xaa\x87\x17\xec\x4f\x63\x55\x2f\x94\xba\xdd\x83\xe9"
    "\x34\x4b\xf3\xe9\x91\x13\x50\xb6\xcb\xca\x62\x08\xe7\x3b\x09\xdc"
    "\xc3\x63\x4b\x2d\xb9\x73\x53\xe4\x45\xe6\x7c\xad\xe7\x6b\xb0\xe8"
    "\xaf",
    .m =
    "\xc2\x2b\x5f\x91\x78\x34\x26\x09\x42\x8d\x6f\x51\xb2\xc5\xaf\x4c"
    "\x0b\xde\x6a\x42",
    .c =
    "\x30\x46\x02\x21\x00\xf9\x25\xce\x9f\x3a\xa6\x35\x81\xcf\xd4\xe7"
    "\xb7\xf0\x82\x56\x41\xf7\xd4\xad\x8d\x94\x5a\x69\x89\xee\xca\x6a"
    "\x52\x0e\x48\x4d\xcc\x02\x21\x00\xd7\xe4\xef\x52\x66\xd3\x5b\x9d"
    "\x8a\xfa\x54\x93\x29\xa7\x70\x86\xf1\x03\x03\xf3\x3b\xe2\x73\xf7"
    "\xfb\x9d\x8b\xde\xd4\x8d\x6f\xad",
    }, {
    .pubk_size = 64,
    .m_size = 28,
    .c_size = 70,
    .curve_type = PCE_ECC_CURVE_SECP256R1,
    .algo = PCE_ECDSA_VERIFY,
    .pubkey =
    "\x8b\x6d\xc0\x33\x8e\x2d\x8b\x67\xf5\xeb\xc4\x7f\xa0\xf5\xd9"
    "\x7b\x03\xa5\x78\x9a\xb5\xea\x14\xe4\x23\xd0\xaf\xd7\x0e\x2e\xa0"
    "\xc9\x8b\xdb\x95\xf8\xb3\xaf\xac\x00\x2c\x2c\x1f\x7a\xfd\x95\x88"
    "\x43\x13\xbf\xf3\x1c\x05\x1a\x14\x18\x09\x3f\xd6\x28\x3e\xc5\xa0"
    "\xd4",
    .m =
    "\x1a\x15\xbc\xa3\xe4\xed\x3a\xb8\x23\x67\xc6\xc4\x34\xf8\x6c\x41"
    "\x04\x0b\xda\xc5\x77\xfa\x1c\x2d\xe6\x2c\x3b\xe0",
    .c =
    "\x30\x44\x02\x20\x20\x43\xfa\xc0\x9f\x9d\x7b\xe7\xae\xce\x77\x59"
    "\x1a\xdb\x59\xd5\x34\x62\x79\xcb\x6a\x91\x67\x2e\x7d\x25\xd8\x25"
    "\xf5\x81\xd2\x1e\x02\x20\x5f\xf8\x74\xf8\x57\xd0\x5e\x54\x76\x20"
    "\x4a\x77\x22\xec\xc8\x66\xbf\x50\x05\x58\x39\x0e\x26\x92\xce\xd5"
    "\x2e\x8b\xde\x5a\x04\x0e",
    }, {
    .pubk_size = 64,
    .m_size = 32,
    .c_size = 71,
    .curve_type = PCE_ECC_CURVE_SECP256R1,
    .algo = PCE_ECDSA_VERIFY,
    .pubkey =
    "\xf1\xea\xc4\x53\xf3\xb9\x0e\x9f\x7e\xad\xe3\xea\xd7\x0e\x0f"
    "\xd6\x98\x9a\xca\x92\x4d\x0a\x80\xdb\x2d\x45\xc7\xec\x4b\x97\x00"
    "\x2f\xe9\x42\x6c\x29\xdc\x55\x0e\x0b\x53\x12\x9b\x2b\xad\x2c\xe9"
    "\x80\xe6\xc5\x43\xc2\x1d\x5e\xbb\x65\x21\x50\xb6\x37\xb0\x03\x8e"
    "\xb8",
    .m =
    "\x8f\x43\x43\x46\x64\x8f\x6b\x96\xdf\x89\xdd\xa9\x01\xc5\x17\x6b"
    "\x10\xa6\xd8\x39\x61\xdd\x3c\x1a\xc8\x8b\x59\xb2\xdc\x32\x7a\xa4",
    .c =
    "\x30\x45\x02\x20\x08\x31\xfa\x74\x0d\x1d\x21\x5d\x09\xdc\x29\x63"
    "\xa8\x1a\xad\xfc\xac\x44\xc3\xe8\x24\x11\x2d\xa4\x91\xdc\x02\x67"
    "\xdc\x0c\xd0\x82\x02\x21\x00\xbd\xff\xce\xee\x42\xc3\x97\xff\xf9"
    "\xa9\x81\xac\x4a\x50\xd0\x91\x0a\x6e\x1b\xc4\xaf\xe1\x83\xc3\x4f"
    "\x2a\x65\x35\x23\xe3\x1d\xfa",
    }, {
    .pubk_size = 64,
    .m_size = 48,
    .c_size = 72,
    .curve_type = PCE_ECC_CURVE_SECP256R1,
    .algo = PCE_ECDSA_VERIFY,
    .pubkey =
    "\xc5\xc6\xea\x60\xc9\xce\xad\x02\x8d\xf5\x3e\x24\xe3\x52\x1d"
    "\x28\x47\x3b\xc3\x6b\xa4\x99\x35\x99\x11\x88\x88\xc8\xf4\xee\x7e"
    "\x8c\x33\x8f\x41\x03\x24\x46\x2b\x1a\x82\xf9\x9f\xe1\x97\x1b\x00"
    "\xda\x3b\x24\x41\xf7\x66\x33\x58\x3d\x3a\x81\xad\xcf\x16\xe9\xe2"
    "\x7c",
    .m =
    "\x3e\x78\x70\xfb\xcd\x66\xba\x91\xa1\x79\xff\x1e\x1c\x6b\x78\xe6"
    "\xc0\x81\x3a\x65\x97\x14\x84\x36\x14\x1a\x9a\xb7\xc5\xab\x84\x94"
    "\x5e\xbb\x1b\x34\x71\xcb\x41\xe1\xf6\xfc\x92\x7b\x34\xbb\x86\xbb",
    .c =
    "\x30\x46\x02\x21\x00\x8e\xf3\x6f\xdc\xf8\x69\xa6\x2e\xd0\x2e\x95"
    "\x54\xd1\x95\x64\x93\x08\xb2\x6b\x24\x94\x48\x46\x5e\xf2\xe4\x6c"
    "\xc7\x94\xb1\xd5\xfe\x02\x21\x00\xeb\xa7\x80\x26\xdc\xf9\x3a\x44"
    "\x19\xfb\x5f\x92\xf4\xc9\x23\x37\x69\xf4\x3b\x4f\x47\xcf\x9b\x16"
    "\xc0\x60\x11\x92\xdc\x17\x89\x12",
    }, {
    .pubk_size = 64,
    .m_size = 64,
    .c_size = 71,
    .curve_type = PCE_ECC_CURVE_SECP256R1,
    .algo = PCE_ECDSA_VERIFY,
    .pubkey =
    "\xd7\x27\x46\x49\xf6\x26\x85\x12\x40\x76\x8e\xe2\xe6\x2a\x7a"
    "\x83\xb1\x4e\x7a\xeb\x3b\x5c\x67\x4a\xb5\xa4\x92\x8c\x69\xff\x38"
    "\xee\xd9\x4e\x13\x29\x59\xad\xde\x6b\xbb\x45\x31\xee\xfd\xd1\x1b"
    "\x64\xd3\xb5\xfc\xaf\x9b\x4b\x88\x3b\x0e\xb7\xd6\xdf\xf1\xd5\x92"
    "\xbf",
    .m =
    "\x57\xb7\x9e\xe9\x05\x0a\x8c\x1b\xc9\x13\xe5\x4a\x24\xc7\xe2\xe9"
    "\x43\xc3\xd1\x76\x62\xf4\x98\x1a\x9c\x13\xb0\x20\x1b\xe5\x39\xca"
    "\x4f\xd9\x85\x34\x95\xa2\x31\xbc\xbb\xde\xdd\x76\xbb\x61\xe3\xcf"
    "\x9d\xc0\x49\x7a\xf3\x7a\xc4\x7d\xa8\x04\x4b\x8d\xb4\x4d\x5b\xd6",
    .c =
    "\x30\x45\x02\x21\x00\xb8\x6d\x87\x81\x43\xdf\xfb\x9f\x40\xea\x44"
    "\x81\x00\x4e\x29\x08\xed\x8c\x73\x30\x6c\x22\xb3\x97\x76\xf6\x04"
    "\x99\x09\x37\x4d\xfa\x02\x20\x1e\xb9\x75\x31\xf6\x04\xa5\x4d\xf8"
    "\x00\xdd\xab\xd4\xc0\x2b\xe6\x5c\xad\xc3\x78\x1c\xc2\xc1\x19\x76"
    "\x31\x79\x4a\xe9\x81\x6a\xee",
    },

    {
    .pubk_size = 96,
    .m_size = 20,
    .c_size = 104,
    .curve_type = PCE_ECC_CURVE_SECP384R1,
    .algo = PCE_ECDSA_VERIFY,
    .pubkey = /* PCE_ECC_CURVE_SECP384R1(sha1) */
    "\x89\x25\xf3\x97\x88\xcb\xb0\x78\xc5\x72\x9a\x14\x6e\x7a\xb1"
    "\x5a\xa5\x24\xf1\x95\x06\x9e\x28\xfb\xc4\xb9\xbe\x5a\x0d\xd9\x9f"
    "\xf3\xd1\x4d\x2d\x07\x99\xbd\xda\xa7\x66\xec\xbb\xea\xba\x79\x42"
    "\xc9\x34\x89\x6a\xe7\x0b\xc3\xf2\xfe\x32\x30\xbe\xba\xf9\xdf\x7e"
    "\x4b\x6a\x07\x8e\x26\x66\x3f\x1d\xec\xa2\x57\x91\x51\xdd\x17\x0e"
    "\x0b\x25\xd6\x80\x5c\x3b\xe6\x1a\x98\x48\x91\x45\x7a\x73\xb0\xc3"
    "\xf1",
    .m =
    "\x12\x55\x28\xf0\x77\xd5\xb6\x21\x71\x32\x48\xcd\x28\xa8\x25\x22"
    "\x3a\x69\xc1\x93",
    .c =
    "\x30\x66\x02\x31\x00\xf5\x0f\x24\x4c\x07\x93\x6f\x21\x57\x55\x07"
    "\x20\x43\x30\xde\xa0\x8d\x26\x8e\xae\x63\x3f\xbc\x20\x3a\xc6\xf1"
    "\x32\x3c\xce\x70\x2b\x78\xf1\x4c\x26\xe6\x5b\x86\xcf\xec\x7c\x7e"
    "\xd0\x87\xd7\xd7\x6e\x02\x31\x00\xcd\xbb\x7e\x81\x5d\x8f\x63\xc0"
    "\x5f\x63\xb1\xbe\x5e\x4c\x0e\xa1\xdf\x28\x8c\x1b\xfa\xf9\x95\x88"
    "\x74\xa0\x0f\xbf\xaf\xc3\x36\x76\x4a\xa1\x59\xf1\x1c\xa4\x58\x26"
    "\x79\x12\x2a\xb7\xc5\x15\x92\xc5",
    }, {
    .pubk_size = 96,
    .m_size = 28,
    .c_size = 104,
    .curve_type = PCE_ECC_CURVE_SECP384R1,
    .algo = PCE_ECDSA_VERIFY,
    .pubkey = /* PCE_ECC_CURVE_SECP384R1(sha224) */
    "\x69\x6c\xcf\x62\xee\xd0\x0d\xe5\xb5\x2f\x70\x54\xcf\x26\xa0"
    "\xd9\x98\x8d\x92\x2a\xab\x9b\x11\xcb\x48\x18\xa1\xa9\x0d\xd5\x18"
    "\x3e\xe8\x29\x6e\xf6\xe4\xb5\x8e\xc7\x4a\xc2\x5f\x37\x13\x99\x05"
    "\xb6\xa4\x9d\xf9\xfb\x79\x41\xe7\xd7\x96\x9f\x73\x3b\x39\x43\xdc"
    "\xda\xf4\x06\xb9\xa5\x29\x01\x9d\x3b\xe1\xd8\x68\x77\x2a\xf4\x50"
    "\x6b\x93\x99\x6c\x66\x4c\x42\x3f\x65\x60\x6c\x1c\x0b\x93\x9b\x9d"
    "\xe0",
    .m =
    "\x12\x80\xb6\xeb\x25\xe2\x3d\xf0\x21\x32\x96\x17\x3a\x38\x39\xfd"
    "\x1f\x05\x34\x7b\xb8\xf9\x71\x66\x03\x4f\xd5\xe5",
    .c =
    "\x30\x66\x02\x31\x00\x8a\x51\x84\xce\x13\x1e\xd2\xdc\xec\xcb\xe4"
    "\x89\x47\xb2\xf7\xbc\x97\xf1\xc8\x72\x26\xcf\x5a\x5e\xc5\xda\xb4"
    "\xe3\x93\x07\xe0\x99\xc9\x9c\x11\xb8\x10\x01\xc5\x41\x3f\xdd\x15"
    "\x1b\x68\x2b\x9d\x8b\x02\x31\x00\x8b\x03\x2c\xfc\x1f\xd1\xa9\xa4"
    "\x4b\x00\x08\x31\x6c\xf5\xd5\xf6\xdf\xd8\x68\xa2\x64\x42\x65\xf3"
    "\x4d\xd0\xc6\x6e\xb0\xe9\xfc\x14\x9f\x19\xd0\x42\x8b\x93\xc2\x11"
    "\x88\x2b\x82\x26\x5e\x1c\xda\xfb",
    }, {
    .pubk_size = 96,
    .m_size = 32,
    .c_size = 102,
    .curve_type = PCE_ECC_CURVE_SECP384R1,
    .algo = PCE_ECDSA_VERIFY,
    .pubkey = /* PCE_ECC_CURVE_SECP384R1(sha256) */
    "\xee\xd6\xda\x3e\x94\x90\x00\x27\xed\xf8\x64\x55\xd6\x51\x9a"
    "\x1f\x52\x00\x63\x78\xf1\xa9\xfd\x75\x4c\x9e\xb2\x20\x1a\x91\x5a"
    "\xba\x7a\xa3\xe5\x6c\xb6\x25\x68\x4b\xe8\x13\xa6\x54\x87\x2c\x0e"
    "\xd0\x83\x95\xbc\xbf\xc5\x28\x4f\x77\x1c\x46\xa6\xf0\xbc\xd4\xa4"
    "\x8d\xc2\x8f\xb3\x32\x37\x40\xd6\xca\xf8\xae\x07\x34\x52\x39\x52"
    "\x17\xc3\x34\x29\xd6\x40\xea\x5c\xb9\x3f\xfb\x32\x2e\x12\x33\xbc"
    "\xab",
    .m =
    "\xaa\xe7\xfd\x03\x26\xcb\x94\x71\xe4\xce\x0f\xc5\xff\xa6\x29\xa3"
    "\xe1\xcc\x4c\x35\x4e\xde\xca\x80\xab\x26\x0c\x25\xe6\x68\x11\xc2",
    .c =
    "\x30\x64\x02\x30\x08\x09\x12\x9d\x6e\x96\x64\xa6\x8e\x3f\x7e\xce"
    "\x0a\x9b\xaa\x59\xcc\x47\x53\x87\xbc\xbd\x83\x3f\xaf\x06\x3f\x84"
    "\x04\xe2\xf9\x67\xb6\xc6\xfc\x70\x2e\x66\x3c\x77\xc8\x8d\x2c\x79"
    "\x3a\x8e\x32\xc4\x02\x30\x40\x34\xb8\x90\xa9\x80\xab\x47\x26\xa2"
    "\xb0\x89\x42\x0a\xda\xd9\xdd\xce\xbc\xb2\x97\xf4\x9c\xf3\x15\x68"
    "\xc0\x75\x3e\x23\x5e\x36\x4f\x8d\xde\x1e\x93\x8d\x95\xbb\x10\x0e"
    "\xf4\x1f\x39\xca\x4d\x43",
    }, {
    .pubk_size = 96,
    .m_size = 48,
    .c_size = 104,
    .curve_type = PCE_ECC_CURVE_SECP384R1,
    .algo = PCE_ECDSA_VERIFY,
    .pubkey = /* PCE_ECC_CURVE_SECP384R1(sha384) */
    "\x3a\x2f\x62\xe7\x1a\xcf\x24\xd0\x0b\x7c\xe0\xed\x46\x0a\x4f"
    "\x74\x16\x43\xe9\x1a\x25\x7c\x55\xff\xf0\x29\x68\x66\x20\x91\xf9"
    "\xdb\x2b\xf6\xb3\x6c\x54\x01\xca\xc7\x6a\x5c\x0d\xeb\x68\xd9\x3c"
    "\xf1\x01\x74\x1f\xf9\x6c\xe5\x5b\x60\xe9\x7f\x5d\xb3\x12\x80\x2a"
    "\xd8\x67\x92\xc9\x0e\x4c\x4c\x6b\xa1\xb2\xa8\x1e\xac\x1c\x97\xd9"
    "\x21\x67\xe5\x1b\x5a\x52\x31\x68\xd6\xee\xf0\x19\xb0\x55\xed\x89"
    "\x9e",
    .m =
    "\x8d\xf2\xc0\xe9\xa8\xf3\x8e\x44\xc4\x8c\x1a\xa0\xb8\xd7\x17\xdf"
    "\xf2\x37\x1b\xc6\xe3\xf5\x62\xcc\x68\xf5\xd5\x0b\xbf\x73\x2b\xb1"
    "\xb0\x4c\x04\x00\x31\xab\xfe\xc8\xd6\x09\xc8\xf2\xea\xd3\x28\xff",
    .c =
    "\x30\x66\x02\x31\x00\x9b\x28\x68\xc0\xa1\xea\x8c\x50\xee\x2e\x62"
    "\x35\x46\xfa\x00\xd8\x2d\x7a\x91\x5f\x49\x2d\x22\x08\x29\xe6\xfb"
    "\xca\x8c\xd6\xb6\xb4\x3b\x1f\x07\x8f\x15\x02\xfe\x1d\xa2\xa4\xc8"
    "\xf2\xea\x9d\x11\x1f\x02\x31\x00\xfc\x50\xf6\x43\xbd\x50\x82\x0e"
    "\xbf\xe3\x75\x24\x49\xac\xfb\xc8\x71\xcd\x8f\x18\x99\xf0\x0f\x13"
    "\x44\x92\x8c\x86\x99\x65\xb3\x97\x96\x17\x04\xc9\x05\x77\xf1\x8e"
    "\xab\x8d\x4e\xde\xe6\x6d\x9b\x66",
    }, {
    .pubk_size = 96,
    .m_size = 64,
    .c_size = 101,
    .curve_type = PCE_ECC_CURVE_SECP384R1,
    .algo = PCE_ECDSA_VERIFY,
    .pubkey = /* PCE_ECC_CURVE_SECP384R1(sha512) */
    "\xb4\xe7\xc1\xeb\x64\x25\x22\x46\xc3\x86\x61\x80\xbe\x1e\x46"
    "\xcb\xf6\x05\xc2\xee\x73\x83\xbc\xea\x30\x61\x4d\x40\x05\x41\xf4"
    "\x8c\xe3\x0e\x5c\xf0\x50\xf2\x07\x19\xe8\x4f\x25\xbe\xee\x0c\x95"
    "\x54\x36\x86\xec\xc2\x20\x75\xf3\x89\xb5\x11\xa1\xb7\xf5\xaf\xbe"
    "\x81\xe4\xc3\x39\x06\xbd\xe4\xfe\x68\x1c\x6d\x99\x2b\x1b\x63\xfa"
    "\xdf\x42\x5c\xc2\x5a\xc7\x0c\xf4\x15\xf7\x1b\xa3\x2e\xd7\x00\xac"
    "\xa3",
    .m =
    "\xe8\xb7\x52\x7d\x1a\x44\x20\x05\x53\x6b\x3a\x68\xf2\xe7\x6c\xa1"
    "\xae\x9d\x84\xbb\xba\x52\x43\x3e\x2c\x42\x78\x49\xbf\x78\xb2\x71"
    "\xeb\xe1\xe0\xe8\x42\x7b\x11\xad\x2b\x99\x05\x1d\x36\xe6\xac\xfc"
    "\x55\x73\xf0\x15\x63\x39\xb8\x6a\x6a\xc5\x91\x5b\xca\x6a\xa8\x0e",
    .c =
    "\x30\x63\x02\x2f\x1d\x20\x94\x77\xfe\x31\xfa\x4d\xc6\xef\xda\x02"
    "\xe7\x0f\x52\x9a\x02\xde\x93\xe8\x83\xe4\x84\x4c\xfc\x6f\x80\xe3"
    "\xaf\xb3\xd9\xdc\x2b\x43\x0e\x6a\xb3\x53\x6f\x3e\xb3\xc7\xa8\xb3"
    "\x17\x77\xd1\x02\x30\x63\xf6\xf0\x3d\x5f\x5f\x99\x3f\xde\x3a\x3d"
    "\x16\xaf\xb4\x52\x6a\xec\x63\xe3\x0c\xec\x50\xdc\xcc\xc4\x6a\x03"
    "\x5f\x8d\x7a\xf9\xfb\x34\xe4\x8b\x80\xa5\xb6\xda\x2c\x4e\x45\xcf"
    "\x3c\x93\xff\x50\x5d",
    },

    {
    .pubk_size = 56,
    .m_size = 64,
    .c_size = 63,
    .curve_type = PCE_ECC_CURVE_SECP224R1,
    .algo = PCE_ECDSA_VERIFY,
    .pubkey =
    "\x25\x65\xd7\x5d\x14\x94\x68\x02\x79\x27\x6c\x78\x11\x9a"
    "\x4d\xc9\x65\xda\xbe\x52\xc1\xcf\xd3\x1d\x15\x73\x0c\x5e\x1a"
    "\xa0\xbf\xf5\x9b\x97\xb7\x38\x68\x72\x46\x17\xfa\x3d\xcb\xca"
    "\xff\x61\x1f\x6a\x1c\x12\x08\x0f\x5b\x7b\x73\xc9",
    .m =
    "\x39\xa5\xe0\x4a\xaf\xf7\x45\x5d\x98\x50\xc6\x05\x36\x4f\x51\x4c"
    "\x11\x32\x4c\xe6\x40\x16\x96\x0d\x23\xd5\xdc\x57\xd3\xff\xd8\xf4"
    "\x9a\x73\x94\x68\xab\x80\x49\xbf\x18\xee\xf8\x20\xcd\xb1\xad\x6c"
    "\x90\x15\xf8\x38\x55\x6b\xc7\xfa\xd4\x13\x8b\x23\xfd\xf9\x86\xc7",
    .c =
    "\x30\x3d\x02\x1c\x5f\xc8\x59\x1b\x9a\xbf\x0f\xce\x8f\xe7\xd7\xa7"
    "\x70\x30\x0f\x03\xdf\x75\x1d\x08\x7a\x75\xcb\xe9\xaa\x39\xe5\xd0"
    "\x02\x1d\x00\xab\xa4\xca\x7d\x88\xec\x72\xd1\x37\x5a\xed\x53\x79"
    "\x91\xab\xe6\x04\xca\x3c\xb6\xb2\x6f\xa1\x92\x2b\xd5\x9d\x7f",
    },

    {
    .pubk_size = 132,
    .m_size = 64,
    .c_size = 138,
    .curve_type = PCE_ECC_CURVE_SECP521R1,
    .algo = PCE_ECDSA_VERIFY,
    .pubkey =
    "\x00\x86\x68\x6a\xd4\x61\x09\xdd\xeb\x9d\x97\x3e\x09\xe2"
    "\x9f\xf5\xb5\xa5\x9c\xfc\x14\x1a\xc5\xa8\x96\xed\xc0\xba\x7d"
    "\x79\x88\xd7\x83\xd0\x14\xd2\x58\xa4\x01\x73\xc2\x9f\xe2\xb6"
    "\xde\x69\xe0\x62\x89\x74\x40\x42\x6c\x56\x47\xe5\x6b\xeb\x00"
    "\x81\xac\x20\x1c\xf5\x09\xda\x01\x66\x50\xb2\x83\x63\x89\x0a"
    "\xd1\x64\x7e\x52\xfd\xd1\x77\x6a\x39\xf6\x23\xbb\xe9\x28\x4e"
    "\xa6\x0d\x16\x6a\xc0\x1c\x17\xe9\x98\xa6\x78\x28\xaf\x72\x46"
    "\x28\x1c\xa0\x01\x53\xf1\x13\xa9\xb1\x88\xae\xae\x01\xb0\xb7"
    "\x04\x7b\x96\x86\x8b\x4d\x9a\x9b\x7b\xd9\x97\xd8\xca",
    .m =
    "\x39\xa5\xe0\x4a\xaf\xf7\x45\x5d\x98\x50\xc6\x05\x36\x4f\x51\x4c"
    "\x11\x32\x4c\xe6\x40\x16\x96\x0d\x23\xd5\xdc\x57\xd3\xff\xd8\xf4"
    "\x9a\x73\x94\x68\xab\x80\x49\xbf\x18\xee\xf8\x20\xcd\xb1\xad\x6c"
    "\x90\x15\xf8\x38\x55\x6b\xc7\xfa\xd4\x13\x8b\x23\xfd\xf9\x86\xc7",
    .c =
    "\x30\x81\x87\x02\x42\x01\xdd\x5b\x55\xaf\x30\x98\x6a\x7a\x8c\x6b"
    "\x71\x04\x37\x5b\xdc\x39\x19\x77\x84\xbc\xd1\x47\xce\xed\x56\x22"
    "\x1f\xbf\x23\x98\x83\x32\xd3\x63\x13\x37\x91\xcc\xea\x7d\x7e\xa1"
    "\x83\x39\x7a\x51\x04\x6a\x69\x46\xc7\x77\xda\x95\x7d\x9f\xbf\x29"
    "\x52\x0e\xfb\x25\x10\xeb\xdf\x02\x41\x1b\xb9\xec\x52\x06\x47\x44"
    "\xef\x52\x3c\xf0\x30\x48\xb1\x73\x3f\xda\x1e\x8e\xdb\xb4\x4e\xd5"
    "\x7c\xe5\x64\xf2\xc5\xd9\xb1\x70\xf4\xcb\x45\x22\x28\x9c\x19\x77"
    "\x00\xbe\x33\x0f\xc2\x27\x16\x22\x9a\x0b\x0d\x46\xea\x0a\x45\x8b"
    "\xae\xf6\x00\xef\xf5\xf0\x4b\x6d\x63\x58",
    },
    {
    .pubk_size = 48,
    .m_size = 20,
    .curve_type = PCE_ECC_CURVE_SECP192R1,
    .algo = PCE_ECDSA_SIGN,
    .prikey =
    "\x3d\xa5\x8a\x8a\x95\x43\xe4\x68"
    "\xea\xc6\x25\xc1\xc1\x01\x25\x4c\x7e\xc3\x3c\xa6\x04\x0a\xe7\x08",
    .m =
    "\xcd\xb9\xd2\x1c\xb7\x6f\xcd\x44\xb3\xfd\x63\xea\xa3\x66\x7f\xae"
    "\x63\x85\xe7\x82",
    },

    {
    .pubk_size = 64,
    .m_size = 48,
    .curve_type = PCE_ECC_CURVE_SECP256R1,
    .algo = PCE_ECDSA_SIGN,
    .prikey =
    "\x28\x47\x3b\xc3\x6b\xa4\x99\x35\x99\x11\x88\x88\xc8\xf4\xee\x7e"
    "\xda\x3b\x24\x41\xf7\x66\x33\x58\x3d\x3a\x81\xad\xcf\x16\xe9\xe2",
    .m =
    "\x3e\x78\x70\xfb\xcd\x66\xba\x91\xa1\x79\xff\x1e\x1c\x6b\x78\xe6"
    "\xc0\x81\x3a\x65\x97\x14\x84\x36\x14\x1a\x9a\xb7\xc5\xab\x84\x94"
    "\x5e\xbb\x1b\x34\x71\xcb\x41\xe1\xf6\xfc\x92\x7b\x34\xbb\x86\xbb",
    },

    {
    .pubk_size = 96,
    .m_size = 64,
    .curve_type = PCE_ECC_CURVE_SECP384R1,
    .algo = PCE_ECDSA_SIGN,
    .prikey =
    "\x54\x36\x86\xec\xc2\x20\x75\xf3\x89\xb5\x11\xa1\xb7\xf5\xaf\xbe"
    "\x81\xe4\xc3\x39\x06\xbd\xe4\xfe\x68\x1c\x6d\x99\x2b\x1b\x63\xfa"
    "\xdf\x42\x5c\xc2\x5a\xc7\x0c\xf4\x15\xf7\x1b\xa3\x2e\xd7\x00\xac",
    .m =
    "\xe8\xb7\x52\x7d\x1a\x44\x20\x05\x53\x6b\x3a\x68\xf2\xe7\x6c\xa1"
    "\xae\x9d\x84\xbb\xba\x52\x43\x3e\x2c\x42\x78\x49\xbf\x78\xb2\x71"
    "\xeb\xe1\xe0\xe8\x42\x7b\x11\xad\x2b\x99\x05\x1d\x36\xe6\xac\xfc"
    "\x55\x73\xf0\x15\x63\x39\xb8\x6a\x6a\xc5\x91\x5b\xca\x6a\xa8\x0e",
    },
    {
    .pubk_size = 48,
    .curve_type = PCE_ECC_CURVE_SECP192R1,
    .algo = PCE_ECC_PUBKEY,
    .prikey =
    "\x35\x61\xd8\xf7\x0d\x17\x4c\x96\x95\x69\x19\x68\xeb\xaf\xf4"
    "\xc1\xe2\x58\x28\xa7\xa7\x60\xa6\xdd",
    .pubkey = 
    "\x04\x1a\xa4\x6c\xd6\x6b\xbe\x44\xb7\x24\xe8\x7b\x14\x3b"
    "\x18\x47\x08\xf2\xef\xc1\x1d\x16\xa1\xbc\x5b\x6a\xea\xda\xb2"
    "\xc7\x3a\x8e\x05\x3a\xe1\xce\x43\x32\x20\x97\x33\x07\xb1\xb7"
    "\xfd\x89\xcc\xbe",
    },
    {
    .pubk_size = 56,
    .curve_type = PCE_ECC_CURVE_SECP224R1,
    .algo = PCE_ECC_PUBKEY,
    .prikey =
    "\x0e\x43\x63\x59\x7c\xae\xee\x6b\x10\x31\x18\x13\x9c\x33\x5f"
    "\xa7\x0f\x7a\x71\x88\x70\x1a\x7c\x4f\x1c\xa3\x62\xe6",
    .pubkey = 
    "\x44\xbb\xd4\x9b\x06\xe4\x7e\xce\x17\x74\x91\xb3\xf3\xf1"
    "\x8d\xd1\x58\xfd\x3c\x33\x39\x65\x04\x3e\x3e\x62\x60\x45\x90"
    "\x12\xf8\xa2\x91\x2e\x31\x0e\x3b\x1a\xc8\x07\x28\x76\x68\xff"
    "\x48\x9d\x51\xfe\x5d\xa5\x50\x1d\x04\x4a\x4b\xbe",
    },
    {
    .pubk_size = 64,
    .curve_type = PCE_ECC_CURVE_SECP256R1,
    .algo = PCE_ECC_PUBKEY,
    .prikey =
    "\x58\x42\xb3\x2a\xdc\xef\xf7\x0e\x3e\x93\x9a\x1a\x96\xd0\x29"
    "\x77\xcd\x77\x27\xb4\x8f\x5d\xaa\x91\xa9\x59\xd3\xd6\xf3\x51"
    "\x48\x17",
    .pubkey = 
     "\xdc\x35\x1e\x91\x00\x1d\x62\x9a\x64\xd6\xa7\xdf\x4a\xfd"
     "\xab\xd1\xce\xb0\x9d\x4a\xb6\x9d\x0c\xb8\xa8\xeb\x0a\x54\xbe"
     "\x2c\x1b\x6c\x88\xf0\xa8\x36\x06\x2e\x77\x8e\xf9\x73\xde\xba"
     "\xf0\x27\x26\xdb\x22\x06\x0a\x6e\x28\xcc\xbe\x2d\x0b\x2d\xe4"
     "\x82\x32\x12\x93\xda",
    },

    {
    .pubk_size = 96,
    .curve_type = PCE_ECC_CURVE_SECP384R1,
    .algo = PCE_ECC_PUBKEY,
    .prikey =
     "\x65\xe5\xe5\xd1\x9a\x7d\xcd\x14\xe2\xea\x8c\xc1\xdb\xc1\xf7"
     "\xfa\xf4\x34\x76\x29\x16\xa7\xd6\xc9\xa9\x17\x25\x77\x9e\xb8"
     "\xe7\x6e\xb8\x42\x5c\x7a\xc5\xd7\xc5\x6d\xe7\xaa\x99\xf7\x36"
     "\x58\x58\xba",
    .pubkey = 
    "\x62\xca\xbe\x54\x14\x23\x52\x77\x55\x57\x17\x4a\x19\x78"
    "\xc3\x64\x42\x27\xc9\xf8\x37\x87\xb9\x18\xea\x52\xb2\xed\xff"
    "\x1c\x34\xc5\xc7\x36\x90\xb0\xfb\x94\x51\x0d\xfc\xe5\x77\xdb"
    "\x78\xc4\x3d\xd3\xc7\x65\xd3\x5b\x11\xae\x72\xd6\xd0\x71\xe4"
    "\xbb\x5b\xfb\x80\x6d\x54\x20\xdc\xb3\x0b\x4a\xdc\xa0\xc8\xbd"
    "\x3a\x9c\x52\x5f\xa1\x41\x56\x69\xaf\xb5\x27\x01\x26\x28\x9f"
    "\x0c\x11\x24\x67\x99\xb2\xfd",
    },
    {
    .pubk_size = 132,
    .curve_type = PCE_ECC_CURVE_SECP521R1,
    .algo = PCE_ECC_PUBKEY,
    .prikey =
    "\x01\xe3\x5b\x25\xc4\x78\x16\x45\xf5\x48\x27\x24\x87\x42\x36"
    "\xf2\xc8\xe1\xc0\x59\xd8\x48\x8a\xd6\x5c\x7d\x1c\x5e\xcf\xf6"
    "\x92\xef\x4e\x8c\x03\x14\x1f\x12\x64\x75\x15\xfa\xf7\x2d\xe1"
    "\x01\xda\x2e\xb8\xfa\x50\xca\x1e\x0b\xfd\x67\x41\x2c\x90\xda"
    "\x5d\xee\xca\x6d\x0d\x9f",
    .pubkey = 
    "\x01\xaf\xcc\xe9\x70\x9e\x3d\x7e\x25\xca\x0c\x0c\x52\x89"
    "\x85\xe3\xb9\x58\xcf\x6b\xfd\xd3\x3a\x44\x66\xca\x39\xdb\x83"
    "\xcf\xed\x47\x3a\xb7\x0d\xfc\x0b\xd9\xb2\x7b\xf1\x11\xde\xe8"
    "\x21\x26\xe1\xe3\xf2\xda\xb1\x35\x60\x3b\x44\x40\x36\x34\xb3"
    "\xd2\xe2\x17\x16\x2e\xab\xc0\x00\x1e\xa1\xac\xff\xdf\x17\x2e"
    "\x71\x0e\xb1\x62\x93\xdc\x20\x8f\xe2\x10\x69\x96\x21\x94\xbf"
    "\x09\x89\xe4\x13\xc9\xc3\x57\x92\xec\x81\xca\x2f\x76\xc4\xcf"
    "\x05\x2c\xed\x94\x16\x91\x51\xbc\xf4\xec\xcc\xfa\x3e\x4f\x25"
    "\xc1\x16\x2d\x84\xea\xe3\xf4\x26\x48\x9b\x48\x93\x82",
    },

    {
    .pubk_size = 48,
    .c_size = 24,
    .curve_type = PCE_ECC_CURVE_SECP192R1,
    .algo = PCE_ECDH_EXCHANGE,
    .prikey =
    "\xb5\x05\xb1\x71\x1e\xbf\x8c\xda"
    "\x4e\x19\x1e\x62\x1f\x23\x23\x31"
    "\x36\x1e\xd3\x84\x2f\xcc\x21\x72",
    .pubkey =
    "\xc3\xba\x67\x4b\x71\xec\xd0\x76"
    "\x7a\x99\x75\x64\x36\x13\x9a\x94"
    "\x5d\x8b\xdc\x60\x90\x91\xfd\x3f"
    "\xb0\x1f\x8a\x0a\x68\xc6\x88\x6e"
    "\x83\x87\xdd\x67\x09\xf8\x8d\x96"
    "\x07\xd6\xbd\x1c\xe6\x8d\x9d\x67",
    .c =
    "\xf4\x57\xcc\x4f\x1f\x4e\x31\xcc"
    "\xe3\x40\x60\xc8\x06\x93\xc6\x2e"
    "\x99\x80\x81\x28\xaf\xc5\x51\x74",
    },
    {
    .pubk_size = 56,
    .c_size = 28,
    .curve_type = PCE_ECC_CURVE_SECP224R1,
    .algo = PCE_ECDH_EXCHANGE,
    .c =
    "\xc9\xe6\x2a\x25\x34\xef\x41\x16\x4c\x58\xe0\xb8\x50\xe2\x9e\x30\x94\xbc\x80\x94\x79\xee\xe1\x24\x57\x8b\x08\x4d",
    .prikey = 
    "\xB5\x58\xEB\x6C\x28\x8D\xA7\x07\xBB\xB4\xF8\xFB\xAE\x2A\xB9\xE9\xCB\x62\xE3\xBC\x5C\x75\x73\xE2\x2E\x26\xD3\x7F",
    .pubkey =
    "\x1c\x65\xb3\x72\x2f\x91\x9f\xb0\xa5\x8a\xa1\x32\x6a\x04"
    "\xa2\x78\x0a\x2e\x9f\x7a\x81\x87\xc0\x1d\x52\xf0\x7d\xab\xf4"
    "\x8b\xda\xa5\xef\x59\xbc\xec\x02\xcd\x58\xd0\x74\x4e\x26\x0f"
    "\xad\xbf\xcf\x53\x13\xb2\xf7\x50\xcc\x05\x9f\xb0",
    },

    {
    .pubk_size = 64,
    .c_size = 32,
    .curve_type = PCE_ECC_CURVE_SECP256R1,
    .algo = PCE_ECDH_EXCHANGE,
    .pubkey = 
    "\xcc\xb4\xda\x74\xb1\x47\x3f\xea"
    "\x6c\x70\x9e\x38\x2d\xc7\xaa\xb7"
    "\x29\xb2\x47\x03\x19\xab\xdd\x34"
    "\xbd\xa8\x2c\x93\xe1\xa4\x74\xd9"
    "\x64\x63\xf7\x70\x20\x2f\xa4\xe6"
    "\x9f\x4a\x38\xcc\xc0\x2c\x49\x2f"
    "\xb1\x32\xbb\xaf\x22\x61\xda\xcb"
    "\x6f\xdb\xa9\xaa\xfc\x77\x81\xf3",
    .c = 
    "\xea\x17\x6f\x7e\x6e\x57\x26\x38"
    "\x8b\xfb\x41\xeb\xba\xc8\x6d\xa5"
    "\xa8\x72\xd1\xff\xc9\x47\x3d\xaa"
    "\x58\x43\x9f\x34\x0f\x8c\xf3\xc9",
    .prikey = 
    "\x24\xd1\x21\xeb\xe5\xcf\x2d\x83"
    "\xf6\x62\x1b\x6e\x43\x84\x3a\xa3"
    "\x8b\xe0\x86\xc3\x20\x19\xda\x92"
    "\x50\x53\x03\xe1\xc0\xea\xb8\x82",
    },
    {
    .pubk_size = 96,
    .c_size = 48,
    .curve_type = PCE_ECC_CURVE_SECP384R1,
    .algo = PCE_ECDH_EXCHANGE,
    .pubkey = 
    "\xE5\x58\xDB\xEF\x53\xEE\xCD\xE3"
    "\xD3\xFC\xCF\xC1\xAE\xA0\x8A\x89"
    "\xA9\x87\x47\x5D\x12\xFD\x95\x0D"
    "\x83\xCF\xA4\x17\x32\xBC\x50\x9D"
    "\x0D\x1A\xC4\x3A\x03\x36\xDE\xF9"
    "\x6F\xDA\x41\xD0\x77\x4A\x35\x71"
    "\xDC\xFB\xEC\x7A\xAC\xF3\x19\x64"
    "\x72\x16\x9E\x83\x84\x30\x36\x7F"
    "\x66\xEE\xBE\x3C\x6E\x70\xC4\x16"
    "\xDD\x5F\x0C\x68\x75\x9D\xD1\xFF"
    "\xF8\x3F\xA4\x01\x42\x20\x9D\xFF"
    "\x5E\xAA\xD9\x6D\xB9\xE6\x38\x6C",
    .c = 
    "\x11\x18\x73\x31\xC2\x79\x96\x2D"
    "\x93\xD6\x04\x24\x3F\xD5\x92\xCB"
    "\x9D\x0A\x92\x6F\x42\x2E\x47\x18"
    "\x75\x21\x28\x7E\x71\x56\xC5\xC4"
    "\xD6\x03\x13\x55\x69\xB9\xE9\xD0"
    "\x9C\xF5\xD4\xA2\x70\xF5\x97\x46",
    .prikey = 
    "\x09\x9F\x3C\x70\x34\xD4\xA2\xC6"
    "\x99\x88\x4D\x73\xA3\x75\xA6\x7F"
    "\x76\x24\xEF\x7C\x6B\x3C\x0F\x16"
    "\x06\x47\xB6\x74\x14\xDC\xE6\x55"
    "\xE3\x5B\x53\x80\x41\xE6\x49\xEE"
    "\x3F\xAE\xF8\x96\x78\x3A\xB1\x94",
    },
    {
    .pubk_size = 132,
    .c_size = 66,
    .curve_type = PCE_ECC_CURVE_SECP521R1,
    .algo = PCE_ECDH_EXCHANGE,
    .prikey =
    "\x00\x37\xAD\xE9\x31\x9A\x89\xF4\xDA\xBD\xB3\xEF\x41\x1A\xAC\xCC"
    "\xA5\x12\x3C\x61\xAC\xAB\x57\xB5\x39\x3D\xCE\x47\x60\x81\x72\xA0"
    "\x95\xAA\x85\xA3\x0F\xE1\xC2\x95\x2C\x67\x71\xD9\x37\xBA\x97\x77"
    "\xF5\x95\x7B\x26\x39\xBA\xB0\x72\x46\x2F\x68\xC2\x7A\x57\x38\x2D"
    "\x4A\x52",
    .pubkey =
    "\x00\xD0\xB3\x97\x5A\xC4\xB7\x99\xF5\xBE\xA1\x6D\x5E\x13\xE9\xAF"
    "\x97\x1D\x5E\x9B\x98\x4C\x9F\x39\x72\x8B\x5E\x57\x39\x73\x5A\x21"
    "\x9B\x97\xC3\x56\x43\x6A\xDC\x6E\x95\xBB\x03\x52\xF6\xBE\x64\xA6"
    "\xC2\x91\x2D\x4E\xF2\xD0\x43\x3C\xED\x2B\x61\x71\x64\x00\x12\xD9"
    "\x46\x0F"
    "\x01\x5C\x68\x22\x63\x83\x95\x6E\x3B\xD0\x66\xE7\x97\xB6\x23\xC2"
    "\x7C\xE0\xEA\xC2\xF5\x51\xA1\x0C\x2C\x72\x4D\x98\x52\x07\x7B\x87"
    "\x22\x0B\x65\x36\xC5\xC4\x08\xA1\xD2\xAE\xBB\x8E\x86\xD6\x78\xAE"
    "\x49\xCB\x57\x09\x1F\x47\x32\x29\x65\x79\xAB\x44\xFC\xD1\x7F\x0F"
    "\xC5\x6A",
    .c =
    "\x01\x14\x4C\x7D\x79\xAE\x69\x56\xBC\x8E\xDB\x8E\x7C\x78\x7C\x45"
    "\x21\xCB\x08\x6F\xA6\x44\x07\xF9\x78\x94\xE5\xE6\xB2\xD7\x9B\x04"
    "\xD1\x42\x7E\x73\xCA\x4B\xAA\x24\x0A\x34\x78\x68\x59\x81\x0C\x06"
    "\xB3\xC7\x15\xA3\xA8\xCC\x31\x51\xF2\xBE\xE4\x17\x99\x6D\x19\xF3"
    "\xDD\xEA",
    },
    {
    .pubk_size = 132,
    .c_size = 66,
    .curve_type = PCE_ECC_CURVE_SECP521R1,
    .algo = PCE_ECDH_EXCHANGE,
    .prikey =
    "\x00\x37\xAD\xE9\x31\x9A\x89\xF4\xDA\xBD\xB3\xEF\x41\x1A\xAC\xCC"
    "\xA5\x12\x3C\x61\xAC\xAB\x57\xB5\x39\x3D\xCE\x47\x60\x81\x72\xA0"
    "\x95\xAA\x85\xA3\x0F\xE1\xC2\x95\x2C\x67\x71\xD9\x37\xBA\x97\x77"
    "\xF5\x95\x7B\x26\x39\xBA\xB0\x72\x46\x2F\x68\xC2\x7A\x57\x38\x2D"
    "\x4A\x52",
    .pubkey =
    "\x00\xD0\xB3\x97\x5A\xC4\xB7\x99\xF5\xBE\xA1\x6D\x5E\x13\xE9\xAF"
    "\x97\x1D\x5E\x9B\x98\x4C\x9F\x39\x72\x8B\x5E\x57\x39\x73\x5A\x21"
    "\x9B\x97\xC3\x56\x43\x6A\xDC\x6E\x95\xBB\x03\x52\xF6\xBE\x64\xA6"
    "\xC2\x91\x2D\x4E\xF2\xD0\x43\x3C\xED\x2B\x61\x71\x64\x00\x12\xD9"
    "\x46\x0F"
    "\x01\x5C\x68\x22\x63\x83\x95\x6E\x3B\xD0\x66\xE7\x97\xB6\x23\xC2"
    "\x7C\xE0\xEA\xC2\xF5\x51\xA1\x0C\x2C\x72\x4D\x98\x52\x07\x7B\x87"
    "\x22\x0B\x65\x36\xC5\xC4\x08\xA1\xD2\xAE\xBB\x8E\x86\xD6\x78\xAE"
    "\x49\xCB\x57\x09\x1F\x47\x32\x29\x65\x79\xAB\x44\xFC\xD1\x7F\x0F"
    "\xC5\x6A",
    .c =
    "\x01\x14\x4C\x7D\x79\xAE\x69\x56\xBC\x8E\xDB\x8E\x7C\x78\x7C\x45"
    "\x21\xCB\x08\x6F\xA6\x44\x07\xF9\x78\x94\xE5\xE6\xB2\xD7\x9B\x04"
    "\xD1\x42\x7E\x73\xCA\x4B\xAA\x24\x0A\x34\x78\x68\x59\x81\x0C\x06"
    "\xB3\xC7\x15\xA3\xA8\xCC\x31\x51\xF2\xBE\xE4\x17\x99\x6D\x19\xF3"
    "\xDD\xEA",
    },
    /*gen key */
    {
    .pubk_size = 132,
    .c_size = 66,
    .curve_type = PCE_ECC_CURVE_SECP521R1,
    .algo = PCE_ECC_KEY,
    },
    {
    .pubk_size = 96,
    .c_size = 48,
    .curve_type = PCE_ECC_CURVE_SECP384R1,
    .algo = PCE_ECC_KEY,
    },
    {
    .pubk_size = 64,
    .c_size = 32,
    .curve_type = PCE_ECC_CURVE_SECP256R1,
    .algo = PCE_ECC_KEY,
    },
    {
    .pubk_size = 56,
    .c_size = 28,
    .curve_type = PCE_ECC_CURVE_SECP224R1,
    .algo = PCE_ECC_KEY,
    },
    {
    .pubk_size = 48,
    .c_size = 24,
    .curve_type = PCE_ECC_CURVE_SECP192R1,
    .algo = PCE_ECC_KEY,
    }
};


typedef struct {
    int alg;
    uint8_t *result;
    uint8_t *src ;
    uint8_t *privkey ;
    uint8_t *pubkey;

    uint8_t *peer_pub_key_addr;
    ecdsa_testvec_t *testvec;
}ecc_test_data_t;


static const char *test_ecc_curves_names[SM2_NUM] = {
    "eccp256v1",
};
static const int test_ecc_curves_bits[] = {
    192,224,256,384,512,
};
int eccsign_doit[SM2_NUM] = {0};
int eccenc_doit[SM2_NUM] = {0};

static double eccsign_results[MAX_THREAD_NUM][3];
static double eccenc_results[SM2_NUM][3];
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))


static int init_ecc_test_data(ecc_test_data_t *test_data,enum pce_curve_type  curve_type, enum pce_alg algo)
{
    int i;
    //查找算法
    test_data->testvec = NULL;
    for (i = 0; i < ARRAY_SIZE(ecdsa_tv_template); i++){
        if(ecdsa_tv_template[i].algo == algo && ecdsa_tv_template[i].curve_type == curve_type){
            test_data->testvec = &ecdsa_tv_template[i];
            break;
        }
    }
    
    test_data->result = pce_alloc_mem(numa_node, 0x10000);
    if (NULL == test_data->result) {
        goto out;
    }
    memset(test_data->result, 0, 0x10000);
        
    test_data->src = pce_alloc_mem(numa_node, 0x10000);
    if (NULL == test_data->src) {
        goto out;
    }
    memset(test_data->src, 0, 0x10000);
    
    test_data->privkey = pce_alloc_mem(numa_node, 0x10000);
    if (NULL == test_data->privkey) {
        goto out;
    }
    memset(test_data->privkey, 0, 0x10000);
    
    test_data->pubkey = pce_alloc_mem(numa_node, 0x10000);
    if (NULL == test_data->pubkey) {
        goto out;
    }
    memset(test_data->pubkey, 0, 0x10000);
 
    out:
    return 0;
}


static void free_ecc_test_data(ecc_test_data_t *test_data)
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

void fill_op_data_ecc(pce_op_data_t *op_data, ecc_test_data_t *test_data)
{
    ecc_test_data_t *ctx = test_data;
    if (!ctx) {
        return;
    }
    ecdsa_testvec_t *testvec = test_data->testvec;
    uint8_t *src = test_data->src;
    uint8_t *result = test_data->result;
    uint8_t *privkey = test_data->privkey;
    uint8_t *pubkey = test_data->pubkey;

    
    op_data->ecc.alg = testvec->algo;
    op_data->ecc.curve_id = testvec->curve_type;
    
    switch (ctx->alg)
    {
    case PCE_ECC_PUBKEY:    
        memcpy(privkey, testvec->prikey, testvec->pubk_size>>1);
        op_data->ecc.genkey.priv_key_addr = (uint64_t)privkey;
        op_data->ecc.genkey.pub_key_addr = (uint64_t)pubkey;
        break;
    case PCE_ECC_KEY:
        op_data->ecc.genkey.priv_key_addr = (uint64_t)privkey;
        op_data->ecc.genkey.pub_key_addr = (uint64_t)pubkey;
        break;
    case PCE_ECDSA_SIGN:
        
        memcpy(src, testvec->m, testvec->m_size);
        memcpy(privkey, testvec->prikey, testvec->pubk_size>>1);
                        
        op_data->ecc.sign.e_byte_length = (testvec->m_size > testvec->pubk_size / 2) ? testvec->pubk_size / 2 : testvec->m_size;
        op_data->ecc.sign.e_addr = (uint64_t)src;
        op_data->ecc.sign.priv_key_addr = (uint64_t)privkey;
        op_data->ecc.sign.result_addr = (uint64_t)result;
        /* code */
        break;
    case PCE_ECDSA_VERIFY:
        
        memcpy(src, testvec->m, testvec->m_size);
        memcpy(pubkey, testvec->pubkey, testvec->pubk_size);
        
        op_data->ecc.verify.e_byte_length = (testvec->m_size > testvec->pubk_size / 2) ? testvec->pubk_size / 2 : testvec->m_size;
                        
        if (pce_ecsign_decode(testvec->curve_type, testvec->c, testvec->c_size, src + op_data->ecc.verify.e_byte_length))
                break;
                        
        op_data->ecc.verify.e_signature_addr = (uint64_t)src;
        op_data->ecc.verify.pub_key_addr = (uint64_t)pubkey;
        /* code */
        break;
    case PCE_ECDH_EXCHANGE:
        memcpy(pubkey, testvec->pubkey, testvec->pubk_size);
        memcpy(privkey, testvec->prikey, testvec->pubk_size / 2);
        
        memcpy(privkey, testvec->prikey, 32);
        op_data->ecc.ecdh.peer_pub_key_addr = (uint64_t)pubkey;
        op_data->ecc.ecdh.priv_key_addr = (uint64_t)privkey;
        op_data->ecc.ecdh.result_addr = (uint64_t)result;        
        break;
    default:
        break;
    }
    
    
}

// 0 fail  1 success
static int test_ecc_loop(void *args)
{
    loopargs_t *loopargs = args;
    if(args == NULL){
        return 0;
    }
    int i;
    int batch = 1;
    ecc_test_data_t *data = (ecc_test_data_t *)loopargs->asym_data;

    int enqueued_count = 0;
    pce_op_data_t *ecc_datas = NULL;
    perf_ring *ring = loopargs->ring;
    ecc_datas = loopargs->requests;
    
    for(i = 0; i < batch; i++){
        fill_op_data_ecc(&ecc_datas[i], data);
        SET_CALLBACK_INIT();
        SET_CALLBACK_ALGOINDEX(loopargs->algo_index);
        SET_CALLBACK_TEST_NUM(loopargs->testnum);
        SET_CALLBACK_THREAD_ID(loopargs->thread_id);
        ecc_datas[i].ecc.tag = (uint64_t) (callback);
    }

    enqueued_count = mp_enqueue(ring, &ecc_datas, batch);//入队一个,此处队列句柄来源错误
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
int test_hit_for_ecc(const char *algo_name)
{
    return 0;
}
void test_perf_for_ecc(loopargs_t *loopargs)
{
    long count = 0;
    double d;
    int testnum = 0;
    loopargs->batch = cmd_option.batch;
    uint16_t thread_id = loopargs->thread_id;
    algo_data_t *algo_data = (algo_data_t*)get_hash_map(g_algo_hash_table, loopargs->algo_name);
    sem_t *start_sem = GET_START_SEM();
    int algo_index = algo_data->algo_index;
    loopargs->algo_index = algo_index;
    ecc_test_data_t *ecc_data = pce_alloc_mem(numa_node, sizeof(ecc_test_data_t) * 2);
    uint16_t ecc_operations[] = {PCE_ECDSA_SIGN, PCE_ECDSA_VERIFY, PCE_ECC_KEY, 0 };
    char *ecc_ops[]={"sign","verify","genkey",NULL};
    show_results_funcs[thread_id] = show_results_for_ecc;
    // test ecc sign and verify
    for (testnum = 0; ecc_operations[testnum] != 0; testnum++) {    
        // SIGN性能测试
        memset(ecc_data, 0, sizeof(ecc_test_data_t));
        
        init_ecc_test_data(ecc_data, loopargs->test_length, ecc_operations[testnum]);
        
        loopargs->asym_data = ecc_data;
        pkey_print_message(ecc_ops[testnum], "ecc", 0, test_ecc_curves_bits[loopargs->test_length],
                   cmd_option.duration);
        
        loopargs->testnum = testnum;
        sem_post(start_sem);
        gettimeofday(&tv,NULL); 
        count = run_benchmark(test_ecc_loop, loopargs);
        gettimeofday(&tv1,NULL);
        d = (tv1.tv_usec-tv.tv_usec)/(100000.0)+((tv1.tv_sec-tv.tv_sec));
        
        count = results[thread_id][testnum];
        fprintf(stderr,
            mr ? "+R7:%ld:%d:%.2f\n"
               : "%ld %d bit ecc signs in %.2fs \n",
            count, test_ecc_curves_bits[loopargs->test_length], d);
        eccsign_results[thread_id][testnum] = d / (double)count; // 每次签名运算耗时
        free_ecc_test_data(ecc_data);
    }
    
    pce_free_mem(ecc_data);
}


/**
 *
 *@ Description: 输出ecc算法的执行结果
 *
 * 示例：
 *
 *  Doing 256 bit sign ecc's for 2s: 31593 256 bit SM2 signs in 1.97s
Doing 256 bit verify ecc's for 2s: 5882 256 bit SM2 verify in 2.00s
                  sign    verify    sign/s verify/s
 256 bit ecc (eccp256v1)   0.0001s   0.0003s  16037.1   2941.0
 *
 * +F6:0:256:0.000063:0.000345 // +F6表示类型， 0：位数索引，位数，签名耗时，
验签耗时
 *@ return void
 */
void show_results_for_ecc(uint16_t thread_id)
{
    int testnum = 1;
    int k,i;
    char *ecc_ops[]={"sign","verify","genkey",NULL};
    for (k = 0; k < SM2_NUM; k++) {
        //if (!sm2sign_doit[k])
            // continue;
        if (testnum && !mr) {
            printf("%25s"," ");
            for(i = 0; ecc_ops[i] != NULL; i++){
                printf("    %s",ecc_ops[i]);
            }
            for(i = 0; ecc_ops[i] != NULL;i++){
                printf("  %s/s",ecc_ops[i]);
            }
            printf("\n");
            testnum = 0;
        }

        if (mr)
            printf("+F6:%u:%u:%f:%f\n", k, test_ecc_curves_bits[k],
            eccsign_results[thread_id][0], eccsign_results[thread_id][1]);
        else{
            printf("%4u bit ecc (%s)",test_ecc_curves_bits[k], test_ecc_curves_names[k]);
            for(i = 0; ecc_ops[i] != NULL; i++){
                printf(" %8.5fs", eccsign_results[thread_id][i]);
            }
            for(i = 0; ecc_ops[i] != NULL; i++){
                printf(" %8.2f", 1.0 / eccsign_results[thread_id][i]);
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
int do_multi_buf_ecc(char *buf, int n)
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
        eccsign_results[k][0] = 1 / (1 / eccsign_results[k][0] + 1 / d);
    else
        eccsign_results[k][0] = d;

    d = atof(sstrsep(&p, sep));
    if (n)
        eccsign_results[k][1] = 1 / (1 / eccsign_results[k][1] + 1 / d);
    else
        eccsign_results[k][1] = d;
    ret = 0;
    } else if (strncmp(buf, "+F7:", 4) == 0) {
    p = buf + 4;
    k = atoi(sstrsep(&p, sep));
    sstrsep(&p, sep);

    d = atof(sstrsep(&p, sep));
    if (n)
        eccenc_results[k][0] = 1 / (1 / eccenc_results[k][0] + 1 / d);
    else
        eccenc_results[k][0] = d;

    d = atof(sstrsep(&p, sep));
    if (n)
        eccenc_results[k][1] = 1 / (1 / eccenc_results[k][1] + 1 / d);
    else
        eccenc_results[k][1] = d;

    ret = 0;
    }

    return ret;
}

/*

*/


