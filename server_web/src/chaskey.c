// SERVER                         //
// Chaskey                        //
// Ver. 0.4                       //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //

#include "chaskey.h"
#include <string.h>

/* Rotate left (32-bit) */
#define ROTL32(x,b) (uint32_t)(((x) << (b)) | ((x) >> (32 - (b))))

/* Chaskey round */
#define ROUND do { \
    v[0] += v[1]; v[1] = ROTL32(v[1], 5);  v[1] ^= v[0]; v[0] = ROTL32(v[0],16); \
    v[2] += v[3]; v[3] = ROTL32(v[3], 8);  v[3] ^= v[2]; \
    v[0] += v[3]; v[3] = ROTL32(v[3],13);  v[3] ^= v[0]; \
    v[2] += v[1]; v[1] = ROTL32(v[1], 7);  v[1] ^= v[2]; v[2] = ROTL32(v[2],16); \
} while (0)

/* 12-round permutation */
#define PERMUTE do { \
    ROUND; ROUND; ROUND; ROUND; ROUND; ROUND; \
    ROUND; ROUND; ROUND; ROUND; ROUND; ROUND; \
} while (0)

/* GF(2^128) constant */
static const uint32_t C[2] = { 0x00, 0x87 };

/* Multiply by 2 in GF(2^128) */
#define TIMESTWO(out,in) do { \
    out[0] = (in[0] << 1) ^ C[in[3] >> 31]; \
    out[1] = (in[1] << 1) | (in[0] >> 31); \
    out[2] = (in[2] << 1) | (in[1] >> 31); \
    out[3] = (in[3] << 1) | (in[2] >> 31); \
} while (0)

void chaskey_subkeys(uint32_t k1[4],
                     uint32_t k2[4],
                     const uint32_t k[4])
{
    TIMESTWO(k1, k);
    TIMESTWO(k2, k1);
}

void chaskey_mac(uint8_t *tag,
                 size_t taglen,
                 const uint8_t *msg,
                 size_t msglen,
                 const uint32_t k[4],
                 const uint32_t k1[4],
                 const uint32_t k2[4])
{
    uint32_t v[4];
    const uint32_t *M = (const uint32_t *)msg;
    const uint32_t *end;
    const uint32_t *last;
    const uint32_t *l;
    uint8_t block[16];
    size_t i;

    if (taglen > 16) taglen = 16;

    /* Initialize state */
    v[0] = k[0];
    v[1] = k[1];
    v[2] = k[2];
    v[3] = k[3];

    if (msglen >= 16) {
        end = M + ((msglen - 1) / 16) * 4;

        while (M != end) {
            v[0] ^= M[0];
            v[1] ^= M[1];
            v[2] ^= M[2];
            v[3] ^= M[3];
            PERMUTE;
            M += 4;
        }
    }

    if (msglen != 0 && (msglen & 0xF) == 0) {
        l = k1;
        last = M;
    } else {
        l = k2;
        memset(block, 0, sizeof(block));
        for (i = 0; i < msglen % 16; i++) {
            block[i] = ((const uint8_t *)M)[i];
        }
        block[i] = 0x01;
        last = (const uint32_t *)block;
    }

    v[0] ^= last[0];
    v[1] ^= last[1];
    v[2] ^= last[2];
    v[3] ^= last[3];

    v[0] ^= l[0];
    v[1] ^= l[1];
    v[2] ^= l[2];
    v[3] ^= l[3];

    PERMUTE;

    v[0] ^= l[0];
    v[1] ^= l[1];
    v[2] ^= l[2];
    v[3] ^= l[3];

    memcpy(tag, v, taglen);
}
