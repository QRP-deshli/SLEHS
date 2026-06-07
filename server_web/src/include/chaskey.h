// SERVER                         //
// Chaskey                        //
// Ver. 0.4                       //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //

#ifndef CHASKEY_H
#define CHASKEY_H

#include <stdint.h>
#include <stddef.h>

/*
 * Chaskey-12 MAC
 *
 * Assumptions:
 *  - little-endian architecture
 *  - unaligned memory access is allowed
 *
 * Key size: 128-bit (16 bytes)
 * Tag size: up to 16 bytes
 */

/* Generate Chaskey subkeys k1 and k2 from master key k */
void chaskey_subkeys(uint32_t k1[4],
                     uint32_t k2[4],
                     const uint32_t k[4]);

/* Compute Chaskey MAC
 *
 * tag     : output buffer
 * taglen  : number of bytes written to tag (<= 16)
 * msg     : message buffer
 * msglen  : message length in bytes
 * k       : master key (4 x uint32_t)
 * k1, k2  : subkeys derived from k
 */
void chaskey_mac(uint8_t *tag,
                 size_t taglen,
                 const uint8_t *msg,
                 size_t msglen,
                 const uint32_t k[4],
                 const uint32_t k1[4],
                 const uint32_t k2[4]);

#endif /* CHASKEY_H */
