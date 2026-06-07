// SERVER                         //
// Blacklist functions            //
// Ver. 0.4                       //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <frame.h>

/* ============================================================
 * CRYPTO HELPERS
 * ============================================================ */
 void chaskey_mac_wrap(
    const uint8_t base[16],
    const uint8_t *msg,
    size_t msg_len,
    uint8_t out[16]);
void derive_sess_key(
    const uint8_t *ikm,
    size_t ikm_len,
    const uint8_t salt[16],
    const uint8_t *info,
    size_t info_len,
    uint8_t *okm,
    size_t okm_len);

 void rotate_key(
    uint8_t new_k[16],
    const uint8_t curr_k[16],
    uint32_t cnt);

 void build_salt(uint32_t n1, uint32_t n2, uint8_t salt[16]);

 uint64_t frame_tag(frame_t *f, const uint8_t *key);
 #endif
