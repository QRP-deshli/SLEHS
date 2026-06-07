// SERVER                         //
// Blacklist functions            //
// Ver. 0.4                       //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "parameters.h"
#include "port_common.h"
#include "frame.h"
#include "chaskey.h"

// Context string used during key rotation derivation
static const uint8_t ROT_INFO[] = "CHASKEY-ROTATION-KEY";

// Fixed constant appended to rotation salt generation
static const uint8_t ROT_CONST[] = {0x01,0x02,0x03,0x04};

// External cryptographic material
extern const uint8_t MASTER_KEY[16];
extern const uint8_t SESS_INFO[];

/* ============================================================
 * CRYPTO HELPERS
 * ============================================================ */

/*
 * Function: chaskey_mac_wrap
 * Description: Convenience wrapper around the Chaskey MAC implementation.
 * Generates the required subkeys and computes a 128-bit MAC over the
 * provided message using the supplied base key.
 *
 * Parameters:
 * base    - 128-bit Chaskey key.
 * msg     - Input message buffer.
 * msg_len - Length of the message in bytes.
 * out     - Output buffer for the generated 128-bit MAC.
 */
void chaskey_mac_wrap(
    const uint8_t base[16],
    const uint8_t *msg,
    size_t msg_len,
    uint8_t out[16])
{
    uint32_t k[4];
    uint32_t k1[4];
    uint32_t k2[4];

    // Convert byte key into Chaskey internal format
    memcpy(k, base, 16);

    // Generate Chaskey subkeys
    chaskey_subkeys(k1, k2, k);

    // Compute MAC
    chaskey_mac(out, 16, msg, msg_len, k, k1, k2);
}

/*
 * Function: derive_sess_key
 * Description: HKDF-like key derivation routine based on Chaskey MAC.
 * Produces output keying material from input key material, salt,
 * and optional context information.
 *
 * Parameters:
 * ikm      - Input key material.
 * ikm_len  - Length of input key material.
 * salt     - Salt value used during extraction.
 * info     - Context/application-specific information.
 * info_len - Length of context information.
 * okm      - Output key material buffer.
 * okm_len  - Requested output length.
 */
void derive_sess_key(
    const uint8_t *ikm,
    size_t ikm_len,
    const uint8_t salt[16],
    const uint8_t *info,
    size_t info_len,
    uint8_t *okm,
    size_t okm_len)
{
    uint8_t prk[16];
    uint8_t t[16];
    uint8_t ctr = 1;
    size_t prod = 0;
    uint8_t buf[256];
    size_t pos;
    size_t n;

    // Initialize previous block with zeros
    memset(t, 0, 16);

    /* Extract */

    // Derive pseudo-random key from input material and salt
    chaskey_mac_wrap(salt, ikm, ikm_len, prk);

    /* Expand */

    // Generate output blocks until requested length is reached
    while (prod < okm_len) {
        pos = 0;

        // Include previous output block
        memcpy(buf + pos, t, 16);
        pos = pos + 16;

        // Append optional context information
        if (info_len > 0) {
            memcpy(buf + pos, info, info_len);
            pos = pos + info_len;
        }

        // Append block counter
        buf[pos] = ctr;
        pos = pos + 1;

        // Generate next block
        chaskey_mac_wrap(prk, buf, pos, t);

        // Determine number of bytes to copy
        n = okm_len - prod;
        if (n > 16) {
            n = 16;
        }

        // Copy generated block into output buffer
        memcpy(okm + prod, t, n);

        prod = prod + n;
        ctr = ctr + 1;
    }
}

/*
 * Function: rotate_key
 * Description: Performs deterministic session key rotation after
 * a configured number of frames or events. If rotation is not required,
 * the current key is copied unchanged.
 *
 * Parameters:
 * new_k  - Output buffer for the rotated key.
 * curr_k - Current session key.
 * cnt    - Rotation counter value.
 */
void rotate_key(
    uint8_t new_k[16],
    const uint8_t curr_k[16],
    uint32_t cnt)
{
    uint8_t salt[16];
    uint32_t blk_idx;
    uint32_t remainder;

    // Check whether rotation boundary has been reached
    remainder = cnt % ROT_INTERVAL;

    if (remainder != 0) {
        // No rotation required
        memcpy(new_k, curr_k, 16);
        return;
    }

    // Determine current rotation block index
    blk_idx = cnt / ROT_INTERVAL;

    // Construct unique salt for this rotation step
    memcpy(salt, curr_k, 8);
    memcpy(salt + 8, &blk_idx, 4);

    // Append fixed rotation constants
    salt[12] = ROT_CONST[0];
    salt[13] = ROT_CONST[1];
    salt[14] = ROT_CONST[2];
    salt[15] = ROT_CONST[3];

    // Derive the next session key
    derive_sess_key(
        curr_k, KEY_SIZE,
        salt,
        ROT_INFO, sizeof(ROT_INFO) - 1,
        new_k, KEY_SIZE
    );
}

/*
 * Function: build_salt
 * Description: Creates a 128-bit salt value from two 32-bit nonces.
 * The nonce pair is duplicated to fill the entire salt buffer.
 *
 * Parameters:
 * n1   - First nonce.
 * n2   - Second nonce.
 * salt - Output salt buffer.
 */
void build_salt(uint32_t n1, uint32_t n2, uint8_t salt[16])
{
    memcpy(salt + 0, &n1, 4);
    memcpy(salt + 4, &n2, 4);
    memcpy(salt + 8, &n1, 4);
    memcpy(salt + 12, &n2, 4);
}

/*
 * Function: frame_tag
 * Description: Computes a 64-bit authentication tag for a frame
 * using the Chaskey MAC algorithm. The existing tag field is
 * temporarily cleared to ensure it is not included in the MAC input.
 *
 * Parameters:
 * f   - Pointer to the frame structure.
 * key - Authentication key.
 *
 * Returns:
 * First 64 bits of the generated 128-bit Chaskey MAC.
 */
uint64_t frame_tag(frame_t *f, const uint8_t *key)
{
    uint8_t tag128[16];
    uint64_t tag64;
    uint64_t saved;
    size_t mac_len;
    uint32_t k[4];
    uint32_t k1[4];
    uint32_t k2[4];

    // Save original tag value
    saved = f->tag;

    // Exclude current tag field from MAC computation
    f->tag = 0;

    // Determine authenticated frame length
    if (f->len != 0) {
        mac_len = offsetof(frame_t, data) + f->len;
    } else {
        mac_len = offsetof(frame_t, data);
    }

    // Prepare Chaskey key material
    memcpy(k, key, 16);
    chaskey_subkeys(k1, k2, k);

    // Compute full 128-bit MAC
    chaskey_mac(
        tag128, 16,
        (const uint8_t *)f, mac_len,
        k, k1, k2
    );

    // Restore original frame tag
    f->tag = saved;

    // Truncate MAC to 64 bits for transmission/storage
    memcpy(&tag64, tag128, sizeof(tag64));

    return tag64;
}