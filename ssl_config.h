#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

// ============================================================================
// SERVER: Netdata functions
// mbedTLS config — TLS 1.3 ONLY
// Target suite: ECDHE (X25519) key exchange, ECDSA P-256 signature,
//               ChaCha20-Poly1305 AEAD
// Technical University of Kosice | Nikita Kuropatkin
// ============================================================================

// NOTE: Do NOT include check_config.h here.
// mbedTLS 3.x build_info.h includes it automatically after
// setting up internal defines. Including it here causes it to
// run too early and fail with false "prerequisites missing" errors.

#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_DEPRECATE)
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#define MBEDTLS_SSL_CLI_C

// ============================================================================
// TLS 1.3 CORE
// ============================================================================
#define MBEDTLS_SSL_PROTO_TLS1_3                  // Enable TLS 1.3 (TLS 1.2 dropped entirely)
#define MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE      // Sends a dummy CCS so middleboxes that
                                                    // only understand TLS 1.2 record framing
                                                    // don't choke on the handshake
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED  // ← this was missing.
                                                                  // Without it, ZERO key
                                                                  // exchange modes are
                                                                  // compiled in for TLS 1.3 —
                                                                  // cert-based ECDHE handshakes
                                                                  // are literally impossible,
                                                                  // regardless of the group/
                                                                  // ciphersuite config below.

#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE          // Required by mbedTLS's TLS 1.3 implementation

// TLS 1.3's key schedule runs through PSA + HKDF instead of the legacy
// TLS 1.2 PRF, so both are mandatory even though you never call PSA directly.
#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_HKDF_C

// Your board provides its own hardware entropy (pico_entropy()) and is built
// with MBEDTLS_NO_PLATFORM_ENTROPY below. PSA needs its OWN random source
// hooked in separately — this tells PSA to call your
// mbedtls_psa_external_get_random() implementation instead of trying to
// set up its own entropy/DRBG stack.
#define MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG

// Session tickets: TLS 1.3's server-side session resumption code path
// references struct fields that only exist when this is defined. Needed
// to avoid the ssl_tls13_server.c compile errors from before.
#define MBEDTLS_SSL_SESSION_TICKETS

// ============================================================================
// KEY EXCHANGE — ECDHE with X25519 only
// ============================================================================
#define MBEDTLS_ECDH_C                             // Required for the ECDHE key exchange
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED           // Enables X25519

// NOTE: there is no MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED here — that
// macro is a TLS 1.2 ciphersuite-naming concept. TLS 1.3 negotiates the
// key-exchange group (X25519) and the signature algorithm (ECDSA P-256)
// as two independent extensions, not as one combined "key exchange" macro.
// Restrict the actual negotiated group to X25519 only in code, via:
//   mbedtls_ssl_conf_groups(&conf, x25519_only);
// in https_init_system().

// ============================================================================
// SIGNATURE / CERTIFICATE — ECDSA P-256 (matches your existing srv_crt_pem)
// ============================================================================
#define MBEDTLS_ECDSA_C                             // Required for EC certificate signing
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED             // P-256 — the curve your cert/key uses
#define MBEDTLS_ECP_C                                // Underlying EC point arithmetic

// ============================================================================
// AEAD CIPHER — ChaCha20-Poly1305 only (no AES; better perf without AES-NI
// on Cortex-M33)
// ============================================================================
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_CHACHAPOLY_C                         // Combined AEAD mode

// ============================================================================
// SUPPORTING CRYPTO PRIMITIVES (parsing, hashing, bignum — all still needed)
// ============================================================================
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CONSTANT_TIME_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_AES_C   // required internally by CTR_DRBG (AES-256-CTR based DRBG core)
#define MBEDTLS_MD_C
#define MBEDTLS_OID_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_SHA256_C                             // Cert signature hash + TLS 1.3 handshake hash

// ============================================================================
// X.509 — just enough to parse and present your own self-signed cert
// ============================================================================
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C

// ============================================================================
// TLS PROTOCOL / ROLE
// ============================================================================
#define MBEDTLS_SSL_ALL_ALERT_MESSAGES
#define MBEDTLS_SSL_SRV_C                            // Server mode only (client code dropped)
#define MBEDTLS_SSL_TLS_C

// ============================================================================
// ENTROPY / RNG
// ============================================================================
#define MBEDTLS_NO_PLATFORM_ENTROPY                  // we provide pico_entropy() for ctr_drbg,
                                                      // and mbedtls_psa_external_get_random()
                                                      // for PSA (see MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)

// ============================================================================
// MISC
// ============================================================================
#define MBEDTLS_ERROR_STRERROR_DUMMY

// ============================================================================
// LIMITS
// ============================================================================
#define MBEDTLS_MPI_MAX_SIZE       1024

// NO #include "mbedtls/check_config.h" — mbedTLS 3.x does this for you

#endif /* MBEDTLS_CONFIG_H */
