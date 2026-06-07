// SERVER                         //
// Netdata functions              //
// Ver. 0.4                       //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //


#ifndef HTTPS_HANDSHAKE_H
#define HTTPS_HANDSHAKE_H

// #include "mbedtls/ssl.h"
// #include "mbedtls/ctr_drbg.h"
// // mbedTLS global contexts
// mbedtls_ssl_context ssl;
// mbedtls_ssl_config conf;
// mbedtls_ctr_drbg_context ctr_drbg;
// mbedtls_x509_crt srvcert;
// mbedtls_pk_context pkey;

// Helper functions for mbedTLS (Copy these from your original https.c)
static int tls_recv(void *ctx, unsigned char *buf, size_t len);
static int tls_send(void *ctx, const unsigned char *buf, size_t len);

static int pico_entropy(void *data, unsigned char *output, size_t len) ;

// 1. One-time Initialization
void https_init_system() ;

// 2. The polling logic (called every loop)
void https_poll_task() ;
#endif