// SERVER                         //
// Netdata functions              //
// Ver. 0.5                       //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //

// mbedTLS
#include "mbedtls/ssl.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"

#include "certs.h"
#include "page.h"
#include "pico/rand.h"
#include "port_common.h"
#include "socket.h"
#include "wizchip_spi.h"
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "parameters.h"
#include <stdio.h>
#include "debug.h"
#include "sntp.h"
#include "sntp_time.h"

// External global variables
extern port_mode_t current_port_mode;
uint8_t https_client_ip[4] = {0};
extern stats_tracker_t hourly_stats;
extern volatile datetime g_current_time;
extern volatile uint32_t g_uptime_sec;

// Sensor measurements values, defined in sensor_data.c
extern volatile float g_sensor_temp;
extern volatile int   g_sensor_co2;
extern volatile float g_sensor_pm1;
extern volatile float g_sensor_pm2p5;

extern absolute_time_t https_last_activity;

// mbedTLS global contexts
extern mbedtls_ssl_context ssl;
mbedtls_ssl_config conf;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_x509_crt srvcert;
mbedtls_pk_context pkey;
static int https_sock_id = SOCK_HTTPS;

static bool tls_handshake_done = false;

// Idle timeout — must be longer than Keep-Alive timeout sent to browser
#define HTTPS_IDLE_TIMEOUT_US  35000000ULL   // 35 s

// Helper: returns true for any error code that means "peer closed cleanly"
// -0x7780 = CONN_EOF, -0x7708 = PEER_CLOSE_NOTIFY
// Also catches -0x7900 (FATAL_ALERT) which Chrome sends on self-signed cert
// rejection — we don't want that to close the socket permanently either.
static inline bool tls_is_soft_close(int ret) {
    return (ret == MBEDTLS_ERR_SSL_CONN_EOF           ||  // -0x7280
            ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY  ||  // -0x7880
            ret == MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE|| 
            ret == 0);
}


psa_status_t mbedtls_psa_external_get_random(mbedtls_psa_external_random_context_t *ctx,
                                              uint8_t *output, size_t output_size,
                                              size_t *output_length) {
    (void)ctx;
    size_t i = 0;
    while (i < output_size) {
        uint64_t r = get_rand_64();
        size_t chunk = (output_size - i) < 8 ? (output_size - i) : 8;
        memcpy(output + i, &r, chunk);
        i += chunk;
    }
    *output_length = output_size;
    return PSA_SUCCESS;
}

/*
 * Function: tls_recv
 * Description: mbedTLS RX callback — bridges mbedTLS with the WIZnet socket layer.
 */
static int tls_recv(void *ctx, unsigned char *buf, size_t len) {
    int sock = *(int *)ctx;

    uint16_t rx_len = getSn_RX_RSR(sock);
    if (rx_len == 0) {
        uint8_t sr = getSn_SR(sock);
        if (sr == SOCK_CLOSE_WAIT || sr == SOCK_CLOSED) {
            return MBEDTLS_ERR_SSL_CONN_EOF;
        }
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    if (len > rx_len) {
        len = rx_len;
    }

    int32_t recvd = recv(sock, (uint8_t *)buf, (uint16_t)len);
    if (recvd > 0) {
        return recvd;
    }

    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

/*
 * Function: tls_send
 * Description: mbedTLS TX callback — bridges mbedTLS with the WIZnet socket layer.
 */
static int tls_send(void *ctx, const unsigned char *buf, size_t len) {
    int sock = *(int *)ctx;

    uint16_t tx_free = getSn_TX_FSR(sock);
    if (tx_free == 0) {
        uint8_t sr = getSn_SR(sock);
        if (sr == SOCK_CLOSE_WAIT || sr == SOCK_CLOSED) {
            return MBEDTLS_ERR_SSL_CONN_EOF;
        }
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }

    if (len > tx_free) {
        len = tx_free;
    }

    int32_t sent = send(sock, (uint8_t *)buf, (uint16_t)len);
    if (sent > 0) {
        return sent;
    }

    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

/*
 * Function: pico_entropy
 * Description: Hardware entropy source for mbedTLS using the Pico's built-in RNG.
 */

static int pico_entropy(void *data, unsigned char *output, size_t len)
{
    (void)data;
    size_t i = 0;
    while (i < len) {
        uint64_t r = get_rand_64();
        size_t chunk;
        if ((len - i) < 8) {
            chunk = len - i;
        } else {
            chunk = 8;
        }
        memcpy(output + i, &r, chunk);
        i += chunk;
    }
    return 0;
}


/*
 * Function: tls_soft_reset
 * Description: Resets mbedTLS session state without touching the TCP socket.
 *              Call this whenever Chrome closes the TLS layer but TCP stays up.
 */
static void tls_soft_reset(void) {
    mbedtls_ssl_session_reset(&ssl);
    // Re-register BIO — session_reset() clears it in mbedTLS 2.x
    mbedtls_ssl_set_bio(&ssl, &https_sock_id, tls_send, tls_recv, NULL);
    tls_handshake_done = false;
}

/*
 * Function: https_init_system
 * Description: One-time initialisation of mbedTLS structures, certificates, and keys.
 */
void https_init_system() {
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);

    mbedtls_ctr_drbg_seed(&ctr_drbg, pico_entropy, NULL,
                           (const unsigned char *)"wiznet-srv", 10);
    mbedtls_x509_crt_parse(&srvcert,
                            (const unsigned char *)srv_crt_pem,
                            sizeof(srv_crt_pem));
    mbedtls_pk_parse_key(&pkey,
                          (const unsigned char *)srv_key_pem,
                          sizeof(srv_key_pem),
                          NULL, 0, pico_entropy, &ctr_drbg);

    mbedtls_ssl_config_defaults(&conf,
                                 MBEDTLS_SSL_IS_SERVER,
                                 MBEDTLS_SSL_TRANSPORT_STREAM,
                                 MBEDTLS_SSL_PRESET_DEFAULT);

    // --- Key exchange: X25519 only -----------------------------------
    static const uint16_t groups[] = {
        MBEDTLS_SSL_IANA_TLS_GROUP_X25519,
        0   // zero-terminated
    };
    mbedtls_ssl_conf_groups(&conf, groups);

    static const int ciphersuites[] = {
    MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256,   // 0x1303 — the correct TLS 1.3 ID
    0
    };
    mbedtls_ssl_conf_ciphersuites(&conf, ciphersuites);

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey);
    mbedtls_ssl_setup(&ssl, &conf);

    mbedtls_ssl_set_bio(&ssl, &https_sock_id, tls_send, tls_recv, NULL);
}

/*
 * Function: https_poll_task
 * Description: Non-blocking polling loop for HTTPS server state transitions.
 *
 *   CLOSED      → open socket, listen
 *   CLOSE_WAIT  → send TLS close_notify, disconnect (→ CLOSED next poll)
 *   ESTABLISHED + no handshake → TLS handshake
 *   ESTABLISHED + handshake OK → read request, send response
 *
 * Chrome behaviour: it sends close_notify (or just TCP FIN) between every
 * auto-refresh even on keep-alive connections.  We handle this by doing a
 * TLS soft-reset (session_reset + re-register BIO) WITHOUT closing the TCP
 * socket, so the re-handshake starts immediately on the next poll tick and
 * the port is never left unguarded.
 */
void https_poll_task() {
    if (current_port_mode != PORT_MODE_HTTPS) {
        return;
    }

    uint8_t sr = getSn_SR(SOCK_HTTPS);
    int ret;
        uint8_t dip[4];
        static uint64_t tls_hs_start_us = 0;

    // ── CLOSED: open socket and start listening ───────────────────────────────
    if (sr == SOCK_CLOSED) {
        tls_handshake_done = false;
        socket(SOCK_HTTPS, Sn_MR_TCP, HTTPS_PORT, 0);
        listen(SOCK_HTTPS);
        sleep_us(100);
        return;
    }

    if (sr == SOCK_SYNRECV) {
            getSn_DIPR(SOCK_HTTPS, dip); 

            // STRICT WHITELIST FILTER: If the IP doesn't match the allowed client, kill it instantly
            if (memcmp(dip, https_client_ip, 4) != 0) {
                close(SOCK_HTTPS);
                async_print("SECURITY: Unauthorized IP %d.%d.%d.%d dropped instantly in HTTPS SYNRECV\n",
                            dip[0], dip[1], dip[2], dip[3]);
                
                disconnect(SOCK_HTTPS);
        mbedtls_ssl_session_reset(&ssl);
        mbedtls_ssl_set_bio(&ssl, &https_sock_id, tls_send, tls_recv, NULL);
        tls_handshake_done = false;
        return;
            }
            return;
        }

    // ── CLOSE_WAIT: browser sent TCP FIN (tab closed, navigated away, etc.) ──
    if (sr == SOCK_CLOSE_WAIT) {
        mbedtls_ssl_close_notify(&ssl);   // best-effort; ignore return value
        disconnect(SOCK_HTTPS);
        mbedtls_ssl_session_reset(&ssl);
        mbedtls_ssl_set_bio(&ssl, &https_sock_id, tls_send, tls_recv, NULL);
        tls_handshake_done = false;
        // Socket → CLOSED on next poll, which reopens and listens immediately
        return;
    }

    

    // ── Any transient state (LISTEN, SYN_RECV, TIME_WAIT…): just wait ────────
    if (sr != SOCK_ESTABLISHED) {
        return;
    }

    // ── ESTABLISHED ───────────────────────────────────────────────────────────

    // --- IP whitelist: drop anyone who isn't the authorised client ------------
    getSn_DIPR(SOCK_HTTPS, dip);
    if (memcmp(dip, https_client_ip, 4) != 0) {
        async_print("HTTPS rejected non-whitelisted client\n");
        disconnect(SOCK_HTTPS);
        mbedtls_ssl_session_reset(&ssl);
        mbedtls_ssl_set_bio(&ssl, &https_sock_id, tls_send, tls_recv, NULL);
        tls_handshake_done = false;
        return;
    }

    // --- Idle timeout: release stale sessions so the slot never locks up ------
    if (tls_handshake_done) {
        if (absolute_time_diff_us(https_last_activity, get_absolute_time())
                > HTTPS_IDLE_TIMEOUT_US) {
            async_print("HTTPS idle timeout — closing session\n");
            mbedtls_ssl_close_notify(&ssl);
            disconnect(SOCK_HTTPS);
            mbedtls_ssl_session_reset(&ssl);
            mbedtls_ssl_set_bio(&ssl, &https_sock_id, tls_send, tls_recv, NULL);
            tls_handshake_done = false;
            return;
        }
    }

    // --- TLS Handshake — runs once per TCP connection (or after soft-reset) ---
    if (!tls_handshake_done) {

        // Guard: if TCP is already tearing down don't even try
        uint8_t cur_sr = getSn_SR(SOCK_HTTPS);
        if (cur_sr == SOCK_CLOSE_WAIT || cur_sr == SOCK_CLOSED) {
            tls_soft_reset();
            return;
        }

        if (tls_hs_start_us == 0) {
            tls_hs_start_us = to_us_since_boot(get_absolute_time());
        }

        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {

            uint64_t elapsed_us = to_us_since_boot(get_absolute_time()) - tls_hs_start_us;

            // Timeout guard — revert to stealth if handshake takes too long
            if (elapsed_us > 15000000ULL) {
                async_print("HTTPS handshake timeout — reverting to Stealth Mode\n");
                current_port_mode = PORT_MODE_CUSTOM;
                close(SOCK_HTTPS);
                tls_hs_start_us = 0;
                mbedtls_ssl_session_reset(&ssl);
                mbedtls_ssl_set_bio(&ssl, &https_sock_id, tls_send, tls_recv, NULL);
                tls_handshake_done = false;
                return;
            }

            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                // Not enough data yet — yield and come back next poll tick
                // (do NOT tight_loop here; that starves other tasks)
                return;
            }

            // Anything else is either a soft peer-close or a real fatal error
            if (tls_is_soft_close(ret)) {
                // Chrome closed before we finished — soft-reset and wait for
                // the CLOSE_WAIT branch to cycle the TCP socket
                async_print("HTTPS handshake soft-close: -0x%04X\n", -ret);
                tls_soft_reset();
                return;
            }

            // Genuine fatal handshake error — log it and hard-close
            char err_buf[80];
            mbedtls_strerror(ret, err_buf, sizeof(err_buf));
            tls_hs_start_us = 0;
            async_print("HTTPS handshake fatal: -0x%04X %s\n", -ret, err_buf);
            close(SOCK_HTTPS);
            mbedtls_ssl_session_reset(&ssl);
            mbedtls_ssl_set_bio(&ssl, &https_sock_id, tls_send, tls_recv, NULL);
            tls_handshake_done = false;
            return;
        }

        tls_handshake_done = true;
        tls_hs_start_us = 0;
        https_last_activity = get_absolute_time();
        async_print("HTTPS handshake OK — persistent session established\n");
    }

    // --- Non-blocking read: bail out if no HTTP request has arrived yet -------
    static unsigned char buf[4096];
    ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf) - 1);

    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return;  // Nothing ready — come back on next poll tick
    }

    if (tls_is_soft_close(ret)) {
        // Chrome closed the TLS layer (close_notify or clean EOF).
        // Reply with our own close_notify, soft-reset TLS, keep TCP alive.
        // The next poll tick immediately re-enters the handshake block.
        async_print("HTTPS read soft-close: -0x%04X\n", -ret);
        mbedtls_ssl_close_notify(&ssl);
        tls_soft_reset();
        return;
    }

    if (ret < 0) {
        // Genuine fatal read error — hard-close everything
        char err_buf[80];
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        async_print("HTTPS read fatal: -0x%04X %s\n", -ret, err_buf);
        close(SOCK_HTTPS);
        mbedtls_ssl_session_reset(&ssl);
        mbedtls_ssl_set_bio(&ssl, &https_sock_id, tls_send, tls_recv, NULL);
        tls_handshake_done = false;
        return;
    }

    // --- Request received: format uptime string -------------------------------
    uint32_t ud = g_uptime_sec / 86400;
    uint32_t uh = (g_uptime_sec % 86400) / 3600;
    uint32_t um = (g_uptime_sec % 3600) / 60;
    uint32_t us = g_uptime_sec % 60;

    char uptime_str[32];
    if (ud > 0)
        snprintf(uptime_str, sizeof(uptime_str), "%ud %02u:%02u:%02u", ud, uh, um, us);
    else
        snprintf(uptime_str, sizeof(uptime_str), "%02u:%02u:%02u", uh, um, us);

    // --- Format device IP string ----------------------------------------------
    uint8_t my_ip[4];
    getSIPR(my_ip);
    char ip_str[16];
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
             my_ip[0], my_ip[1], my_ip[2], my_ip[3]);

    uint8_t max_socks_last_hour = hourly_stats.peak_sockets_last;

    // --- Build HTML body so Content-Length can be calculated exactly ----------
    static char html_body[ETHERNET_BUF_MAX_SIZE * 2];
    snprintf(html_body, sizeof(html_body), html_page_template,
             g_current_time.yy, g_current_time.mo, g_current_time.dd,
             g_current_time.hh, g_current_time.mm, g_current_time.ss,
             uptime_str, max_socks_last_hour,
             g_sensor_temp, g_sensor_co2, g_sensor_pm1, g_sensor_pm2p5,
             ip_str);

    int body_len = strlen(html_body);

    // --- Prepend HTTP headers with exact Content-Length -----------------------
    static char page_buffer[ETHERNET_BUF_MAX_SIZE * 2 + 128];
    int header_len = snprintf(page_buffer, sizeof(page_buffer),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %d\r\n"
        "Connection: keep-alive\r\n"
        "Keep-Alive: timeout=30, max=100\r\n\r\n",
        body_len);

    memcpy(page_buffer + header_len, html_body, body_len);
    int total_len = header_len + body_len;

    // --- Send full response ---------------------------------------------------
    int written = 0;
    while (written < total_len) {
        ret = mbedtls_ssl_write(&ssl,
                (const unsigned char *)(page_buffer + written),
                total_len - written);
        if (ret > 0) {
            written += ret;
        } else if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
                   ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            // Fatal write error — session cleaned up on next poll tick
            break;
        }
    }

    // Session stays open — browser reuses the TLS connection on next refresh
    https_last_activity = get_absolute_time();
}
