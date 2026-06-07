// SERVER                         //
// Blacklist functions            //
// Ver. 0.4                       //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "parameters.h"

/* Wiznet dependencies */
#include "frame.h"
#include "timer.h"
#include "hardware/watchdog.h"
#include "hardware/timer.h"
#include "hardware/regs/watchdog.h"
#include "blacklist.h"
#include "debug.h"
#include "network_data.h"
#include "pico/rand.h"
#include "crypto.h"
#include "restart.h"
#include "socket.h"
#include "pico/stdlib.h"

extern absolute_time_t https_start_time; 
extern sess_t sess[MAX_SOCKETS];
extern uint8_t MASTER_KEY[KEY_SIZE];
extern bool https_init_flag;

// Label for HKDF-like derivation //
extern uint8_t SESS_INFO[];
#define SESS_INFO_LEN  19U
extern uint64_t synrecv_start_us[MAX_SOCKETS];
extern restart_data_t res_data;   // Var for restart value

extern stats_tracker_t hourly_stats;
extern absolute_time_t last_stats_reset;

extern port_mode_t current_port_mode;
extern uint8_t https_client_ip[4];
extern absolute_time_t https_timeout;

extern hourly_record_t stats_history[];
extern uint16_t history_count;
extern uint16_t history_head;

/* ============================================================
 * FUNCTION: is_valid_cmd
 * Verifies that the received command byte matches one of the 
 * supported application protocol commands. Returns true if 
 * valid, false otherwise.
 * ============================================================ */
static bool is_valid_cmd(uint8_t cmd)
{   
    if (cmd == CMD_INIT)  return true; // Keepalive response
    if (cmd == CMD_AUTH)  return true; // Authentication request
    if (cmd == CMD_DATA)  return true; // Application data payload
    if (cmd == CMD_ACK)   return true; // Protocol acknowledgement
    if (cmd == CMD_PING)  return true; // Keepalive request
    if (cmd == CMD_PONG)  return true; // Keepalive response
    if (cmd == CMD_CLOSE) return true; // Keepalive response
    
    return false; // Unknown command
}

/* ============================================================
 * FUNCTION: init_frame
 * Handles the initial handshake step. It validates the incoming 
 * protocol framing, stores the client's nonce, generates a unique 
 * server challenge nonce, initializes the session state, and 
 * transmits a response frame back to the client. 
 * ============================================================ */
bool init_frame(uint8_t sk, frame_t *rx, frame_t *tx, sess_t *s) 
{
    uint32_t cli_nonce;

    // Validate protocol magic number to ensure packet belongs to this system
    if (rx->magic != PROTOCOL_MAGIC_RECEIVE) return false;

    // Check version compatibility
    if (rx->ver != PROTOCOL_VER) return false;

    // Prevent buffer overflow by checking length against max MTU
    if (rx->len > MAX_PAYLOAD) return false;

    // Ensure command is supported
    if (!is_valid_cmd(rx->cmd)) return false;
    
    // === CMD_INIT — Client sends its nonce first ===
    if (rx->cmd == CMD_INIT) {
        if (rx->len != 4) {
            async_print("INIT: bad length\n");
            return false;
        }

        // Read client's nonce (we skip tag check here — no key yet)
        if (read_pico(sk, rx->data, 4) != 0) {
            async_print("Socket %d: read header failed (normal close / partial) - closing gracefully\n", sk);
            close(sk);
            s->active = false;
            s->init_verified = false;
            return false;
        }    
        memcpy(&cli_nonce, rx->data, 4);

        // Store it and generate our challenge
        s->client_nonce  = cli_nonce;
        s->nonce         = get_rand_32();          // server's fresh nonce
        s->rx_cnt        = rx->cnt;                // remember client's counter
        s->tx_cnt        = 0;
        s->active        = true;
        s->last_act      = get_absolute_time();
        s->send_data     = false;
        s->wait_ack      = false;
        s->ping_sent     = false;
        s->init_verified = true;
        
        async_print("INIT OK. Client nonce: 0x%08X | Server nonce: 0x%08X\n", cli_nonce, s->nonce);

        // === Prepare reply (same CMD_INIT) ===
        memset(tx, 0, sizeof(*tx));
        tx->magic = PROTOCOL_MAGIC_SEND;
        tx->ver   = PROTOCOL_VER;
        tx->cmd   = CMD_INIT;
        tx->cnt   = ++s->tx_cnt;
        tx->len   = 4;
        memcpy(tx->data, &s->nonce, 4);

        // For the very first frame we don't sign (no key yet)
        tx->tag = 0;

        if (write_pico(sk, (uint8_t*)tx, FRAME_HEADER_SIZE + 4) != 0) return false;
        
        return true; // early return, handshake step 1 done
    }
    return false;
}

/* ============================================================
 * FUNCTION: proc_frame
 * Processes a single verified protocol frame after initialization. 
 * Validates header consistency, performs authentication checks, 
 * derives/rotates session keys, verifies message tags, and handles 
 * explicit application data payloads (like HTTPS port switching).
 * ============================================================ */  
bool proc_frame(uint8_t sk, frame_t *rx, frame_t *tx, sess_t *s)
{
    uint32_t cli_nonce;
    uint64_t cli_hmac;
    uint8_t auth_buf[8];
    uint8_t exp_tag[16];
    uint64_t exp_hmac;
    uint8_t salt[16];
    uint64_t exp;

    watchdog_update();

    if (rx->magic != PROTOCOL_MAGIC_RECEIVE) return false;
    if (rx->ver != PROTOCOL_VER) return false;
    if (!is_valid_cmd(rx->cmd)) return false;
    if (rx->len > MAX_PAYLOAD) return false;

    if (rx->cmd == CMD_AUTH) {
        if (rx->cnt != 2) return false;
    }
    if (rx->cnt != s->rx_cnt + 1) return false;

    /* === AUTH special handling === */
    if (rx->cmd == CMD_AUTH) {
        if (rx->len != 12) return false;

        async_print("AUTH: reading 12-byte payload...\n");
           
        if (read_pico(sk, rx->data, rx->len) != 0) {
            async_print("Socket %d: read header failed (normal close / partial) - closing gracefully\n", sk);
            close(sk);
            s->active = false;
            s->init_verified = false;
            return false;
        }    
        watchdog_update();

        memcpy(&cli_hmac, &rx->data[0], 8);
        memcpy(&cli_nonce, &rx->data[8], 4);

        async_print("AUTH: HMAC check...\n");
        memcpy(auth_buf, &s->nonce, 4);
        memcpy(auth_buf + 4, &cli_nonce, 4);

        chaskey_mac_wrap(MASTER_KEY, auth_buf, sizeof(auth_buf), exp_tag);
        memcpy(&exp_hmac, exp_tag, sizeof(exp_hmac));

        if (cli_hmac != exp_hmac) {
            async_print("AUTH Fail: Bad HMAC\n");
            return false;
        }

        async_print("AUTH OK. Client Nonce: 0x%08X\n", cli_nonce);
        //clear_blacklist_ip(s->ip);
    
        async_print("AUTH: deriving session key...\n");
        
        build_salt(s->nonce, cli_nonce, salt);
        derive_sess_key(MASTER_KEY, KEY_SIZE, salt, SESS_INFO, SESS_INFO_LEN, s->key, KEY_SIZE);
        watchdog_update();
    }

    if (rx->cmd == CMD_CLOSE) {
        async_print("Socket %d: Client requested clean close\n", sk);
        close(sk);
        s->active = false;
        s->init_verified = false;
        return true; // we handled it, but socket is already closed
    }

    /* DATA payload */
    if (rx->cmd == CMD_DATA) {
        async_print("DATA: reading payload...\n");
        if (read_pico(sk, rx->data, rx->len) != 0) {
            async_print("Socket %d: read header failed (normal close / partial) - closing gracefully\n", sk);
            close(sk);
            s->active = false;
            s->init_verified = false;
            return false;
        }
        
        watchdog_update();
    }

    /* Rotate + tag verify */
    rotate_key(s->key, s->key, rx->cnt);
    watchdog_update();

    exp = frame_tag(rx, s->key);
    if (exp != rx->tag) { // Tag check
        async_print("Tag Mismatch!\n");
        return false;
    }

    // Explicit Context Parsing for Incoming Data
    if (rx->cmd == CMD_DATA && rx->len > 0) {
        async_print("Client says: %.*s\n", rx->len, rx->data);
        
        // 1. STREAMING HISTORY COMMAND
        if (rx->len >= 4 && strncmp((char*)rx->data, "info", 4) == 0) {
            s->streaming_history = true;
            s->history_cursor = 0;
            s->system_up_only = false;
            if (!s->wait_ack) s->send_data = true; 
        } 
        // 2. EXPLICIT HOURLY STATS COMMANDS ("stats" or "hello")
        else if ((rx->len >= 5 && strncmp((char*)rx->data, "stats", 5) == 0) || 
                 (rx->len >= 5 && strncmp((char*)rx->data, "hello", 5) == 0)) {
            s->streaming_history = false;
            s->system_up_only = false;
            if (!s->wait_ack) s->send_data = true; 
        }
        // 3. SECURE PORT SWITCH OVER TO HTTPS
        else if (rx->len >= 3 && strncmp((char*)rx->data, "web", 3) == 0) {
           
            https_start_time = get_absolute_time();
            snprintf((char*)tx->data, MAX_PAYLOAD, "Switching Port 443 to HTTPS...");

            s->rx_cnt = rx->cnt;
            s->last_act = get_absolute_time();
            s->ping_sent = false;

            /* Prepare ACK */
            memset(tx, 0, sizeof(*tx));
            tx->magic = PROTOCOL_MAGIC_SEND;
            tx->ver = PROTOCOL_VER;
            tx->cmd = CMD_ACK;
            s->tx_cnt++;
            tx->cnt = s->tx_cnt;

            rotate_key(s->key, s->key, tx->cnt);
            tx->tag = frame_tag(tx, s->key);
            
            current_port_mode = PORT_MODE_HTTPS;
            https_init_flag = true;
            memcpy(https_client_ip, s->ip, 4); 
            https_timeout = delayed_by_ms(get_absolute_time(), 60000); 
            
            async_print("Port 443 switched to HTTPS for IP %d.%d.%d.%d\n", s->ip[0], s->ip[1], s->ip[2], s->ip[3]);
            return true; 
        }
        // 4. ANY OTHER MESSAGE PAYLOAD (Acknowledge cleanly without sending data strings)
        else {
            s->streaming_history = false;
            s->system_up_only = true;
            if (!s->wait_ack) s->send_data = true;
        }
    }

    s->rx_cnt = rx->cnt;
    s->last_act = get_absolute_time();
    s->ping_sent = false;

    /* Prepare ACK */
    memset(tx, 0, sizeof(*tx));
    tx->magic = PROTOCOL_MAGIC_SEND;
    tx->ver = PROTOCOL_VER;
    tx->cmd = CMD_ACK;
    s->tx_cnt++;
    tx->cnt = s->tx_cnt;

    rotate_key(s->key, s->key, tx->cnt);
    tx->tag = frame_tag(tx, s->key);
    return true;
}

/* ============================================================
 * FUNCTION: handle_new_connection
 * Cleans the session slot, resets counters, wipes old keys, and 
 * prepares the structure for a completely new TCP connection.
 * ============================================================ */
void handle_new_connection(uint8_t sk, sess_t *s) 
{
    uint8_t dip[4];
    getSn_DIPR(sk, dip);
    synrecv_start_us[sk] = 0;

    memcpy(s->ip, dip, 4);
   
    s->active        = false;
    s->init_verified = false;
    s->rx_cnt        = 0;         
    s->tx_cnt        = 0;          
    s->send_data     = false;
    s->wait_ack      = false;
    s->ping_sent     = false;
    s->system_up_only = false;
    s->last_act      = get_absolute_time();
    memset(s->key, 0, KEY_SIZE);   // kill old key
    
    async_print("Socket %d: new connection from %d.%d.%d.%d (FULL reset)\n",
                sk, dip[0], dip[1], dip[2], dip[3]);
}

/* ============================================================
 * FUNCTION: process_one_incoming_frame
 * High-level routing coordinator that reads packet headers directly
 * out of the hardware buffers. Routes the frame to handshake 
 * routines or standard processing based on verification state.
 * ============================================================ */
bool process_one_incoming_frame(uint8_t sk, sess_t *s)
{
    frame_t rx;
    frame_t tx;

    // Read Header
    if (read_pico(sk, (uint8_t*)&rx, FRAME_HEADER_SIZE) != 0) {
        async_print("Socket %d: read header failed (normal close / partial) - closing gracefully\n", sk);
        close(sk);
        s->active = false;
        s->init_verified = false;
        return false;
    }

    // Route to Handshake (INIT)
    if (s->init_verified == false) {
        if (!init_frame(sk, &rx, &tx, s)) {
            async_print("Socket %d: bad INIT frame (garbage or non-client) - closing\n", sk);
            close(sk);
            s->active = false;
            s->init_verified = false;
            hourly_stats.garbage_inits++;
            hourly_stats.garbage_inits_all++;
            return false;
        }
        hourly_stats.success_conns++;
        hourly_stats.success_conns_all++;
        
        return true;
    }
    // Read regular frame 
    else {
        if (proc_frame(sk, &rx, &tx, s)) {
            
            if (rx.cmd != CMD_ACK && rx.cmd != CMD_CLOSE) {
                if (write_pico(sk, (uint8_t*)&tx, FRAME_HEADER_SIZE) != 0) return false;
            }
            s->last_act = get_absolute_time();
        
            if (rx.cmd == CMD_ACK) {
                if (s->wait_ack) {
                    s->wait_ack = false;
                    async_print("Client ACK received\n");
                }
            }
        
            s->ping_sent = false; 
            return true;
        } 
        // Error handle
        else {
            async_print("Socket %d: frame failed\n", sk);
        
            if (s->active) {
                add_strike(s->ip, 1);
            }
        
            close(sk);
            s->active = false;
            return false;
        }
    }
    return false;
}

/* ============================================================
 * FUNCTION: send_status_update
 * Formats and transmits system telemetry, live tracking stats, or 
 * continuous historical streaming data based on the client's 
 * request context. Encrypts the payload before sending.
 * ============================================================ */
void send_status_update(uint8_t sk, sess_t *s) 
{
    frame_t tx;
    memset(&tx, 0, sizeof(tx));
    
    tx.magic = PROTOCOL_MAGIC_SEND;
    tx.ver = PROTOCOL_VER;
    tx.cmd = CMD_DATA; 
    tx.cnt = ++s->tx_cnt;

    if (s->system_up_only) {
        snprintf((char*)tx.data, MAX_PAYLOAD, "System is up");
    }
    // IF NORMAL UPDATE
    else if (!s->streaming_history) {
        uint8_t current_soc = 0;
        for (int i = 0; i < MAX_SOCKETS; i++) {
            if (sess[i].active) current_soc++;
        }

        // Huge format string: safely contained within our new 128-byte MAX_PAYLOAD
        snprintf((char*)tx.data, MAX_PAYLOAD, 
                 "Suc:%lu(%lu/%lu) Tmo:%lu(%lu/%lu) Bad:%lu(%lu/%lu) Soc:%u/%u Pk:%u(%u/%u) Rst:%lu Blk:%u",
                 hourly_stats.success_conns, hourly_stats.success_conns_last, hourly_stats.success_conns_all,
                 hourly_stats.ack_timeouts, hourly_stats.ack_timeouts_last, hourly_stats.ack_timeouts_all,
                 hourly_stats.garbage_inits, hourly_stats.garbage_inits_last, hourly_stats.garbage_inits_all,
                 current_soc, MAX_SOCKETS,
                 hourly_stats.peak_sockets, hourly_stats.peak_sockets_last, hourly_stats.peak_sockets_all,
                 res_data.restart_count,
                 get_blocked_count());
    } 
    // IF STREAMING 2-WEEK HISTORY
    else {
        if (s->history_cursor >= history_count) {
            // Reached the end. Send exit code.
            snprintf((char*)tx.data, MAX_PAYLOAD, "EOF");
            s->streaming_history = false; // Turn off streaming
        } else {
            // Calculate actual index in ring buffer (oldest to newest)
            int start_idx = (history_count < MAX_HISTORY_HOURS) ? 0 : history_head;
            int actual_idx = (start_idx + s->history_cursor) % MAX_HISTORY_HOURS;
            
            hourly_record_t *rec = &stats_history[actual_idx];
            
            // Format one hour per frame to easily fit under 128 bytes
            snprintf((char*)tx.data, MAX_PAYLOAD, 
                     "[Hour -%d] Suc:%lu Tmo:%lu Bad:%lu Pk:%u", 
                     history_count - s->history_cursor, 
                     rec->success, rec->timeout, rec->garbage, rec->peak);
                     
            s->history_cursor++;
        }
    }

    tx.len = (uint16_t)strlen((char*)tx.data);
    rotate_key(s->key, s->key, tx.cnt);
    tx.tag = frame_tag(&tx, s->key);

    if (write_pico(sk, (uint8_t *)&tx, FRAME_HEADER_SIZE + tx.len) != 0) return;
    
    s->last_act = get_absolute_time();
    
    // KEEP send_data TRUE if we are streaming so the state machine loops back
    if (s->streaming_history) {
        s->send_data = true; 
    } else {
        s->send_data = false;
        s->system_up_only = false;
    }
    s->wait_ack = true; 

    async_print("Stats Sent: %s\n", tx.data);
}

/* ============================================================
 * FUNCTION: handle_keepalive_ping
 * Monitors idle connection limits. Issues a CMD_PING payload to 
 * dormant sockets and severs the connection if the client fails 
 * to reply within the execution window.
 * ============================================================ */
void handle_keepalive_ping(uint8_t sk, sess_t *s)
{
    absolute_time_t now = get_absolute_time();
    int64_t diff = absolute_time_diff_us(s->last_act, now);
    
    // Send ping if idle too long
    if (s->active && !s->ping_sent) {
        if (diff > APP_KEEPALIVE_IDLE_MS * 1000LL) {
            frame_t tx;
            memset(&tx, 0, sizeof(tx));
            tx.magic = PROTOCOL_MAGIC_SEND;
            tx.ver = PROTOCOL_VER;
            tx.cmd = CMD_PING;
            s->tx_cnt = s->tx_cnt + 1;
            tx.cnt = s->tx_cnt;
            tx.len = 0;

            rotate_key(s->key, s->key, tx.cnt);
            tx.tag = frame_tag(&tx, s->key);

            if (write_pico(sk, (uint8_t *)&tx, FRAME_HEADER_SIZE) != 0) return;
            
            async_print("Socket %d: PING sent\n", sk);
            
            s->ping_sent = true;
            s->ping_deadline = delayed_by_ms(now, APP_KEEPALIVE_REPLY_MS);
        }
    }
    
    // Check ping deadline
    if (s->ping_sent) {
        diff = absolute_time_diff_us(now, s->ping_deadline);
        if (diff <= 0) {
            async_print("Socket %d: ping timeout\n", sk);
        
            close(sk);
            s->active = false;
            s->init_verified = false;
        }
    }
}