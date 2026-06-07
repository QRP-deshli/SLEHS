// SERVER                         //
// Netdata functions              //
// Ver. 0.4                       //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //

/* 
This header purpose is to define 2 structures that will be used to maintain 
sessions and to define frames that will be send 
*/

#ifndef FRAME_H
#define FRAME_H

#include "parameters.h"
#include "timer.h"
#include "hardware/timer.h"

/* This header purpose is to define 2 structures that will be used to maintain 
sessions and to define frames that will be send 
*/

/* ============================================================
 * DATA STRUCTURE: frame_t
 * ============================================================
 * Defines the binary layout of the network packets (frames).
 * #pragma pack(push,1) forces the compiler to align every field
 * precisely, ensuring the frame looks exactly the same in memory
 * for both the sender and the receiver.
 * ============================================================ */
#pragma pack(push,1)
typedef struct {
    uint16_t magic;           // Packet identifier to filter out random noise/garbage.
    uint8_t ver;              // Protocol version to ensure both sides speak the same language.
    uint8_t cmd;              // Command code (e.g., PING, AUTH).
    uint32_t cnt;             // Sequence counter to detect missing or reordered packets.
    uint16_t len;             // Actual length of the data currently held in the 'data' buffer.
    uint64_t tag;             // Security tag or unique ID for validating packet integrity.
    uint8_t data[MAX_PAYLOAD];// The actual message content being transmitted.
} frame_t;
#pragma pack(pop)

typedef struct {
    uint32_t success_conns;
    uint32_t success_conns_last;
    uint32_t success_conns_all;

    uint32_t ack_timeouts;
    uint32_t ack_timeouts_last;
    uint32_t ack_timeouts_all;

    uint32_t garbage_inits;
    uint32_t garbage_inits_last;
    uint32_t garbage_inits_all;

    uint8_t peak_sockets;
    uint8_t peak_sockets_last;
    uint8_t peak_sockets_all;
} stats_tracker_t;

typedef struct {
    uint32_t success;
    uint32_t timeout;
    uint32_t garbage;
    uint8_t  peak;
} hourly_record_t;
    
/* ============================================================
 * DATA STRUCTURE: sess_t
 * ============================================================
 * Tracks the "Living" state of a connection in RAM.
 * Unlike a frame, which is temporary, a session persists to 
 * remember who the client is, their security keys, and whether 
 * they are currently responding to pings.
 * ============================================================ */
typedef struct {
    bool active;              // True if this session slot is currently in use.
    uint8_t ip[4];            // Remote client's IPv4 address.
    uint32_t rx_cnt;          // Total packets received (used for sequence validation).
    uint32_t tx_cnt;          // Total packets sent.
    uint32_t nonce;           // A "number used once" for cryptographic freshness.
    uint8_t key[KEY_SIZE]; // Unique encryption key generated for this session.
    absolute_time_t last_act; // Timestamp of the last successful communication.
    bool send_data;           // Flag to indicate if there is data pending to be sent.
    bool wait_ack;            // State flag: waiting for the client to confirm receipt.
    bool ping_sent;           // Tracks if a PING is currently "in flight."
    uint32_t client_nonce;      // 
    bool     init_verified;
    bool     system_up_only;
    absolute_time_t ping_deadline; // The "cutoff" time; if no PONG by now, drop session.
    bool     streaming_history; 
    uint16_t history_cursor;
} sess_t;

#endif

