// SERVER                         //
// Debug functions                //
// Ver. 0.4                       //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //

#ifndef DEBUG_H
#define DEBUG_H

#include <stdint.h>
#include <frame.h>


#define LOG_QUEUE_SIZE 64
typedef struct {
    char msg[128];          // plenty for your current prints
} log_entry_t;

/* ============================================================
 * DEBUG UART
 * ============================================================ */
void dbg_init(void);

void print_last_known_state(void);

/**
 * Logs events for an established session.
 * Includes IP, Socket, and sequence counters for RX/TX.
 */
void dbg_log(const char* evt, uint8_t sk, sess_t *s);

/**
 * Logs events where a session object might not exist yet.
 * Used for logging BLOCKED IPs or new connection attempts.
 */
void dbg_log_nocon(const char* evt, uint8_t sk, uint8_t ip[4]);

void async_print(const char *fmt, ...);
 #endif
