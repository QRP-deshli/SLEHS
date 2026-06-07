// SERVER                         //
// Debug functions                //
// Ver. 0.4                       //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //

#include <stdio.h>
#include "parameters.h"
#include "hardware/regs/watchdog.h"
#include "hardware/uart.h"
#include "port_common.h"
#include "frame.h"
#include "hardware/uart.h"
#include <stdarg.h>   // for vsnprintf
#include "pico/util/queue.h"
#include "debug.h"

extern queue_t log_queue;

/*
 * Function: async_print
 * Description: Formats and pushes log messages from Core 1 into a lock-free queue.
 * The messages are subsequently processed and printed by Core 0 to 
 * prevent blocking critical real-time operations on Core 1.
 */
void async_print(const char *fmt, ...) {
    log_entry_t entry;
    va_list args;
    
    // Format the variable argument list into the fixed-size message buffer
    va_start(args, fmt);
    vsnprintf(entry.msg, sizeof(entry.msg), fmt, args);
    va_end(args);
    
    // Attempt to add the new log entry to the inter-core queue.
    // If the queue is full, queue_try_add() returns false immediately without blocking.
    if (!queue_try_add(&log_queue, &entry)) {
        /* * QUEUE OVERFLOW HANDLING:
         * Do NOT call queue_try_remove() here to force space! 
         * Removing items from the producer side (Core 1) breaks the strict 
         * Single-Producer Single-Consumer (SPSC) queue invariants and will 
         * lead to race conditions or crashes with Core 0.
         * * Instead, we gracefully drop this specific log entry. 
         * This data-loss safety valve ensures system stability and guarantees 
         * the server survives high-stress conditions (e.g., thousands of rapid connections).
         */
    }
}
// /*
//  *   At the beginning of main(), prints information about the last known state before reset
//  *   Uses .noinit variables - survives software reset and watchdog reset
//  *   (but not power-off - that would require flash or RTC backup)
//  */
// void print_last_known_state(void)
// {
//     if (last_critical_state == 0) {
//         printf("\n");
//         printf("============================================================\n");
//         printf(" Cold boot / power-on reset detected\n");
//         printf(" No previous crash or watchdog signature found\n");
//         printf("============================================================\n\n");
//         return;
//     }

//     if (state_magic != STATE_MAGIC_EXPECTED) {
//         printf("!!! ====================================================== !!!\n");
//         printf("!!!         .noinit SECTION APPEARS CORRUPTED            !!!\n");
//         printf("!!!   (bad magic number: 0x%04X, expected 0x%04X)       !!!\n",
//                state_magic, STATE_MAGIC_EXPECTED);
//         printf("!!!   - values are probably random garbage after power loss !!!\n");
//         printf("!!! ====================================================== !!!\n\n");

//         // voliteľne tu môžeš vynulovať všetko
//         last_critical_state = 0;
//         last_socket = 255;
//         state_change_counter = 0;
//         state_magic = STATE_MAGIC_EXPECTED;   // aby sa to už nabudúce neopakovalo
//         return;
//     }

//     const char *state_name = "UNKNOWN";
//     const char *location_hint = "";

//     switch (last_critical_state) {
//         // Boot & basic initialization
//         case STATE_BOOT_SUCCESS:
//             state_name = "BOOT_SUCCESS";
//             location_hint = "main() - after successful startup";
//             break;

//         case STATE_MAIN_LOOP:
//             state_name = "MAIN_LOOP";
//             location_hint = "main() - entering while(1)";
//             break;

//         case STATE_INIT_OK:
//             state_name = "INIT_OK";
//             location_hint = "init_frame() - successful nonce exchange";
//             break;

//         // Network / socket related states
//         case STATE_NEW_CONNECTION:
//             state_name = "NEW_CONNECTION";
//             location_hint = "handle_new_connection()";
//             break;

//         case STATE_RX_HEADER:
//             state_name = "RX_HEADER";
//             location_hint = "process_one_incoming_frame() - header read";
//             break;

//         case STATE_AUTH_OK:
//             state_name = "AUTH_OK";
//             location_hint = "proc_frame() - successful authentication (HMAC OK)";
//             break;

//         case STATE_DATA_OK:
//             state_name = "DATA_OK";
//             location_hint = "proc_frame() - valid DATA frame + tag verified";
//             break;

//         case STATE_ACK_OR_PONG_SENT:
//             state_name = "ACK_OR_PONG_SENT";
//             location_hint = "proc_frame() or handle_keepalive_ping() - response sent";
//             break;

//         case STATE_DATA_SEND:
//             state_name = "DATA_SEND";
//             location_hint = "send_status_update() - status packet sent";
//             break;

//         // Problematic / timeout states
//         case STATE_PING_TIMEOUT:
//             state_name = "PING_TIMEOUT";
//             location_hint = "handle_keepalive_ping() - client did not respond to PING";
//             break;

//         case STATE_FRAME_FAILED:
//             state_name = "FRAME_FAILED";
//             location_hint = "process_one_incoming_frame() - invalid frame - close()";
//             break;

//         case STATE_CLOSE_CALLED:
//             state_name = "CLOSE_CALLED";
//             location_hint = "tcp_srv_task() or other function - close(sk) called";
//             break;

//         // Blacklist related states
//         case STATE_BLACKLIST_STRIKE_ADDED:
//             state_name = "BLACKLIST_STRIKE_ADDED";
//             location_hint = "add_strike() - strike count increased (not yet blocked)";
//             break;

//         case STATE_BLACKLIST_SAVE_INIT:
//             state_name = "BLACKLIST_SAVE_INIT";
//             location_hint = "blacklist_save() - preparing data for flash write";
//             break;

//         case STATE_BLACKLIST_SAVE_START:
//             state_name = "BLACKLIST_SAVE_START";
//             location_hint = "blacklist_save() - before disable interrupts + flash erase";
//             break;

//         case STATE_BLACKLIST_SAVE_FINISHED:
//             state_name = "BLACKLIST_SAVE_FINISHED";
//             location_hint = "blacklist_save() - after flash program + restore interrupts";
//             break;

//         default:
//             state_name = "UNKNOWN / RESERVED";
//             location_hint = "value outside expected enum critical_state range";
//             break;
//     }

//     printf("\n");
//     printf("!!! ====================================================== !!!\n");
//     printf("!!!          LAST KNOWN STATE BEFORE RESET               !!!\n");
//     printf("!!! ====================================================== !!!\n\n");

//     printf(" Last critical state     : %3u  (%s)\n", last_critical_state, state_name);
//     printf(" Location / context hint : %s\n", location_hint);

//     if (last_socket != 255) {
//         printf(" Associated socket       : %u\n", last_socket);
//     } else {
//         printf(" Associated socket       : none / global operation\n");
//     }

//     printf(" State change counter    : %u\n", state_change_counter);

//     // Quick problem area classification
//     if (last_critical_state >= 80 && last_critical_state <= 95) {
//         printf(" Likely issue related to blacklist manipulation / flash write\n");
//     }
//     else if (last_critical_state >= 30 && last_critical_state <= 70) {
//         printf(" Likely issue in network layer / frame processing / keepalive\n");
//     }
//     else if (last_critical_state <= 20) {
//         printf(" Likely issue already during boot or very early execution\n");
//     }

//     printf("\n");
//     printf("!!! ====================================================== !!!\n\n");

//     // Optional: clear after reading (prevents repeating message after manual reset)
//     // last_critical_state = 0;
// }