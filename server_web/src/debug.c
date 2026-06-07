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
