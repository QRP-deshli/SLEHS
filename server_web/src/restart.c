// ============================================================================
// SERVER: Restart Persistent Counter Functions
// Ver. 0.4 | University Work Project
// Technical University of Kosice | 22.3.2026
// Author: Nikita Kuropatkin
// ============================================================================

#include "restart.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Wiznet & Pico Hardware Dependencies */
#include "parameters.h"
#include "timer.h"
#include "debug.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "hardware/watchdog.h"
#include "hardware/regs/watchdog.h"
#include "pico/flash.h"

// Global restart tracking structure
extern restart_data_t res_data;

/**
 * Commits the current runtime restart data configuration down to Flash memory.
 */
void res_count_save(void) {
    uint32_t ints = save_and_disable_interrupts();

    // Erase and program a single 4KB Flash sector
    flash_range_erase(PERSISTENT_DATA_OFFSET, 4096);
    flash_range_program(PERSISTENT_DATA_OFFSET,
                        (const uint8_t *)&res_data,
                        sizeof(restart_data_t));

    restore_interrupts(ints);
    watchdog_update(); 
}

/**
 * Initializes the persistent counter configuration from Flash memory.
 * Wipes and forces a 0 reset only when a version mismatch is explicitly detected.
 */
void res_count_init(void) {
    const restart_data_t *flash_ptr = (const restart_data_t *)(XIP_BASE + PERSISTENT_DATA_OFFSET);

    // If the magic matches and the structure version matches, we trust the count
    if (flash_ptr->magic == RESTART_COUNTER_MAGIC &&
        flash_ptr->version == RESTART_COUNTER_VER) { 
        
        memcpy(&res_data, flash_ptr, sizeof(restart_data_t));
        async_print("Persistent: loaded restart count = %lu\n", res_data.restart_count);
    } else {
        // Triggers ONLY on clean flash or when you change RESTART_COUNTER_VER in parameters.h
        memset(&res_data, 0, sizeof(restart_data_t));
        res_data.magic         = RESTART_COUNTER_MAGIC;
        res_data.version       = RESTART_COUNTER_VER; // Locks it to the new version
        res_data.restart_count = 0;
        
        async_print("Persistent: Fresh firmware version detected. Counter reset to 0\n");
        res_count_save(); // Overwrites flash with the fresh version and 0 count
    }
}

/**
 *  Increments the sequence token counter and immediately updates flash storage.
 */
void res_count_increment(void) {
    async_print("Restart #%lu\n", res_data.restart_count);
    res_data.restart_count++;
    res_count_save();
}
