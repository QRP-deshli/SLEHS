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
#include "timer.h"
#include "hardware/watchdog.h"
#include "hardware/timer.h"
#include "hardware/regs/watchdog.h"
#include "hardware/uart.h"
#include "hardware/flash.h"
#include "pico/flash.h"
#include "hardware/sync.h"
#include "port_common.h"
#include "blacklist.h"
#include <pico/bootrom.h>
#include "debug.h"

/* ============================================================
 * GLOBAL BLACKLIST STATE (RAM only)
 * ============================================================ */
extern blacklist_slot_t g_blacklist;   // still used by the rest of the code

/* ============================================================
 * BLACKLIST IMPLEMENTATION
 * ============================================================ */

/* * Initializes the blacklist metadata and clears out the memory slot, 
 * putting the subsystem into an empty RAM-only state.
 */
void blacklist_init(void)
{
    memset(&g_blacklist, 0, sizeof(g_blacklist));
    g_blacklist.magic = BLACKLIST_MAGIC;
    g_blacklist.ver   = BLACKLIST_VER;
    g_blacklist.seq   = 0;
    g_blacklist.num   = 0;

    printf("Blacklist: RAM-only mode initialised (no persistence)\n");
}

/* * Loops through active RAM records and prints statistics alongside 
 * details for each recorded IP address (strikes, block status, and age).
 */
void print_blacklist(void)
{
    printf("=== BLACKLIST DUMP (RAM-only) ===\n");
    printf("Total entries in RAM : %d\n", g_blacklist.num);
    printf("Permanently blocked  : %d\n", get_blocked_count());
    printf("--------------------------------------------------\n");

    if (g_blacklist.num == 0) {
        printf("Blacklist is empty.\n");
        printf("=== END BLACKLIST ===\n\n");
        return;
    }

    for (uint16_t i = 0; i < g_blacklist.num; i++) {
        blacklist_entry_t *e = &g_blacklist.entries[i];

        printf("[%3u] IP: %3u.%3u.%3u.%3u   Strikes: %3u   Blocked: %s",
               i,
               e->ip[0], e->ip[1], e->ip[2], e->ip[3],
               e->strikes,
               e->blocked ? "YES" : "NO");

        if (!e->blocked) {
            uint64_t age_us = absolute_time_diff_us(e->last_strike_time, get_absolute_time());
            printf("   (temp, age: %lu s)", (unsigned long)(age_us / 1000000ULL));
        }
        printf("\n");
    }
    printf("=== END BLACKLIST ===\n\n");
}

/* * Searches for a matching IP address in the tracker and completely 
 * removes its record, shifting any remaining table elements downward.
 */
void clear_blacklist_ip(uint8_t ip[4])
{
    for (uint16_t i = 0; i < g_blacklist.num; i++) {
        if (memcmp(g_blacklist.entries[i].ip, ip, 4) == 0) {
            // Remove completely and shift elements
            memmove(&g_blacklist.entries[i],
                    &g_blacklist.entries[i + 1],
                    (g_blacklist.num - i - 1) * sizeof(blacklist_entry_t));
            g_blacklist.num--;
            return;
        }
    }
}

/* * Wipes the current global state tracking completely, resetting 
 * version codes and dropping all tracked entries from memory.
 */
void blacklist_clear_all(void)
{
    memset(&g_blacklist, 0, sizeof(g_blacklist));
    g_blacklist.magic = BLACKLIST_MAGIC;
    g_blacklist.ver   = BLACKLIST_VER;
    g_blacklist.seq   = 0;
    g_blacklist.num   = 0;

    printf("=== BLACKLIST FULLY CLEARED (RAM-only) ===\n");
}

/* * Registers incident strikes against an IP address, establishes a 
 * new tracking block if full, and evicts older unblocked items if 
 * the structure reaches maximum capacity limits.
 */
void add_strike(uint8_t ip[4], uint8_t amount)
{
    uint16_t i;
    blacklist_entry_t *entry;

    for (i = 0; i < g_blacklist.num; i++) {
        entry = &g_blacklist.entries[i];
        if (memcmp(entry->ip, ip, 4) != 0) continue;

        if (entry->blocked) return;

        entry->strikes += amount;
        if (entry->strikes > 255) entry->strikes = 255;
        entry->last_strike_time = get_absolute_time();

        async_print("Strike %d for ip: %d.%d.%d.%d\n ", entry->strikes, ip[0], ip[1], ip[2], ip[3]);

        if (entry->strikes >= STRIKE_MAX) {
            entry->blocked = 1;
            async_print("!!! BLACKLISTED: %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
        }
        return;
    }

    // List full? Evict oldest temporary entry
    if (g_blacklist.num >= MAX_BLACKLIST_ENTRY) {
        for (uint16_t j = 0; j < g_blacklist.num; j++) {
            if (!g_blacklist.entries[j].blocked) {
                memmove(&g_blacklist.entries[j],
                        &g_blacklist.entries[j + 1],
                        (g_blacklist.num - j - 1) * sizeof(blacklist_entry_t));
                g_blacklist.num--;
                break;
            }
        }
    }

    // New entry allocation
    entry = &g_blacklist.entries[g_blacklist.num];
    memcpy(entry->ip, ip, 4);
    entry->strikes = amount;
    entry->blocked = 0;
    entry->last_strike_time = get_absolute_time();
    g_blacklist.num++;

    if (entry->strikes >= STRIKE_MAX) {
        entry->blocked = 1;
        async_print("!!! BLACKLISTED: %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
    }
}

/* * Performs a lookup on the tracking table to quickly verify if 
 * a specific IP target has crossed the max strike threshold and 
 * is currently flagged as blocked.
 */
bool is_blocked(uint8_t ip[4])
{
    for (uint16_t i = 0; i < g_blacklist.num; i++) {
        if (memcmp(g_blacklist.entries[i].ip, ip, 4) == 0) {
            return g_blacklist.entries[i].blocked != 0;
        }
    }
    return false;
}

/* * Iterates backward through active structures to clean out stale temporary 
 * strikes (older than 1 hour) or drop expired block bans (older than 24 hours).
 */
void blacklist_periodic_cleanup(void)
{
    // Define grace periods
    const uint64_t STRIKE_TIMEOUT_US = HOUR_MS(1) * 1000LL;   // 1 Hour for temp strikes
    const uint64_t BLOCK_TIMEOUT_US  = HOUR_MS(24) * 1000LL;  // 24 Hours for full blocks
    
    absolute_time_t now = get_absolute_time();

    // Iterate backwards so memmove doesn't skip entries
    for (int i = (int)g_blacklist.num - 1; i >= 0; i--) {
        blacklist_entry_t *e = &g_blacklist.entries[i];
        uint64_t age_us = absolute_time_diff_us(e->last_strike_time, now);
        bool should_remove = false;

        if (e->blocked) {
            // If they are blocked, check against the long timeout
            if (age_us > BLOCK_TIMEOUT_US) {
                should_remove = true;
                async_print("Cleanup: Unblocking IP %d.%d.%d.%d (Ban expired)\n", 
                            e->ip[0], e->ip[1], e->ip[2], e->ip[3]);
            }
        } else {
            // If they just have strikes, check against the short timeout
            if (age_us > STRIKE_TIMEOUT_US) {
                should_remove = true;
            }
        }

        if (should_remove) {
            // Remove entry and shift the rest of the array down
            if (i < (int)g_blacklist.num - 1) {
                memmove(&g_blacklist.entries[i], 
                        &g_blacklist.entries[i + 1], 
                        (g_blacklist.num - i - 1) * sizeof(blacklist_entry_t));
            }
            g_blacklist.num--;
        }
    }
}

/* * Returns the exact numeric total of IP components currently flagged 
 * under restricted/blocked status within the structure.
 */
uint16_t get_blocked_count(void)
{
    uint16_t count = 0;
    for (uint16_t i = 0; i < g_blacklist.num; i++) {
        if (g_blacklist.entries[i].blocked) {
            count++;
        }
    }
    return count;
}