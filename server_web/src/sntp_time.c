// SERVER                         //
// Netdata functions              //
// Ver. 0.4                       //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //

#include "sntp_time.h"
#include <stdint.h>
#include "include/parameters.h"
#include "port_common.h"
#include "sntp.h"
#include "time.h"
#include "timing.h"
#include "debug.h"

// Google public SNTP server IP address (time.google.com)
static uint8_t g_sntp_server_ip[4] = {216, 239, 35, 0};

// Buffer used by the SNTP library for packet transmission/reception
static uint8_t g_sntp_buf[ETHERNET_BUF_MAX_SIZE];

// Global date and time structure updated by SNTP and local timer
volatile datetime g_current_time = {0};

// System uptime counter in seconds since startup
volatile uint32_t g_uptime_sec = 0;

// Repeating hardware timer instance used for 1 Hz timekeeping
static struct repeating_timer clock_timer;

// Prevents accidental creation of multiple 1 Hz timers
static bool timer_initialized = false;


/*
 * Function: clock_1hz_callback
 * Description: 1Hz hardware timer interrupt/callback function used to increment the
 * internal uptime counter and real-time clock structure fields. Avoids overhead by keeping
 * track of time internally between daily remote server updates.
 *
 * Parameters:
 * t - Pointer to the triggering repeating timer structure.
 *
 * Returns: Always returns true to keep the repeating timer active.
 */
bool clock_1hz_callback(struct repeating_timer *t) {

    // Increment total system uptime
    g_uptime_sec++;

    // Increment seconds field of the internal clock
    g_current_time.ss++;

    // Handle second overflow
    if (g_current_time.ss >= 60) {
        g_current_time.ss = 0;
        g_current_time.mm++;

        // Handle minute overflow
        if (g_current_time.mm >= 60) {
            g_current_time.mm = 0;
            g_current_time.hh++;

            // Handle hour overflow
            if (g_current_time.hh >= 24) {
                g_current_time.hh = 0;

                // Increment day counter
                // Note: Month/year rollover is not handled here because
                // the clock is periodically corrected via SNTP.
                g_current_time.dd++;
            }
        }
    }

    // Keep the repeating timer running
    return true;
}


/*
 * Function: time_sync_sntp
 * Description: Initializes and queries an external network NTP server over UDP using
 * the WIZnet module. If a valid packet arrives within the receive window timeout, the
 * global datetime structure updates and spins up the localized 1Hz counter hardware timer.
 */
void time_sync_sntp() {

    // Initialize the SNTP client with:
    // - socket number
    // - SNTP server IP
    // - timezone offset
    // - communication buffer
    SNTP_init(SOCKET_SNTP, g_sntp_server_ip, TIMEZONE, g_sntp_buf);

    // Record start time for timeout handling
    uint32_t start_sntp_ms = millis();

    // Return value from SNTP_run()
    int sntp_ret = 0;
    
    async_print("Fetching SNTP time...\n");

    // Keep polling the SNTP client until:
    // - a valid response is received, or
    // - the timeout period expires
    do {
        sntp_ret = SNTP_run((datetime*)&g_current_time);

        // SNTP library returns 1 when synchronization succeeds
        if (sntp_ret == 1) {
            break;
        }

    } while ((millis() - start_sntp_ms) < SNTP_RECV_TIMEOUT);

    // Synchronization successful
    if (sntp_ret == 1) {
        async_print("Time synced successfully.\n");

        // Start the local 1 Hz clock only once
        if (!timer_initialized) {
            add_repeating_timer_ms(1000, clock_1hz_callback, NULL, &clock_timer);
            timer_initialized = true;
        }
    }
    // Synchronization failed
    else {
        // Existing internal clock continues operating
        // using the previously started 1 Hz timer.
        async_print("SNTP sync failed. Internal clock continues running.\n");
    }
}