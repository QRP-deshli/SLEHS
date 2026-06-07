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

static uint8_t g_sntp_server_ip[4] = {216, 239, 35, 0}; // time.google.com
static uint8_t g_sntp_buf[ETHERNET_BUF_MAX_SIZE];

volatile datetime g_current_time = {0};
volatile uint32_t g_uptime_sec = 0;

static struct repeating_timer clock_timer;
static bool timer_initialized = false; // Prevents multiple timer instances


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
    g_uptime_sec++;
    g_current_time.ss++;
    if (g_current_time.ss >= 60) {
        g_current_time.ss = 0;
        g_current_time.mm++;
        if (g_current_time.mm >= 60) {
            g_current_time.mm = 0;
            g_current_time.hh++;
            if (g_current_time.hh >= 24) {
                g_current_time.hh = 0;
                g_current_time.dd++; // Simple day increment
            }
        }
    }
    return true;
}


/*
 * Function: time_sync_sntp
 * Description: Initializes and queries an external network NTP server over UDP using 
 * the WIZnet module. If a valid packet arrives within the receive window timeout, the 
 * global datetime structure updates and spins up the localized 1Hz counter hardware timer.
 */
void time_sync_sntp() {
    SNTP_init(SOCKET_SNTP, g_sntp_server_ip, TIMEZONE, g_sntp_buf);
    uint32_t start_sntp_ms = millis();
    int sntp_ret = 0;
    
    async_print("Fetching SNTP time...\n");
    do {
        sntp_ret = SNTP_run((datetime*)&g_current_time);
        if (sntp_ret == 1) {
            break;
        }
    } while ((millis() - start_sntp_ms) < SNTP_RECV_TIMEOUT);

    if (sntp_ret == 1) {
        async_print("Time synced successfully.\n");
        // Only start the 1Hz incrementer if it's not already running
        if (!timer_initialized) {
            add_repeating_timer_ms(1000, clock_1hz_callback, NULL, &clock_timer);
            timer_initialized = true;
        }
    } else {
        async_print("SNTP sync failed. Internal clock continues running.\n");
    }
}