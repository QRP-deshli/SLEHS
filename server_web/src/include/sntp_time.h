// SERVER                         //
// Netdata functions              //
// Ver. 0.4                       //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //

/* 
This header file declares functions for Sntp 
synchronization with extern server. 
Function definitions are in the sntp_time.c file. 
*/

#ifndef SNTP_TIME_H
#define SNTP_TIME_H

#include "time.h"
#include <stdbool.h>
#include "sntp.h"
#include "pico/stdlib.h"

extern volatile datetime g_current_time;
extern volatile uint32_t g_uptime_sec;

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
bool clock_1hz_callback(struct repeating_timer *t);

/*
 * Function: time_sync_sntp
 * Description: Initializes and queries an external network NTP server over UDP using 
 * the WIZnet module. If a valid packet arrives within the receive window timeout, the 
 * global datetime structure updates and spins up the localized 1Hz counter hardware timer.
 */
void time_sync_sntp();
#endif