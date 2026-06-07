// SERVER                         //
// Netdata functions              //
// Ver. 0.4                       //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //

/* 
This header file declares functions for configuring the timing system 
and managing timers in the application. These functions are used to 
set up the system's operating frequency. 
Function definitions are in the timing.c file. 
*/

#ifndef TIMING_H
#define TIMING_H
#include "time.h"
#include <stdbool.h>
#include "hardware/timer.h"

extern struct repeating_timer timer1;

extern struct repeating_timer timer2;

/*
This function's purpose is to configure the system clock and 
peripheral clock to operate at PLL_SYS_KHZ frequency.
Easier explanation: we are setting up these clocks 
to configure the chip`s operating frequency as PLL_SYS_KHZ.
*/
void set_clock_khz(void);

/*
Function that repeatedly increments the counter every millisecond.
*/
void repeating_timer_callback(void);

/*
Returns the millisecond counter value.
It means the number of milliseconds that 
have passed from the start of the program.
*/
time_t millis(void);

/*
IRQ callback function for watchdog
*/
bool watchdog_irq (struct repeating_timer *timer1);

/*
IRQ callback function for LED blinking, for debugging 
*/
bool led_blink_irq(struct repeating_timer *timer2);

/*
Function for updatinf IRQ callback function period time 
*/
void update_blink_period(int new_period_ms);

#endif
