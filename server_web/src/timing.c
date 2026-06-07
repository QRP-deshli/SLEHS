// SERVER                         //
// Netdata functions              //
// Ver. 0.4                       //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //


#include "include/timing.h"
#include "include/parameters.h"
#include "port_common.h"
#include "dhcp.h"
#include "hardware/watchdog.h"

extern volatile int blink_period_ms;

/* 
Initial values for a global millisecond counter.
Tracks milliseconds since the program started.
*/
static volatile uint32_t g_msec_cnt = 0; // Refreshes every 1000ms 

static volatile uint32_t g_msec_cnt_2 = 0;

/*
Value for led blinking, changed everytime led_blink_irq called 
*/
static bool led_state = false;

/*
This function's purpose is to configure the system clock and 
peripheral clock to operate at PLL_SYS_KHZ frequency.
Easier explanation: we are setting up these clocks 
to configure the chip`s operating frequency  
*/
void set_clock_khz(void) {
 // Set the system clock (clk_sys) frequency in kilohertz (kHz).
 set_sys_clock_khz(PLL_SYS_KHZ, true);

 /*
 Set the peripheral clock (clk_peri) to use the System PLL (PLL_SYS).
 */
 clock_configure(
    /* The peripheral clock to configure. */
    clk_peri,   
    /* No glitchless multiplexer. */                                     
    0,                                              
    /* Use the System PLL as the clock source. */
    CLOCKS_CLK_PERI_CTRL_AUXSRC_VALUE_CLKSRC_PLL_SYS, 
    /* Input clock frequency in Hz, thats why we need to multiply by 1000 */
    PLL_SYS_KHZ * 1000,                             
    /* Output clock frequency in Hz. */
    PLL_SYS_KHZ * 1000                             
 );
}

/*
Function that repeatedly increments the counter every millisecond.
*/
void repeating_timer_callback(void) {
 g_msec_cnt_2++; 
 g_msec_cnt++;  
  if (g_msec_cnt >= 1000) {
        g_msec_cnt = 0;
        DHCP_time_handler();
  }
}

/*
Returns the millisecond counter value.
It means the number of milliseconds that 
have passed from the start of the program.
*/
time_t millis(void) {
 return g_msec_cnt_2;  
}

/*
IRQ callback function for LED blinking, for debugging 
*/
bool led_blink_irq (struct repeating_timer *timer2) {
    gpio_put(LED_PIN, led_state);
    led_state = !led_state;
    int blink_repeat = 0;

    if (blink_period_ms == DHCP_LED_DEBUG) blink_repeat = DHCP_BLINK_REPEAT*2;

    for (int i = 0; i<blink_repeat; i++) {
          gpio_put(LED_PIN, led_state);
          led_state = !led_state;
          busy_wait_ms(BLINK_PAUSE);
    }

    return true;  // Keep repeating
}

/*
IRQ callback function for watchdog
*/
bool watchdog_irq (struct repeating_timer *timer1) {
  if (millis() < TIME_TO_LIFE) {
    watchdog_update(); // Update the watchdog
    return true;  // Keep repeating
  }
  return false;
}

/*
Function for updatinf IRQ callback function period time 
*/
void update_blink_period(int new_period_ms) {
    blink_period_ms = new_period_ms;
    cancel_repeating_timer(&timer2);
    add_repeating_timer_ms(-blink_period_ms, led_blink_irq, NULL, &timer2);
}

