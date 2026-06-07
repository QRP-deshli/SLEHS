// SERVER                         //
// Netdata functions              //
// Ver. 0.4                       //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "include/error.h" //All errors defined + function proto
#include "dhcp.h"
#include "include/parameters.h"
#include "include/network_data.h"
#include "wizchip_spi.h"
#include "socket.h"
#include "timing.h"
#include "w6100.h"
#include "hardware/watchdog.h"
#include "wizchip_conf.h"
#include "pico/stdlib.h"
#include "hardware/timer.h"
#include "hardware/regs/watchdog.h"

extern volatile int blink_period_ms;
/*
 * Default settings of the chip for network connection (networking data).  
 * You can modify these values based on your needs.
 *
 * This conditional block switches the entire network identity of the PICO.
 * It ensures that when you move the device from the University Lab to 
 * the Office, you don't have to manually rewrite the IP/MAC logic—you 
 * simply change the 'LOCATION' macro in parameters.h.
 */

#if LOCATION == LAB
  /* * LAB PROFILE: Configured for Lab 512.
   * Uses the Lab-specific MAC address and a static IP assignment 
   * within the 147.232.54.x subnet for easy remote access during testing.
   */
  wiz_NetInfo your_net_info =
  {
    .mac = DEVICE_MAC,             // MAC address (Resolves to Lab MAC)
    .ip = {147, 232, 54, 19},      // Fixed IP for debugging in the Lab environment
    .sn = {255, 255, 255, 0},      // Standard Class C Subnet Mask
    .gw = {147, 232, 54, 1},       // Default Gateway for Lab 512 routing
    .dns = {147, 232, 16, 16},     // University DNS Server
    .dhcp = NETINFO_DHCP           // DHCP enabled (will override static if server found)
  };

#elif LOCATION == OFFICE
  /* * OFFICE PROFILE: Configured for Production/Hidden use.
   * Even if the IP values look similar now, this allows for independent 
   * adjustment. The DEVICE_MAC here will resolve to the OFFICE MAC address
   * to avoid triggering security alerts on the office network.
   */
  wiz_NetInfo your_net_info =
  {
    .mac = DEVICE_MAC,             // MAC address (Resolves to Office MAC)
    .ip = {147, 232, 54, 19},      // IP address for the Office segment
    .sn = {255, 255, 255, 0},      // Subnet Mask
    .gw = {147, 232, 54, 1},       // Office Gateway
    .dns = {147, 232, 16, 16},     // Local DNS server
    .dhcp = NETINFO_DHCP           // DHCP enabled to blend in with dynamic clients
  };
  
#elif LOCATION == OFFICE2
  /* * OFFICE2 PROFILE: Configured for Production/Hidden use.
   * Even if the IP values look similar now, this allows for independent 
   * adjustment. The DEVICE_MAC here will resolve to the OFFICE MAC address
   * to avoid triggering security alerts on the office network.
   */
  wiz_NetInfo your_net_info =
  {
    .mac = DEVICE_MAC,             // MAC address (Resolves to Office MAC)
    .ip = {147, 232, 47, 163},      // IP address for the Office segment
    .sn = {255, 255, 255, 0},      // Subnet Mask
    .gw = {147, 232, 47, 1},       // Office Gateway
    .dns = {147, 232, 16, 16},     // Local DNS server
    .dhcp = NETINFO_DHCP           // DHCP enabled to blend in with dynamic clients
  };
#endif

/* * This global buffer is allocated in RAM to store raw Ethernet frames.
 * Its size (ETHERNET_BUF_MAX_SIZE) is defined in parameters.h.
 * Making it 'static' limits its scope to this file to prevent naming conflicts.
 */
static uint8_t g_ethernet_buf[ETHERNET_BUF_MAX_SIZE] = {0};

//////////////////////////////////////////
///        Ping Reply Disabler         ///
//////////////////////////////////////////
/*
The purpose of this function is to stop the W6100 chip from replying to
ICMP echo requests (ping) on both IPv4 and IPv6 networks. 

It does this by setting the Ping Block (PB) bit in the IPv4 and IPv6
network mode registers (NET4MR and NET6MR). Once enabled, any ping
requests sent to the device will be ignored, making the module 
non-pingable on the network.

This function should be called after the network configuration is done
(DHCP or static setup) and before starting normal communication.
*/
void disable_ping(void) {
    uint8_t net4mr = getNET4MR();
    uint8_t net6mr = getNET6MR();

    net4mr |= NETxMR_PB;
    net6mr |= NETxMR_PB;

    setNET4MR(net4mr);
    setNET6MR(net6mr);

    // Uncomment for DEBUG
    //printf("IPv4 NET4MR = 0x%02X\n", net4mr);
    //printf("IPv6 NET6MR = 0x%02X\n", net6mr);
}


//////////////////////////////////////////
/// Data Receiver ///
//////////////////////////////////////////
/*
The purpose of this function is to receive data over open sockets 
on Raspberry Pi Pico.
It takes the following parameters:  
1. `sockfd` - the ID of the socket where the data will be received.  
2. `msg` - a buffer where the received message will be written.  
3. `size` - the size of the message.  
The program exits in case of an error.
*/
//////////////////////////////////////////
// Data Receiver – FULL + NON-FATAL (postupne sčítava partial packety)
//////////////////////////////////////////
//////////////////////////////////////////
// Data Receiver – FULL + NON-FATAL (postupne sčítava partial packety)
// Používa správnu Wiznet API (3 argumenty)
//////////////////////////////////////////
int read_pico(const int sockfd, uint8_t *msg, const unsigned int size)
{
    uint16_t total = 0;
    uint8_t sn = (uint8_t)sockfd;
    uint32_t start_ms = millis();

    while (total < size) {
        // CRITICAL: bail out before the watchdog fires (5000ms limit)
        if (millis() - start_ms > 3500) {
            return -1;
        }

        watchdog_update();

        // Don't call recv() if no data is ready — poll instead
        int16_t avail = getSn_RX_RSR(sn);
        if (avail <= 0) {
            uint8_t sr = getSn_SR(sn);
            if (sr == SOCK_CLOSE_WAIT || sr == SOCK_CLOSED) return -1;
            wiz_delay_ms(1);
            continue;
        }

        int32_t retval = recv(sn, msg + total, (uint16_t)(size - total));
        if (retval <= 0) return -1;
        total += (uint16_t)retval;
    }
    return 0;
}

//////////////////////////////////////////
// Data Sender – FULL + NON-FATAL
//////////////////////////////////////////
int write_pico(const int sockfd, const uint8_t *msg, const unsigned int size)
{
    uint16_t total = 0;
    uint8_t sn = (uint8_t)sockfd;
    uint32_t start_ms = millis();

    while (total < size) {
        // CRITICAL: Bail out before the watchdog fires
        if (millis() - start_ms > 3500) {
            return -1;
        }

        watchdog_update(); // Keep system alive while trying to send

        // Check hardware buffer space before calling send()
        int16_t freesize = getSn_TX_FSR(sn);
        if (freesize == 0) {
            uint8_t sr = getSn_SR(sn);
            if (sr == SOCK_CLOSE_WAIT || sr == SOCK_CLOSED) return -1;
            wiz_delay_ms(1);
            continue; // Spin safely without freezing the CPU
        }

        // Only send the chunk that currently fits in the hardware buffer
        uint16_t chunk = (size - total > freesize) ? freesize : (size - total);
        int32_t retval = send(sn, (uint8_t*)(msg + total), chunk);
        
        if (retval <= 0) {
            return -1;
        }
        total += (uint16_t)retval;
    }
    return 0;
}
////////////////////////////////
/// Apply DHCP Configuration ///
///////////////////////////////
/*
Determines network settings by DHCP
*/
wiz_NetInfo get_data_dhcp(void) {

 printf("Configuring with DHCP...\n");
 if (DHCP_ACT == 1) {
  wizchip_dhcp_init(); // Initialize DHCP
  dhcp_usage(); // Attempt to obtain network settings via DHCP
 }
 else your_net_info.dhcp = NETINFO_STATIC;
 return your_net_info;
}
///////////////////////////
///////////////////////////

////////////////////
/// DHCP Renew   ///
////////////////////
/*
Attempts to renew an IP address lease from DHCP.
*/
void renew_dhcp(void) {
 int retval;
 uint8_t dhcp_retry = 0;

 while (1) {
   printf("Waiting for DHCP\n");
    
   // Check if DHCP is enabled
   if (your_net_info.dhcp == NETINFO_DHCP) {
     retval = DHCP_run();
     
     // Successful DHCP lease acquired
     if (retval == DHCP_IP_LEASED) {
       printf("DHCP renew\n");
       //DHCP_stop();
       return; // Exit function after obtaining an IP lease
     }

     // DHCP lease attempt failed, increment retry counter
     else if (retval == DHCP_FAILED) {
       dhcp_retry++;
       printf("DHCP retry : %d\n",dhcp_retry);
     }
  
     wiz_delay_ms(1000); // Wait before retrying
     watchdog_update();
   }
 }
}

////////////////////////////
/// DHCP Configuration   ///
////////////////////////////
/*
Attempts to obtain an IP address dynamically using DHCP.
Retries a limited number of times before failing.
*/
static void dhcp_usage(void) {
 int retval;
 uint8_t dhcp_retry = 0;
 uint32_t start_ms = millis(); //timer

 update_blink_period(DHCP_LED_DEBUG); //update LED

 while (1) {
   printf("Waiting for DHCP\n");
    
   // Check if DHCP is enabled
   if (your_net_info.dhcp == NETINFO_DHCP) {
     retval = DHCP_run();
     
     // Successful DHCP lease acquired
     if (retval == DHCP_IP_LEASED) {
       printf("DHCP success\n");
       //DHCP_stop();
       return; // Exit function after obtaining an IP lease
     }

     // DHCP lease attempt failed, increment retry counter
     else if (retval == DHCP_FAILED) {
       dhcp_retry++;
       printf("DHCP retry : %d\n",dhcp_retry);
     }
    
    if((millis() - start_ms) > TIME_FOR_DHCP) {
      your_net_info.dhcp = NETINFO_STATIC;
      printf("Switching to Static Network Data\n");
      DHCP_stop();
      return;
    }
     wiz_delay_ms(1000); // Wait before retrying
   }
 }
}
///////////////////////////
///////////////////////////

//////////////////////////////
/// DHCP Callback - Assign ///
//////////////////////////////
/*
Retrieves the assigned network parameters from DHCP 
and updates the global network info structure.
*/
static void wizchip_dhcp_assign(void) {
 getIPfromDHCP(your_net_info.ip);
 getGWfromDHCP(your_net_info.gw);
 getSNfromDHCP(your_net_info.sn);
 getDNSfromDHCP(your_net_info.dns);

 your_net_info.dhcp = NETINFO_DHCP;

 printf("\nDHCP leased time: %ld seconds\n", getDHCPLeasetime());
}
///////////////////////////
///////////////////////////

////////////////////////////////
/// DHCP Callback - Conflict ///
////////////////////////////////
/*
Handles IP conflicts detected by DHCP and exits with an error.
*/
static void wizchip_dhcp_conflict(void) {
 exit_with_error(CONFLICT_DHCP, "Conflict IP from DHCP");
}
///////////////////////////
///////////////////////////

///////////////////////
/// Initialize DHCP ///
///////////////////////
/*
Initializes the DHCP client and registers necessary callback functions.
*/
static void wizchip_dhcp_init(void) {
 printf("DHCP client started\n");
 DHCP_init(DHCP_SOCKET, g_ethernet_buf);

 // Register callback functions for DHCP events
 reg_dhcp_cbfunc(wizchip_dhcp_assign, wizchip_dhcp_assign, wizchip_dhcp_conflict);
}
///////////////////////////
///////////////////////////

