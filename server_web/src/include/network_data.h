// SERVER                         //
// Netdata functions              //
// Ver. 0.4                       //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //

/* 
This header file declares prototypes of functions to configure 
networking information of the module, such as DHCP, 
Manual, and LAST used settings. 
Function bodies are in network_data.c.
*/
#ifndef NETWORK_DATA_H
#define NETWORK_DATA_H
#include "wizchip_conf.h"

// Enum to select the type of network information (netinfo)
typedef enum {
  NETDATA_LAST,     // Last used network settings
  NETDATA_DHCP,     // Dynamic Host Configuration Protocol (DHCP)
  NETDATA_MANUAL,    // Manual network settings
  NETDATA_DEFAULT    // Default network settings
} NetInfoType;

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
void disable_ping(void);

void renew_dhcp(void);

////////////////////////////////
/// Apply DHCP Configuration ///
///////////////////////////////
/*
Determines network settings by DHCP
*/
wiz_NetInfo get_data_dhcp(void);
///////////////////////////
///////////////////////////

int read_pico(const int sockfd, uint8_t *msg, const unsigned int size);

//////////////////////////////////////////
// Data Sender – FULL + NON-FATAL
//////////////////////////////////////////
int write_pico(const int sockfd, const uint8_t *msg, const unsigned int size);

////////////////////////////
/// DHCP Configuration   ///
////////////////////////////
/*
Attempts to obtain an IP address dynamically using DHCP.
Retries a limited number of times before failing.
*/
static void dhcp_usage(void);
///////////////////////////
///////////////////////////

//////////////////////////////
/// DHCP Callback - Assign ///
//////////////////////////////
/*
Retrieves the assigned network parameters from DHCP 
and updates the global network info structure.
*/
static void wizchip_dhcp_assign(void);
///////////////////////////
///////////////////////////

////////////////////////////////
/// DHCP Callback - Conflict ///
////////////////////////////////
/*
Handles IP conflicts detected by DHCP and exits with an error.
*/
static void wizchip_dhcp_conflict(void);
///////////////////////////
///////////////////////////

///////////////////////
/// Initialize DHCP ///
///////////////////////
/*
Initializes the DHCP client and registers necessary callback functions.
*/
static void wizchip_dhcp_init(void);
///////////////////////////
///////////////////////////



#endif