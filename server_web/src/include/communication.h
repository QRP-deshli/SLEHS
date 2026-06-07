// SERVER                         //
// Netdata functions              //
// Ver. 0.4                       //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //

/* 
This header purpose is to define function used to process ingress and outgress 
traffic from the server
*/

#ifndef COMMUNICATION_H
#define COMMUNICATION_H

#include <stdbool.h>
#include "parameters.h"

/* ============================================================
 * FUNCTION: is_valid_cmd
 * ============================================================
 * Verifies that received command byte matches
 * one of the supported protocol commands.
 *
 * Provides first-layer protocol validation.
 * ============================================================ */
static bool is_valid_cmd(uint8_t cmd);

bool init_frame( uint8_t sk, frame_t *rx, frame_t *tx, sess_t *s ) ;

/* ============================================================
 * FUNCTION: proc_frame
 * ============================================================
 * Processes a single protocol frame.
 *
 * - Validates header fields and counters
 * - Performs authentication (CMD_AUTH)
 * - Derives and rotates session keys
 * - Verifies message authentication tag
 * - Handles application data
 * - Prepares ACK response frame
 *
 * Returns true if frame is valid and processed.
 * ============================================================ */  
bool proc_frame( uint8_t sk, frame_t *rx, frame_t *tx, sess_t *s );

/* --- HANDLE_NEW_CONNECTION ---
 * Cleans the session slot for a fresh TCP client.
 */
void handle_new_connection(uint8_t sk, sess_t *s);

/* --- PROCESS_ONE_INCOMING_FRAME ---
 * High-level router for incoming socket data.
 */
bool process_one_incoming_frame(uint8_t sk, sess_t *s);

/* --- SEND_STATUS_UPDATE ---
 * Transmits system status (Socket/Blacklist stats) to client.
 */
void send_status_update(uint8_t sk, sess_t *s);

/* --- HANDLE_KEEPALIVE_PING ---
 * Ensures the client is still alive during idle periods.
 */
void handle_keepalive_ping(uint8_t sk, sess_t *s);
#endif