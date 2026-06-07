// SERVER                         //
// Netdata functions              //
// Ver. 0.4                       //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //

/* 
This header purpose is to define 2 structures that will be used to maintain 
sessions and to define frames that will be send 
*/

#ifndef RESTART_H
#define RESTART_H

#include <stdint.h>

/* This header purpose is to define 2 structures that will be used to maintain 
sessions and to define frames that will be send 
*/

/* ============================================================
 * DATA STRUCTURE: frame_t
 * ============================================================
 * Defines the binary layout of the network packets (frames).
 * #pragma pack(push,1) forces the compiler to align every field
 * precisely, ensuring the frame looks exactly the same in memory
 * for both the sender and the receiver.
 * ============================================================ */
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t version;
    uint32_t restart_count;         
} restart_data_t;

/* Load from flash at boot */
void res_count_init(void);

/* Increment and save (call this early in main() after res_count_init()) */
void res_count_increment(void);

/* Save to flash – very similar to blacklist_save but much smaller */
void res_count_save(void);

#endif

