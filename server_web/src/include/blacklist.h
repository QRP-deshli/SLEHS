// SERVER                         //
// Blacklist functions            //
// Ver. 0.4                       //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //

/* 
This header file declares functions for maintaining blacklist: 
updating, saving to the flash.  
*/

#ifndef BLACKLIST_H
#define BLACKLIST_H

/* ============================================================
 * DATA STRUCTURE: blacklist_entry_t
 * ============================================================
 * Represents a single tracked entity in the security system.
 *
 * __attribute__((packed)) ensures the compiler does not add
 * hidden "padding" bytes, making the structure exactly 6 bytes.
 * This is vital for predictable flash memory offsets.
 * ============================================================ */
typedef struct __attribute__((packed)) {
    uint8_t ip[4];      // The 4-byte IPv4 address being monitored.
    uint8_t strikes;    // Volatile penalty counter (RAM-only until threshold).
    uint8_t blocked;    // Persistence flag: 1 = Banned in Flash, 0 = Active/Probation.
    absolute_time_t last_strike_time; //Activity timestamp 
} blacklist_entry_t;

/* ============================================================
 * DATA STRUCTURE: blacklist_slot_t
 * ============================================================
 * The primary container for the entire blacklist database.
 * This structure is mapped directly to a 4KB Flash sector.
 *
 * magic - Used at boot to verify the flash sector isn't empty or corrupted.
 * seq   - Version control; higher numbers represent newer save states.
 * num   - Tracks how many entries are currently active in the list.
 * ver   - Logic version; ensures the software doesn't load outdated data formats.
 * ============================================================ */
typedef struct __attribute__((packed)) {
    uint32_t magic;     // Unique identifier for data validation.
    uint32_t seq;       // Sequence counter for rolling flash slot logic.
    uint16_t num;       // Number of valid entries in the array.
    uint16_t ver;       // Format version for backward compatibility.
    
    // The fixed-size database of offenders.
    blacklist_entry_t entries[MAX_BLACKLIST_ENTRY]; 
} blacklist_slot_t;


/* ============================================================
 * FLASH CALLBACKS
 * ============================================================  
*/
// Erase and Program functions must be in RAM (__no_inline_not_in_flash_func) 
// because the RP2040 cannot read code from Flash while writing to it.
static void __no_inline_not_in_flash_func(flash_erase_call)(uint32_t offs, uint32_t size) ;
static void __no_inline_not_in_flash_func(flash_prog_call)(uint32_t offs, const uint8_t *data, uint32_t len);

/* ============================================================
 * BLACKLIST INIT
 * ============================================================ */
void blacklist_init(void);
void print_blacklist(void);

/* ============================================================
 * CLEAR – now removes the entry completely
 * ============================================================ */
void clear_blacklist_ip(uint8_t ip[4]);

/* ============================================================
 * ADD STRIKE – strikes live ONLY in RAM until they reach STRIKE_MAX
 * ============================================================ */
void add_strike(uint8_t ip[4], uint8_t amount);

// Security Check: Used by the network stack to drop packets immediately if blocked.
bool is_blocked(uint8_t ip[4]);

/**
 Turns back amount of blocked ips in blacklist
 */
uint16_t get_blocked_count(void);

/* ============================================================
 * PERIODIC CLEANUP – removes inactive temporary strike entries
 * Called every ~60 seconds from main()
 * ============================================================ */
void blacklist_periodic_cleanup(void);

void blacklist_clear_all(void);
#endif