# Client-server API (mbed)        
# Client side                    
# Version 0.5.1                   
# Bachelor's work project        
# Technical University of Kosice 
# 10.11.2024                     
# Nikita Kuropatkin

# Define the target name for the executable
set(TARGET_NAME server_web)


# Path to mbedTLS inside libraries/
set(MBEDTLS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../libraries/mbedtls)

# Path to WIZnet-provided TLS config file
set(MBEDTLS_PORT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../port/mbedtls)


# Add all .c files from the project folder, including client_mbed.c
file(GLOB SRC_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/server_web.c 
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c 
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sensor/*.c 
)

# Add the executable with the source files
add_executable(${TARGET_NAME} ${SRC_FILES})

# Include the current directory for header files (if any headers are in the project folder)
target_include_directories(${TARGET_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/include  
    ${CMAKE_CURRENT_SOURCE_DIR}/web 
    ${CMAKE_CURRENT_SOURCE_DIR}/src/include/sensor
    ${CMAKE_CURRENT_SOURCE_DIR}/../../port/mbedtls     # FOLDER WITH ssl_config.h
)

add_definitions(-DPICO_FLASH_SIZE_BYTES=2097152)

# Link libraries (adjust as necessary)
target_link_libraries(${TARGET_NAME} 
    pico_unique_id
    hardware_clocks
    hardware_timer
    hardware_sync
    hardware_i2c
    pico_multicore
    pico_stdlib
    pico_stdio_uart
    pico_rand
    pico_flash
    hardware_spi
    hardware_dma
    ETHERNET_FILES
    IOLIBRARY_FILES
    TIMER_FILES
    DHCP_FILES
    DNS_FILES
    SNTP_FILES
    mbedtls
    mbedx509
    mbedcrypto
)

# If using Debug mode, configure USB and UART
pico_enable_stdio_usb(${TARGET_NAME} 1)
pico_enable_stdio_uart(${TARGET_NAME} 0)


# Macro defining USB/UART usage
target_compile_definitions(${TARGET_NAME} PRIVATE PICO_STDIO_USB_ENABLE=1)

# Macro defining USB/UART usage
target_compile_definitions(${TARGET_NAME} PRIVATE PICO_PING_ENABLE=1)

# Macro defining STACK size. DO NOT CHANGE THIS MACRO!
target_compile_definitions(${TARGET_NAME} PRIVATE PICO_STACK_SIZE=0x1000)

# Add extra outputs (like UF2 file for Raspberry Pi Pico)
pico_add_extra_outputs(${TARGET_NAME})
