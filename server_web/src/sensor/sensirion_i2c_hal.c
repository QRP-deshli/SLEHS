#include "sensirion_i2c_hal.h"
#include "pico/stdlib.h"
#include "hardware/i2c.h"

#define I2C_PORT    i2c0
#define SDA_PIN     4
#define SCL_PIN     5

void sensirion_i2c_hal_init(void) {
    i2c_init(I2C_PORT, 100000);        // 100 kHz
    gpio_set_function(SDA_PIN, GPIO_FUNC_I2C);
    gpio_set_function(SCL_PIN, GPIO_FUNC_I2C);
    gpio_pull_up(SDA_PIN);
    gpio_pull_up(SCL_PIN);
}

// === IMPORTANT: Use uint8_t for count (as declared in the header) ===
int8_t sensirion_i2c_hal_read(uint8_t address, uint8_t* data, uint8_t count) {
    int ret = i2c_read_blocking(I2C_PORT, address, data, count, false);
    return (ret == count) ? 0 : -1;
}

int8_t sensirion_i2c_hal_write(uint8_t address, const uint8_t* data, uint8_t count) {
    int ret = i2c_write_blocking(I2C_PORT, address, data, count, false);
    return (ret == count) ? 0 : -1;
}

void sensirion_i2c_hal_sleep_usec(uint32_t useconds) {
    sleep_us(useconds);
}