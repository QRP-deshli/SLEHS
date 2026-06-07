// SERVER                         //
// Netdata functions              //
// Ver. 0.4                       //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //

#include <stdint.h>
#include "sen63c_i2c.h"
#include "sensor_data.h"
#include "timing.h"
// Global variables to hold the latest cached sensor data
volatile float g_sensor_temp = 0.0f;
volatile int g_sensor_co2 = 0;
volatile float g_sensor_pm1 = 0.0f;
volatile float g_sensor_pm2p5 = 0.0f;
// Non-blocking task to update sensor values in the background
static uint32_t last_sensor_check = 0;

void sensor_poll_task(void) {
    
    uint32_t now = millis();

    // Only query the sensor over I2C every 500ms so we don't block the network
    if (now - last_sensor_check < 15000) return;
    last_sensor_check = now;

    uint8_t padding;
    bool data_ready = false;
    int16_t err = sen63c_get_data_ready(&padding, &data_ready);

    if (err == 0 && data_ready) {
        uint16_t pm1, pm2p5, pm4, pm10, co2;
        int16_t humidity, temperature;

        err = sen63c_read_measured_values_as_integers(
                &pm1, &pm2p5, &pm4, &pm10, &humidity, &temperature, &co2);

        // If read successfully, update our global web cache
        if (err == 0) {
            g_sensor_temp  = temperature / 200.0f;
            g_sensor_co2   = co2;
            g_sensor_pm1   = pm1 / 10.0f;
            g_sensor_pm2p5 = pm2p5 / 10.0f;
        }
    }
}

