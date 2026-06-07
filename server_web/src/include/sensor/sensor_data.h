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

#ifndef SENSOR_DATA_H
#define SENSOR_DATA_H
extern volatile float g_sensor_temp;
extern volatile int g_sensor_co2;
extern volatile float g_sensor_pm1;
extern volatile float g_sensor_pm2p5;

void sensor_poll_task(void);

#endif
