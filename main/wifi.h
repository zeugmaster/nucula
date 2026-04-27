#ifndef NUCULA_WIFI_H
#define NUCULA_WIFI_H

#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WIFI_CONNECTED_BIT BIT0

/**
 * Initialize WiFi in station mode and start the supervisor task.
 *
 * Spawns a long-lived FreeRTOS task that, while disconnected, periodically
 * re-tries esp_wifi_connect(). The initial connect attempt blocks for up to
 * 15 seconds; if it does not succeed in that window the function returns
 * ESP_FAIL while the supervisor keeps trying in the background.
 *
 * Safe to call only once.
 *
 * @return ESP_OK if connected within 15 s, ESP_FAIL otherwise
 */
esp_err_t wifi_init(void);

/**
 * Returns true if WiFi is connected and the device has an IP address.
 */
bool wifi_is_connected(void);

/**
 * Returns the FreeRTOS event group whose WIFI_CONNECTED_BIT is set whenever
 * the device is associated and has an IP, and cleared on disconnect. Other
 * tasks can wait on this bit to react to (re)connection events.
 */
EventGroupHandle_t wifi_get_event_group(void);

#ifdef __cplusplus
}
#endif

#endif
