#ifndef NUCULA_WIFI_H
#define NUCULA_WIFI_H

#include "esp_err.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize WiFi in station mode and connect to the configured network.
 * Blocks until connected or until the maximum number of retries is exhausted.
 *
 * Internally initializes NVS, netif, the default event loop, and the WiFi
 * driver. Safe to call only once.
 *
 * @return ESP_OK if connected, ESP_FAIL if connection failed
 */
esp_err_t wifi_init(void);

/**
 * Returns true if WiFi is connected and the device has an IP address.
 */
bool wifi_is_connected(void);

#ifdef __cplusplus
}
#endif

#endif
