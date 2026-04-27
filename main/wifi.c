#include "wifi.h"
#include "wifi_config.h"

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "nvs_flash.h"

/* Number of fast back-to-back retries the event handler will fire on its own
 * before handing off to the periodic supervisor. After this, the supervisor
 * reconnects on a fixed cadence and never gives up. */
#define FAST_RETRY_COUNT      3
#define SUPERVISOR_PERIOD_MS  30000

static const char *TAG = "wifi";
static EventGroupHandle_t s_event_group;
static int s_retry_count;
static bool s_connected;

static void wifi_supervisor_task(void *arg)
{
    (void)arg;
    for (;;) {
        if (!s_connected) {
            ESP_LOGI(TAG, "supervisor: attempting reconnect");
            esp_err_t err = esp_wifi_connect();
            if (err != ESP_OK && err != ESP_ERR_WIFI_CONN)
                ESP_LOGW(TAG, "esp_wifi_connect() returned %d", err);
        }
        vTaskDelay(pdMS_TO_TICKS(SUPERVISOR_PERIOD_MS));
    }
}

static void event_handler(void *arg, esp_event_base_t base,
                          int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *event =
            (wifi_event_sta_disconnected_t *)data;
        ESP_LOGW(TAG, "disconnected, reason: %d", event->reason);
        s_connected = false;
        xEventGroupClearBits(s_event_group, WIFI_CONNECTED_BIT);
        if (s_retry_count < FAST_RETRY_COUNT) {
            s_retry_count++;
            ESP_LOGI(TAG, "fast retry (%d/%d)", s_retry_count, FAST_RETRY_COUNT);
            esp_wifi_connect();
        }
        /* After FAST_RETRY_COUNT the supervisor task takes over. */
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "connected, ip: " IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_count = 0;
        s_connected = true;
        xEventGroupSetBits(s_event_group, WIFI_CONNECTED_BIT);
    }
}

esp_err_t wifi_init(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    s_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, NULL));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
            .threshold.authmode = WIFI_AUTH_OPEN,
        },
    };

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    /* Spawn the supervisor before we even check the initial result. The fast
     * retries from event_handler may already be exhausted by the time we
     * return; the supervisor takes it from there. */
    BaseType_t ok = xTaskCreate(wifi_supervisor_task, "wifi_sup",
                                2048, NULL, 3, NULL);
    if (ok != pdPASS)
        ESP_LOGE(TAG, "failed to spawn wifi_supervisor_task");

    ESP_LOGI(TAG, "connecting to \"%s\"...", WIFI_SSID);

    EventBits_t bits = xEventGroupWaitBits(s_event_group,
                                           WIFI_CONNECTED_BIT,
                                           pdFALSE, pdFALSE,
                                           pdMS_TO_TICKS(15000));

    if (bits & WIFI_CONNECTED_BIT) {
        esp_wifi_set_ps(WIFI_PS_NONE);
        return ESP_OK;
    }

    ESP_LOGW(TAG, "not connected within 15s; supervisor continues retrying");
    return ESP_FAIL;
}

bool wifi_is_connected(void)
{
    return s_connected;
}

EventGroupHandle_t wifi_get_event_group(void)
{
    return s_event_group;
}
