#include "wifi.h"
#include "task_config.h"
#include "wifi_config.h"
#include "http.h"

#include <stdatomic.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"

/* Number of fast back-to-back retries the event handler will fire on its own
 * before handing off to the periodic supervisor. After this, the supervisor
 * reconnects on a fixed cadence and never gives up. */
#define FAST_RETRY_COUNT      3
#define SUPERVISOR_PERIOD_MS  30000

#define TAG "wifi"

// Public resolvers used only when DHCP hands out no DNS server.
#define WIFI_FALLBACK_DNS_MAIN   "1.1.1.1"
#define WIFI_FALLBACK_DNS_BACKUP "8.8.8.8"
static EventGroupHandle_t s_event_group;
static int s_retry_count;
static atomic_bool s_connected;

static void wifi_supervisor_task(void *arg)
{
    (void)arg;
    bool was_connected = false;
    for (;;) {
        if (!s_connected) {
            if (was_connected) {
                /* Falling edge: the cached HTTP connections are dead. Done
                 * here (not in the event handler) because closing blocks on
                 * the HTTP mutex until any in-flight request finishes. */
                http_close_all();
            }
            ESP_LOGI(TAG, "supervisor: attempting reconnect");
            esp_err_t err = esp_wifi_connect();
            if (err != ESP_OK && err != ESP_ERR_WIFI_CONN)
                ESP_LOGW(TAG, "esp_wifi_connect() returned %d", err);
        }
        was_connected = s_connected;
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

        /* Some networks hand out an IP but no usable DNS server (the DHCP
         * lease omits it). lwIP then fails name resolution instantly with
         * EAI_FAIL, so the mints never resolve. If the main DNS slot is
         * empty, install public resolvers as a fallback. */
        esp_netif_dns_info_t dns = {0};
        esp_netif_get_dns_info(event->esp_netif, ESP_NETIF_DNS_MAIN, &dns);
        ESP_LOGI(TAG, "got ip=" IPSTR " gw=" IPSTR " dns=" IPSTR,
                 IP2STR(&event->ip_info.ip), IP2STR(&event->ip_info.gw),
                 IP2STR(&dns.ip.u_addr.ip4));
        if (dns.ip.u_addr.ip4.addr == 0) {
            esp_netif_dns_info_t main_dns = { .ip.type = ESP_IPADDR_TYPE_V4 };
            esp_netif_dns_info_t backup_dns = { .ip.type = ESP_IPADDR_TYPE_V4 };
            main_dns.ip.u_addr.ip4.addr   = esp_ip4addr_aton(WIFI_FALLBACK_DNS_MAIN);
            backup_dns.ip.u_addr.ip4.addr = esp_ip4addr_aton(WIFI_FALLBACK_DNS_BACKUP);
            esp_netif_set_dns_info(event->esp_netif, ESP_NETIF_DNS_MAIN,
                                   &main_dns);
            esp_netif_set_dns_info(event->esp_netif, ESP_NETIF_DNS_BACKUP,
                                   &backup_dns);
            ESP_LOGW(TAG, "no DNS from DHCP; using fallback "
                     WIFI_FALLBACK_DNS_MAIN " / " WIFI_FALLBACK_DNS_BACKUP);
        }

        s_retry_count = 0;
        s_connected = true;
        xEventGroupSetBits(s_event_group, WIFI_CONNECTED_BIT);
    }
}

/* Log-and-return instead of ESP_ERROR_CHECK: a failed WiFi bring-up must
 * degrade to offline operation (the app tolerates ESP_FAIL), not abort()
 * the whole wallet. */
#define WIFI_RETURN_ON_ERROR(x) do {                                   \
        esp_err_t err_ = (x);                                          \
        if (err_ != ESP_OK) {                                          \
            ESP_LOGE(TAG, "%s failed: %s", #x, esp_err_to_name(err_)); \
            return err_;                                               \
        }                                                              \
    } while (0)

esp_err_t wifi_init(void)
{
    s_event_group = xEventGroupCreate();
    if (!s_event_group)
        return ESP_ERR_NO_MEM;

    WIFI_RETURN_ON_ERROR(esp_netif_init());
    WIFI_RETURN_ON_ERROR(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    WIFI_RETURN_ON_ERROR(esp_wifi_init(&cfg));

    WIFI_RETURN_ON_ERROR(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, NULL));
    WIFI_RETURN_ON_ERROR(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, NULL));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
            .threshold.authmode = WIFI_AUTH_OPEN,
        },
    };

    WIFI_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_STA));
    WIFI_RETURN_ON_ERROR(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    WIFI_RETURN_ON_ERROR(esp_wifi_start());

    /* Spawn the supervisor before we even check the initial result. The fast
     * retries from event_handler may already be exhausted by the time we
     * return; the supervisor takes it from there. */
    /* 4096: the supervisor also runs http_close_all (TLS teardown) now, and
     * its high-water mark was already down to ~270 bytes at 2048. */
    BaseType_t ok = xTaskCreate(wifi_supervisor_task, "wifi_sup",
                                NUCULA_TASK_STACK_WIFI_SUP, NULL,
                                NUCULA_TASK_PRIO_WIFI_SUP, NULL);
    if (ok != pdPASS)
        ESP_LOGE(TAG, "failed to spawn wifi_supervisor_task");

    ESP_LOGI(TAG, "connecting to \"%s\"...", WIFI_SSID);

    EventBits_t bits = xEventGroupWaitBits(s_event_group,
                                           WIFI_CONNECTED_BIT,
                                           pdFALSE, pdFALSE,
                                           pdMS_TO_TICKS(15000));

    if (bits & WIFI_CONNECTED_BIT) {
        /* Battery device: let the radio doze between DTIM beacons. Costs
         * ~100-300 ms first-packet latency; wifi_set_low_latency(true)
         * lifts it for the NFC payment window. */
        esp_wifi_set_ps(WIFI_PS_MIN_MODEM);
        return ESP_OK;
    }

    ESP_LOGW(TAG, "not connected within 15s; supervisor continues retrying");
    return ESP_FAIL;
}

bool wifi_is_connected(void)
{
    return s_connected;
}

void wifi_set_low_latency(bool on)
{
    esp_wifi_set_ps(on ? WIFI_PS_NONE : WIFI_PS_MIN_MODEM);
}

EventGroupHandle_t wifi_get_event_group(void)
{
    return s_event_group;
}
