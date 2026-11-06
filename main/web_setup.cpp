#include "web_setup.h"
#include "console.h"
#include "wifi.h"
#include "cJSON.h"
#include "esp_app_desc.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <cstring>
#include <cstdlib>

static bool s_storage_ready;

// Hex fields preserve spaces and UTF-8 without console quoting or embedded
// JSON NUL ambiguity. Reject all console control characters after decoding.
static bool decode_field(const cJSON *root, const char *name, char *out, size_t size)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(root, name);
    if (!cJSON_IsString(item)) return false;
    const char *hex = item->valuestring;
    size_t len = strlen(hex);
    if (len % 2 || len / 2 >= size) return false;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    };
    for (size_t i = 0; i < len; i += 2) {
        int a = nibble(hex[i]), b = nibble(hex[i + 1]);
        if (a < 0 || b < 0) return false;
        unsigned char c = (a << 4) | b;
        if (c < 32 || c == 127) return false;
        out[i / 2] = c;
    }
    out[len / 2] = 0;
    return true;
}

static void cmd_web(const char *arg)
{
    const char *end = nullptr;
    cJSON *request = arg ? cJSON_ParseWithOpts(arg, &end, true) : nullptr;
    const cJSON *id = cJSON_GetObjectItemCaseSensitive(request, "id");
    const cJSON *op = cJSON_GetObjectItemCaseSensitive(request, "op");
    if (!cJSON_IsString(id) || strlen(id->valuestring) > 48 || !cJSON_IsString(op)) {
        cJSON_Delete(request);
        console_print("\r\n@NUCULA {\"ok\":false,\"error\":\"invalid_request\"}\r\n");
        return;
    }
    cJSON *response = cJSON_CreateObject();
    if (!response) { cJSON_Delete(request); return; }
    cJSON_AddStringToObject(response, "id", id->valuestring);
    bool reboot = false;
    if (strcmp(op->valuestring, "info") == 0) {
        char ssid[33] = {}, ip[16] = {};
        wifi_setup_ssid(ssid, sizeof(ssid));
        wifi_setup_ip(ip, sizeof(ip));
        cJSON_AddBoolToObject(response, "ok", true);
        cJSON_AddNumberToObject(response, "protocol", 1);
        cJSON_AddStringToObject(response, "board", "nucula-v2");
        cJSON_AddStringToObject(response, "storage_schema", "nucula-nvs-v1");
        cJSON_AddStringToObject(response, "version", esp_app_get_description()->version);
        cJSON_AddBoolToObject(response, "storage_ready", s_storage_ready);
        cJSON_AddBoolToObject(response, "configured", wifi_setup_configured());
        cJSON_AddBoolToObject(response, "connected", wifi_is_connected());
        cJSON_AddBoolToObject(response, "restart_required", wifi_setup_restart_required());
        cJSON_AddStringToObject(response, "ssid", ssid);
        cJSON_AddStringToObject(response, "ip", ip);
    } else if (strcmp(op->valuestring, "wifi.set") == 0) {
        char ssid[33] = {}, password[64] = {};
        bool valid = decode_field(request, "ssid_hex", ssid, sizeof(ssid)) &&
                     decode_field(request, "password_hex", password, sizeof(password));
        esp_err_t err = !s_storage_ready ? ESP_ERR_INVALID_STATE :
            !valid ? ESP_ERR_INVALID_ARG : wifi_save_credentials(ssid, password);
        cJSON_AddBoolToObject(response, "ok", err == ESP_OK);
        if (err == ESP_OK) cJSON_AddBoolToObject(response, "restart_required", true);
        else cJSON_AddStringToObject(response, "error", esp_err_to_name(err));
        memset(password, 0, sizeof(password));
    } else if (strcmp(op->valuestring, "reboot") == 0) {
        cJSON_AddBoolToObject(response, "ok", true);
        reboot = true;
    } else {
        cJSON_AddBoolToObject(response, "ok", false);
        cJSON_AddStringToObject(response, "error", "unsupported_operation");
    }
    char *json = cJSON_PrintUnformatted(response);
    if (json) {
        console_print("\r\n@NUCULA ");
        console_print(json);
        console_print("\r\n");
        free(json);
    }
    cJSON_Delete(response);
    cJSON_Delete(request);
    if (reboot) {
        vTaskDelay(pdMS_TO_TICKS(200));
        esp_restart();
    }
}

void web_setup_register(bool storage_ready)
{
    s_storage_ready = storage_ready;
    console_register_cmd("web", cmd_web, "USB setup protocol (used by nucula.dev/setup)");
}
