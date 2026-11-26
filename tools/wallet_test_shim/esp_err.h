#pragma once
using esp_err_t = int;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NVS_NOT_FOUND 1
#define ESP_ERR_NVS_TYPE_MISMATCH 2
#define ESP_ERR_NVS_INVALID_LENGTH 3
inline const char* esp_err_to_name(esp_err_t) { return "mock storage/HTTP error"; }
