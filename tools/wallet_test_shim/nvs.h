#pragma once
#include "esp_err.h"
#include <stddef.h>
#include <stdint.h>
using nvs_handle_t = unsigned;
#define NVS_READONLY 0
#define NVS_READWRITE 1
esp_err_t nvs_open(const char*, int, nvs_handle_t*);
void nvs_close(nvs_handle_t);
esp_err_t nvs_commit(nvs_handle_t);
esp_err_t nvs_erase_key(nvs_handle_t, const char*);
esp_err_t nvs_get_blob(nvs_handle_t, const char*, void*, size_t*);
esp_err_t nvs_set_blob(nvs_handle_t, const char*, const void*, size_t);
esp_err_t nvs_get_str(nvs_handle_t, const char*, char*, size_t*);
esp_err_t nvs_set_str(nvs_handle_t, const char*, const char*);
esp_err_t nvs_get_u8(nvs_handle_t, const char*, uint8_t*);
esp_err_t nvs_set_u8(nvs_handle_t, const char*, uint8_t);
esp_err_t nvs_get_u32(nvs_handle_t, const char*, uint32_t*);
esp_err_t nvs_get_u64(nvs_handle_t, const char*, uint64_t*);
esp_err_t nvs_set_u64(nvs_handle_t, const char*, uint64_t);
