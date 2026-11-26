#pragma once
#include <cstdio>
#define ESP_LOGE(tag, ...) do { fprintf(stderr, __VA_ARGS__); fputc('\n',stderr); } while(0)
#define ESP_LOGW(tag, ...) ((void)0)
#define ESP_LOGI(tag, ...) ((void)0)
#define ESP_LOGD(tag, ...) ((void)0)
