#include "http.h"
#include "task_config.h"

#include <stdlib.h>
#include <string.h>
#include "esp_http_client.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_crt_bundle.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#define TAG "http"
#define MAX_RESPONSE_SIZE (32 * 1024)

// Cached keep-alive connections, one per origin (scheme://host[:port]).
// Every request pays a full TLS handshake (~2-3 s at 160 MHz) without
// reuse; with mbedTLS dynamic buffers an idle kept-alive connection pins
// only a few KB, far less churn than the per-request setup/teardown that
// used to fragment the heap. TLS session tickets are saved in the handle,
// so even a reconnect after a dropped socket skips the full handshake.
#define HTTP_CONN_SLOTS 2
#define HTTP_ORIGIN_MAX 96

typedef struct {
    char origin[HTTP_ORIGIN_MAX];         // "" when the slot is empty
    esp_http_client_handle_t client;
    int64_t last_used_us;
} conn_slot_t;

static conn_slot_t s_slots[HTTP_CONN_SLOTS];
static SemaphoreHandle_t s_mutex;         // serializes all HTTP activity

void http_init(void)
{
    if (!s_mutex)
        s_mutex = xSemaphoreCreateMutex();
}

static void http_lock(void)
{
    if (s_mutex)
        xSemaphoreTake(s_mutex, portMAX_DELAY);
}

static void http_unlock(void)
{
    if (s_mutex)
        xSemaphoreGive(s_mutex);
}

// scheme://host[:port] prefix length of url, or 0 when the URL is malformed.
static size_t origin_len(const char *url)
{
    const char *p = strstr(url, "://");
    if (!p)
        return 0;
    p += 3;
    const char *path = strchr(p, '/');
    return path ? (size_t)(path - url) : strlen(url);
}

typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} response_buf_t;

static esp_err_t on_event(esp_http_client_event_t *evt)
{
    response_buf_t *rb = (response_buf_t *)evt->user_data;
    if (!rb) return ESP_OK;

    if (evt->event_id == HTTP_EVENT_ON_DATA) {
        size_t needed = rb->len + evt->data_len;
        if (needed > MAX_RESPONSE_SIZE) {
            ESP_LOGW(TAG, "response truncated at %d bytes", MAX_RESPONSE_SIZE);
            return ESP_OK;
        }
        if (needed >= rb->cap) {
            size_t new_cap = rb->cap ? rb->cap * 2 : 1024;
            while (new_cap < needed + 1) new_cap *= 2;
            char *tmp = realloc(rb->buf, new_cap);
            if (!tmp) return ESP_ERR_NO_MEM;
            rb->buf = tmp;
            rb->cap = new_cap;
        }
        memcpy(rb->buf + rb->len, evt->data, evt->data_len);
        rb->len += evt->data_len;
        rb->buf[rb->len] = '\0';
    }
    return ESP_OK;
}

// Find or create the cached client for url's origin. Called under the lock.
static esp_http_client_handle_t slot_client_for(const char *url)
{
    size_t olen = origin_len(url);
    if (olen == 0 || olen >= HTTP_ORIGIN_MAX) {
        ESP_LOGE(TAG, "bad origin in url: %s", url);
        return NULL;
    }

    conn_slot_t *victim = &s_slots[0];
    for (int i = 0; i < HTTP_CONN_SLOTS; i++) {
        conn_slot_t *s = &s_slots[i];
        if (s->client && strlen(s->origin) == olen &&
            strncmp(s->origin, url, olen) == 0) {
            s->last_used_us = esp_timer_get_time();
            return s->client;
        }
        if (!s->client)
            victim = s;
        else if (victim->client && s->last_used_us < victim->last_used_us)
            victim = s;
    }

    if (victim->client) {
        ESP_LOGI(TAG, "evicting connection to %s", victim->origin);
        esp_http_client_cleanup(victim->client);
        victim->client = NULL;
    }

    esp_http_client_config_t cfg = {
        .url = url,
        .event_handler = on_event,
        .timeout_ms = 10000,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .keep_alive_enable = true,
        .save_client_session = true,   // TLS session ticket -> fast reconnect
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (!client) {
        ESP_LOGE(TAG, "client init failed");
        return NULL;
    }

    memcpy(victim->origin, url, olen);
    victim->origin[olen] = '\0';
    victim->client = client;
    victim->last_used_us = esp_timer_get_time();
    return client;
}

// Called under the lock when a transport error suggests the cached
// connection went stale: drop the socket but keep the handle (and its
// session ticket) for the retry.
static void close_socket_for(esp_http_client_handle_t client)
{
    esp_http_client_close(client);
}

static esp_err_t perform_with_timeout(const char *url, esp_http_client_method_t method,
                                      const char *post_data, int post_len,
                                      http_response_t *resp, int timeout_ms)
{
    http_lock();

    esp_http_client_handle_t client = slot_client_for(url);
    if (!client) {
        http_unlock();
        resp->body = NULL;
        resp->body_len = 0;
        resp->status = 0;
        return ESP_FAIL;
    }

    response_buf_t rb = {0};
    esp_err_t err = ESP_FAIL;
    long long ms = 0;

    // Attempt 0 uses the cached connection; if that fails with a transport
    // error (typically a server that closed the idle socket), reconnect —
    // resumed via the saved session ticket — and retry once.
    for (int attempt = 0; attempt < 2; attempt++) {
        free(rb.buf);
        memset(&rb, 0, sizeof(rb));

        esp_http_client_set_url(client, url);
        esp_http_client_set_method(client, method);
        esp_http_client_set_timeout_ms(client, timeout_ms);
        esp_http_client_set_user_data(client, &rb);
        if (post_data) {
            esp_http_client_set_header(client, "Content-Type", "application/json");
            esp_http_client_set_post_field(client, post_data, post_len);
        } else {
            // The handle may have carried a POST before. Its Content-Length
            // header persists on the reused handle and prepare_first_line
            // only skips (not deletes) it for a body-less GET, which would
            // make the server wait for a body that never comes.
            esp_http_client_delete_header(client, "Content-Type");
            esp_http_client_delete_header(client, "Content-Length");
            esp_http_client_set_post_field(client, NULL, 0);
        }

        int64_t t0 = esp_timer_get_time();
        err = esp_http_client_perform(client);
        ms = (esp_timer_get_time() - t0) / 1000;

        if (err == ESP_OK)
            break;

        close_socket_for(client);
        if (attempt == 0)
            ESP_LOGW(TAG, "request failed (%s), retrying on a fresh connection",
                     esp_err_to_name(err));
    }

    if (err == ESP_OK) {
        resp->status = esp_http_client_get_status_code(client);
        resp->body = rb.buf;
        resp->body_len = rb.len;
        ESP_LOGI(TAG, "%s %s -> %d in %lld ms (%zu B, heap %lu, largest %u)",
                 post_data ? "POST" : "GET", url, resp->status, ms,
                 resp->body_len, (unsigned long)esp_get_free_heap_size(),
                 (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
    } else {
        ESP_LOGE(TAG, "request failed after %lld ms: %s", ms, esp_err_to_name(err));
        free(rb.buf);
        resp->body = NULL;
        resp->body_len = 0;
        resp->status = 0;
    }

    // Detach our stack-local buffer before releasing the lock.
    esp_http_client_set_user_data(client, NULL);
    http_unlock();
    return err;
}

void http_close_all(void)
{
    http_lock();
    for (int i = 0; i < HTTP_CONN_SLOTS; i++) {
        if (s_slots[i].client) {
            esp_http_client_cleanup(s_slots[i].client);
            s_slots[i].client = NULL;
            s_slots[i].origin[0] = '\0';
        }
    }
    http_unlock();
}

static void prewarm_task(void *arg)
{
    char *url = (char *)arg;
    http_response_t resp = {0};
    if (http_get(url, &resp) == ESP_OK)
        http_response_free(&resp);
    free(url);
    vTaskDelete(NULL);
}

void http_prewarm(const char *base_url)
{
    if (!base_url || !base_url[0])
        return;
    size_t n = strlen(base_url) + sizeof("/v1/info");
    char *url = malloc(n);
    if (!url)
        return;
    snprintf(url, n, "%s/v1/info", base_url);
    if (xTaskCreate(prewarm_task, "http_warm", NUCULA_TASK_STACK_HTTP_WARM, url,
                    NUCULA_TASK_PRIO_HTTP_WARM, NULL) != pdPASS)
        free(url);
}

esp_err_t http_get(const char *url, http_response_t *resp)
{
    return perform_with_timeout(url, HTTP_METHOD_GET, NULL, 0, resp, 10000);
}

esp_err_t http_post_json(const char *url, const char *json_body,
                         http_response_t *resp)
{
    return perform_with_timeout(url, HTTP_METHOD_POST, json_body,
                                json_body ? (int)strlen(json_body) : 0,
                                resp, 10000);
}

esp_err_t http_post_json_timeout(const char *url, const char *json_body,
                                 http_response_t *resp, int timeout_ms)
{
    return perform_with_timeout(url, HTTP_METHOD_POST, json_body,
                                json_body ? (int)strlen(json_body) : 0,
                                resp, timeout_ms);
}

void http_response_free(http_response_t *resp)
{
    free(resp->body);
    resp->body = NULL;
    resp->body_len = 0;
}
