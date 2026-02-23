#include "http.h"

#include <stdlib.h>
#include <string.h>
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_crt_bundle.h"

#define TAG "http"
#define MAX_RESPONSE_SIZE (32 * 1024)

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

static esp_err_t perform(const char *url, esp_http_client_method_t method,
                         const char *post_data, int post_len,
                         http_response_t *resp)
{
    response_buf_t rb = {0};

    esp_http_client_config_t cfg = {
        .url = url,
        .event_handler = on_event,
        .user_data = &rb,
        .timeout_ms = 10000,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };

    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (!client) {
        ESP_LOGE(TAG, "client init failed");
        return ESP_FAIL;
    }

    esp_http_client_set_method(client, method);

    if (post_data) {
        esp_http_client_set_header(client, "Content-Type", "application/json");
        esp_http_client_set_post_field(client, post_data, post_len);
    }

    esp_err_t err = esp_http_client_perform(client);

    if (err == ESP_OK) {
        resp->status = esp_http_client_get_status_code(client);
        resp->body = rb.buf;
        resp->body_len = rb.len;
        ESP_LOGD(TAG, "%s %s -> %d (%zu bytes)", post_data ? "POST" : "GET",
                 url, resp->status, resp->body_len);
    } else {
        ESP_LOGE(TAG, "request failed: %s", esp_err_to_name(err));
        free(rb.buf);
        resp->body = NULL;
        resp->body_len = 0;
        resp->status = 0;
    }

    esp_http_client_cleanup(client);
    return err;
}

esp_err_t http_get(const char *url, http_response_t *resp)
{
    return perform(url, HTTP_METHOD_GET, NULL, 0, resp);
}

esp_err_t http_post_json(const char *url, const char *json_body,
                         http_response_t *resp)
{
    return perform(url, HTTP_METHOD_POST, json_body,
                   json_body ? (int)strlen(json_body) : 0, resp);
}

void http_response_free(http_response_t *resp)
{
    free(resp->body);
    resp->body = NULL;
    resp->body_len = 0;
}
