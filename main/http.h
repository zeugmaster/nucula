#ifndef NUCULA_HTTP_H
#define NUCULA_HTTP_H

#include "esp_err.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int status;
    char *body;
    size_t body_len;
} http_response_t;

/**
 * Perform an HTTP GET request. Response body is heap-allocated.
 * Caller must call http_response_free() when done.
 *
 * @return ESP_OK on successful HTTP exchange (check resp->status for HTTP code)
 */
esp_err_t http_get(const char *url, http_response_t *resp);

/**
 * Perform an HTTP POST with a JSON body. Sets Content-Type: application/json.
 * Response body is heap-allocated. Caller must call http_response_free().
 *
 * @return ESP_OK on successful HTTP exchange (check resp->status for HTTP code)
 */
esp_err_t http_post_json(const char *url, const char *json_body, http_response_t *resp);

/**
 * Like http_post_json but with a custom timeout in milliseconds.
 * Use for long-running operations (e.g. Lightning payments).
 */
esp_err_t http_post_json_timeout(const char *url, const char *json_body,
                                 http_response_t *resp, int timeout_ms);

/**
 * Free a response body allocated by http_get or http_post_json.
 */
void http_response_free(http_response_t *resp);

#ifdef __cplusplus
}
#endif

#endif
