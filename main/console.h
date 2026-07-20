#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*console_cmd_handler_t)(const char *arg);

typedef struct {
    size_t max_line_length;
    size_t tx_buffer_size;
    size_t rx_buffer_size;
    size_t task_stack_size;
    int task_priority;
} console_config_t;

/* task_stack_size: command handlers run TLS on this stack (receive/melt).
 * Measured high-water mark after a full receive + bench + selftest pass:
 * ~7.1 KB used — 12 KB leaves ~5 KB margin. */
#define CONSOLE_DEFAULT_CONFIG() { \
    .max_line_length = 4096, \
    .tx_buffer_size = 4096, \
    .rx_buffer_size = 1024, \
    .task_stack_size = 12288, \
    .task_priority = 5, \
}

int console_init(const console_config_t *config);
int console_register_cmd(const char *name, console_cmd_handler_t handler, const char *help_text);
int console_start(void);
void console_print(const char *str);
void console_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#ifdef __cplusplus
}
#endif

