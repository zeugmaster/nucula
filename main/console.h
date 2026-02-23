#ifndef NUCULA_CONSOLE_H
#define NUCULA_CONSOLE_H

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

#define CONSOLE_DEFAULT_CONFIG() { \
    .max_line_length = 4096, \
    .tx_buffer_size = 4096, \
    .rx_buffer_size = 256, \
    .task_stack_size = 24576, \
    .task_priority = 5, \
}

int console_init(const console_config_t *config);
int console_register_cmd(const char *name, console_cmd_handler_t handler, const char *help_text);
int console_start(void);
void nucula_console_write(const char *str);
void console_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#ifdef __cplusplus
}
#endif

#endif
