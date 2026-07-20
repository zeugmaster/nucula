#include "console.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <vector>

#define MAX_COMMANDS 32

struct command_entry {
    const char *name;
    console_cmd_handler_t handler;
    const char *help_text;
};

static struct {
    bool initialized;
    bool started;
    size_t max_line_length;
    size_t task_stack_size;
    int task_priority;
    char *line_buffer;
    std::vector<command_entry> commands;
} s_con;

void console_print(const char *str)
{
    if (str)
        usb_serial_jtag_write_bytes(str, strlen(str), portMAX_DELAY);
}

void console_printf(const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    console_print(buf);
}

static void cmd_help(const char *arg)
{
    (void)arg;
    console_print("\r\nAvailable commands:\r\n");
    for (const auto &cmd : s_con.commands) {
        console_print("  ");
        console_print(cmd.name);
        if (cmd.help_text) {
            size_t name_len = strlen(cmd.name);
            for (size_t i = name_len; i < 14; i++)
                console_print(" ");
            console_print("- ");
            console_print(cmd.help_text);
        }
        console_print("\r\n");
    }
}

static void process_command(char *cmd, char *arg)
{
    for (const auto &entry : s_con.commands) {
        if (strcmp(cmd, entry.name) == 0) {
            entry.handler(arg);
            return;
        }
    }
    console_print("unknown command: ");
    console_print(cmd);
    console_print("\r\ntype 'help' for available commands.\r\n");
}

static void parse_and_run(char *line)
{
    while (*line == ' ') line++;
    if (*line == '\0') return;

    char *cmd = line;
    char *arg = nullptr;

    char *space = strchr(line, ' ');
    if (space) {
        *space = '\0';
        arg = space + 1;
        while (*arg == ' ') arg++;
        if (*arg == '\0') arg = nullptr;
    }

    process_command(cmd, arg);
}

static void console_task(void *arg)
{
    (void)arg;
    int pos = 0;

    vTaskDelay(pdMS_TO_TICKS(500));
    console_print("\r\nnucula> ");

    // Read in chunks and batch the echo of printable runs: with per-byte
    // reads and a blocking 1-byte echo write each, a full-speed paste of a
    // ~1 KB token outran the task and overflowed the RX ring, silently
    // dropping bytes mid-token.
    while (1) {
        uint8_t buf[64];
        int len = usb_serial_jtag_read_bytes(buf, sizeof(buf),
                                             20 / portTICK_PERIOD_MS);
        if (len <= 0) continue;

        int echo_from = -1;  // start of the unechoed printable run in buf
        auto flush_echo = [&](int upto) {
            if (echo_from >= 0 && upto > echo_from)
                usb_serial_jtag_write_bytes(&buf[echo_from],
                                            upto - echo_from, portMAX_DELAY);
            echo_from = -1;
        };

        for (int i = 0; i < len; i++) {
            uint8_t c = buf[i];
            if (c == '\r' || c == '\n') {
                flush_echo(i);
                console_print("\r\n");
                s_con.line_buffer[pos] = '\0';
                parse_and_run(s_con.line_buffer);
                pos = 0;
                console_print("nucula> ");
            } else if (c == 127 || c == '\b') {
                flush_echo(i);
                if (pos > 0) {
                    pos--;
                    console_print("\b \b");
                }
            } else if (c == 0x03) {
                flush_echo(i);
                console_print("^C\r\n");
                pos = 0;
                console_print("nucula> ");
            } else if (pos < (int)s_con.max_line_length - 1) {
                s_con.line_buffer[pos++] = c;
                if (echo_from < 0)
                    echo_from = i;
            } else {
                flush_echo(i);  // line full: swallow without echo
            }
        }
        flush_echo(len);
    }
}

int console_init(const console_config_t *config)
{
    if (s_con.initialized) return -1;

    console_config_t cfg;
    if (config)
        cfg = *config;
    else
        cfg = CONSOLE_DEFAULT_CONFIG();

    s_con.line_buffer = (char *)malloc(cfg.max_line_length);
    if (!s_con.line_buffer) return -2;
    s_con.max_line_length = cfg.max_line_length;
    s_con.task_stack_size = cfg.task_stack_size;
    s_con.task_priority = cfg.task_priority;

    usb_serial_jtag_driver_config_t usb_config = {
        .tx_buffer_size = cfg.tx_buffer_size,
        .rx_buffer_size = cfg.rx_buffer_size,
    };
    if (usb_serial_jtag_driver_install(&usb_config) != ESP_OK) {
        free(s_con.line_buffer);
        return -3;
    }
    usb_serial_jtag_vfs_use_driver();

    console_register_cmd("help", cmd_help, "show this help");
    s_con.initialized = true;
    return 0;
}

int console_register_cmd(const char *name, console_cmd_handler_t handler, const char *help_text)
{
    if (!name || !handler) return -1;
    if (s_con.commands.size() >= MAX_COMMANDS) return -2;
    s_con.commands.push_back({name, handler, help_text});
    return 0;
}

int console_start(void)
{
    if (!s_con.initialized) return -1;
    if (s_con.started) return -2;

    BaseType_t ret = xTaskCreate(console_task, "console",
                                 s_con.task_stack_size, NULL,
                                 s_con.task_priority, NULL);
    if (ret != pdPASS) return -3;

    s_con.started = true;
    return 0;
}
