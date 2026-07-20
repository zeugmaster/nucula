#include "commands.h"
#include "console.h"
#include "wallet.hpp"
#include "wallet_store.hpp"
#include "unit.hpp"
#include "keyset.hpp"
#include "cashu_json.hpp"
#include "crypto.h"
#include "crypto_test.h"
#include "selftest.hpp"
#include "nfc.hpp"
#include "keypad.h"
#include "display.h"
#include "ui.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <esp_log.h>
#include <esp_heap_caps.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#define TAG "nucula"

// System commands: NFC control, keypad probing, and the reboot/heap/
// tasks/log/bench/selftest diagnostics.

static void cmd_nfc(const char *arg)
{
    if (!arg || strlen(arg) == 0) {
        console_printf("nfc: %s\r\n", nfc_status_str());
        return;
    }
    if (strncmp(arg, "request ", 8) == 0) {
        int amount = atoi(arg + 8);
        if (amount <= 0) {
            console_print("usage: nfc request <amount> [u=<unit>]\r\n");
            return;
        }
        if (nfc_state() == NfcState::off) {
            console_print("error: NFC not available\r\n");
            return;
        }
        CmdOpts opts;
        if (!parse_cmd_opts(strchr(arg + 8, ' '), opts))
            return;
        const std::string unit = opts.unit.empty()
            ? cashu::Wallet::default_unit() : opts.unit;
        char amt[48];
        cashu::format_amount(amt, sizeof(amt), amount, unit.c_str());
        console_printf("requesting %s via NFC...\r\n", amt);
        if (!nfc_request_start(amount, unit.c_str(), nullptr))
            console_print("error: failed to start\r\n");
        return;
    }
    if (strcmp(arg, "stop") == 0) {
        nfc_request_stop();
        console_print("nfc stopped\r\n");
        ui_refresh();
        return;
    }
    console_print("usage: nfc [request <amount> [u=<unit>]|stop]\r\n");
}

static void cmd_reboot(const char *arg)
{
    (void)arg;
    console_print("rebooting...\r\n");
    vTaskDelay(pdMS_TO_TICKS(100));
    esp_restart();
}

// -------------------------------------------------------------------------
// Telemetry
// -------------------------------------------------------------------------

static void cmd_heap(const char *arg)
{
    (void)arg;
    console_printf("free:          %lu\r\n", (unsigned long)esp_get_free_heap_size());
    console_printf("largest block: %u\r\n",
                   (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
    console_printf("min ever free: %lu\r\n",
                   (unsigned long)esp_get_minimum_free_heap_size());
}

static void cmd_tasks(const char *arg)
{
    (void)arg;
    UBaseType_t n = uxTaskGetNumberOfTasks();
    TaskStatus_t *st = (TaskStatus_t *)malloc(n * sizeof(TaskStatus_t));
    if (!st) {
        console_print("error: out of memory\r\n");
        return;
    }
    n = uxTaskGetSystemState(st, n, NULL);
    console_printf("%-16s %4s %10s\r\n", "name", "prio", "stack-min");
    for (UBaseType_t i = 0; i < n; i++)
        console_printf("%-16s %4u %10u\r\n", st[i].pcTaskName,
                       (unsigned)st[i].uxCurrentPriority,
                       (unsigned)st[i].usStackHighWaterMark);
    free(st);
}

static void cmd_log(const char *arg)
{
    esp_log_level_t level;
    if (arg && arg[0] && (arg[1] == '\0' || arg[1] == ' ')) {
        switch (arg[0]) {
            case 'e': level = ESP_LOG_ERROR; break;
            case 'w': level = ESP_LOG_WARN;  break;
            case 'i': level = ESP_LOG_INFO;  break;
            case 'd': level = ESP_LOG_DEBUG; break;
            default:  goto usage;
        }
        const char *tag = arg + 1;
        while (*tag == ' ') tag++;
        esp_log_level_set(*tag ? tag : "*", level);
        console_printf("log level '%c' set for %s\r\n", arg[0], *tag ? tag : "*");
        return;
    }
usage:
    console_print("usage: log <e|w|i|d> [tag]\r\n");
}

static void cmd_bench(const char *arg)
{
    (void)arg;
    console_print("benchmarking crypto primitives...\r\n");
    crypto_run_benchmark(wallet_store_ctx());
    console_print("done (results logged at info level)\r\n");
}

static void cmd_selftest(const char *arg)
{
    (void)arg;
    console_print("running self-tests (details logged at info level)...\r\n");
    bool ok = crypto_run_tests(wallet_store_ctx()) != 0;
    if (!cashu::keyset_run_tests())
        ok = false;
    if (!cashu::unit_run_tests())
        ok = false;
    if (!cashu::cashu_json_run_tests())
        ok = false;
    if (!nucula_pure_selftests())
        ok = false;
    if (!cashu::Wallet::run_tests())
        ok = false;
    console_printf("self-tests %s\r\n", ok ? "PASSED" : "FAILED");
}

// -------------------------------------------------------------------------
// Keypad
// -------------------------------------------------------------------------

static void cmd_keypad(const char *arg)
{
    if (!arg || strcmp(arg, "scan") != 0) {
        console_print("usage: keypad scan\r\n");
        console_print("  scan: probe each PCF8574 pin (P0-P6) and report which\r\n");
        console_print("        other pins go low. Press keys while scanning.\r\n");
        return;
    }

    console_print("keypad scan — press keys, each fires once per press (~30s)\r\n\r\n");

    int64_t deadline = esp_timer_get_time() + 30LL * 1000000;
    while (esp_timer_get_time() < deadline) {
        // Pull from the queue the background task fills — 200ms window per iteration
        char key = keypad_wait_event(200);
        if (key) {
            char line[32];
            snprintf(line, sizeof(line), "key: '%c'\r\n", key);
            console_print(line);
        }
    }
    console_print("scan done\r\n");
}

void commands_system_register(void)
{
    console_register_cmd("nfc",     cmd_nfc,      "nfc [request <amount>|stop]");
    console_register_cmd("keypad",  cmd_keypad,   "keypad scan — probe PCF8574 wiring");
    console_register_cmd("reboot",  cmd_reboot,   "restart the device");
    console_register_cmd("heap",    cmd_heap,     "show heap usage");
    console_register_cmd("tasks",   cmd_tasks,    "show task stack high-water marks");
    console_register_cmd("log",     cmd_log,      "log <e|w|i|d> [tag] — set log level");
    console_register_cmd("bench",   cmd_bench,    "benchmark crypto primitives");
    console_register_cmd("selftest", cmd_selftest, "run crypto/keyset self-tests");
}
