#!/usr/bin/env python3
"""Run the real OLED driver against a host model of Rev B power/reset and I2C."""
from pathlib import Path
import subprocess
import tempfile

source = Path(__file__).resolve().parents[1]
headers = {
    "driver/i2c_master.h": """
#pragma once
#include <cstddef>
#include <cstdint>
#include <cassert>
using esp_err_t = int;
constexpr int ESP_OK = 0;
#define ESP_ERROR_CHECK(expr) assert((expr) == ESP_OK)
const char *esp_err_to_name(int);
using i2c_master_bus_handle_t = void *;
using i2c_master_dev_handle_t = void *;
constexpr int I2C_ADDR_BIT_LEN_7 = 0;
struct i2c_device_config_t {
    int dev_addr_length;
    uint16_t device_address;
    uint32_t scl_speed_hz;
};
int i2c_master_probe(void *, uint16_t, int);
int i2c_master_bus_add_device(void *, const i2c_device_config_t *, void **);
int i2c_master_bus_rm_device(void *);
int i2c_master_transmit(void *, const uint8_t *, size_t, int);
""",
    "driver/gpio.h": """
#pragma once
constexpr int GPIO_NUM_3=3, GPIO_NUM_4=4, GPIO_NUM_5=5, GPIO_NUM_10=10;
constexpr int GPIO_MODE_OUTPUT=1;
int gpio_set_level(int, int);
int gpio_set_direction(int, int);
""",
    "freertos/FreeRTOS.h": """
#pragma once
#define pdMS_TO_TICKS(ms) (ms)
#define portMAX_DELAY -1
""",
    "freertos/task.h": "#pragma once\nvoid vTaskDelay(int);\n",
    "freertos/semphr.h": """
#pragma once
using SemaphoreHandle_t = void *;
void *xSemaphoreCreateMutex();
int xSemaphoreTake(void *, int);
int xSemaphoreGive(void *);
""",
    "esp_system.h": "#pragma once\nint esp_register_shutdown_handler(void (*)());\n",
    "esp_log.h": """
#pragma once
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGW(...) ((void)0)
#define ESP_LOGE(...) ((void)0)
""",
}

harness = r'''
#include "display.h"
#include "board.h"
#include <algorithm>
#include <cassert>
#include <iostream>
#include <string>
#include <vector>

static std::string scenario;
static int ms, reset_at, release_at, power_at, on_at, tx_count, fail_tx;
static bool power, reset, live, locked, cleared, configured, turned_on;
static bool disabled_command, ever_powered, removed;
static int probes;
static void (*shutdown_handler)();
static std::vector<uint8_t> last_frame;

const char *esp_err_to_name(int) { return "injected failure"; }
void vTaskDelay(int delay) { assert(delay > 0); ms += delay; }
void *xSemaphoreCreateMutex() { return scenario == "no-mutex" ? nullptr : &locked; }
int xSemaphoreTake(void *m, int) { assert(m == &locked && !locked); locked=true; return 1; }
int xSemaphoreGive(void *m) { assert(m == &locked && locked); locked=false; return 1; }
int gpio_set_direction(int pin, int mode) {
    assert(mode == GPIO_MODE_OUTPUT);
    assert((pin == 3 && !power) || (pin == 10 && reset));
    return 0;
}
int gpio_set_level(int pin, int level) {
    assert(pin == 3 || pin == 10);
    if (pin == 3) {
        if (level) {
            assert(!reset && configured && cleared && shutdown_handler);
            if (scenario == "power-fail") return 1;
            power_at=ms; ever_powered=true;
        } else if (power) {
            assert(disabled_command); // AE attempted before boost removal, even on I2C failure
        }
        power=level;
    } else {
        if (level) { assert(!power); reset_at=ms; }
        else { assert(reset && ms-reset_at >= 1); release_at=ms; }
        reset=level;
    }
    return 0;
}
int i2c_master_probe(void *bus, uint16_t addr, int timeout) {
    assert(bus && addr == 0x3c && timeout > 0);
    assert(!power && !reset && ms-release_at >= 5);
    probes++;
    return scenario == "absent" ? 1 : 0;
}
int i2c_master_bus_add_device(void *, const i2c_device_config_t *cfg, void **dev) {
    assert(cfg->device_address == 0x3c && cfg->scl_speed_hz == 100000);
    if (scenario == "add-fail") return 1;
    *dev=&live; live=true; return 0;
}
int i2c_master_bus_rm_device(void *dev) {
    assert(dev == &live && live && !power && reset);
    live=false; removed=true; return 0;
}
int esp_register_shutdown_handler(void (*handler)()) {
    if (scenario == "shutdown-register-fail") return 1;
    shutdown_handler=handler; return 0;
}
int i2c_master_transmit(void *dev, const uint8_t *p, size_t n, int timeout) {
    assert(dev == &live && live && !reset && timeout > 0);
    tx_count++;
    if (n == 2 && p[0] == 0 && p[1] == 0xae) disabled_command=true;
    if (tx_count == fail_tx) return 1;
    if (p[0] == 0x40) {
        assert(n == 1025);
        if (!turned_on) {
            assert(!power);
            assert(std::all_of(p+1, p+n, [](uint8_t v) { return v == 0; }));
            cleared=true;
        }
        last_frame.assign(p+1, p+n);
    } else if (n == 2 && p[1] == 0xaf) {
        assert(power && ms-power_at >= 100 && cleared && configured);
        turned_on=true; on_at=ms;
    } else if (n > 7) {
        assert(!power);
        const std::vector<uint8_t> cmds(p+1, p+n);
        assert(cmds[0] == 0xfd && cmds[1] == 0x12 && cmds[2] == 0xae);
        assert(std::find(cmds.begin(), cmds.end(), 0x8d) == cmds.end());
        assert(std::find(cmds.begin(), cmds.end(), 0xaf) == cmds.end());
        const std::vector<uint8_t> vcom={0xdb, 0x34}, precharge={0xd9, 0x22};
        assert(std::search(cmds.begin(), cmds.end(), vcom.begin(), vcom.end()) != cmds.end());
        assert(std::search(cmds.begin(), cmds.end(), precharge.begin(), precharge.end()) != cmds.end());
        configured=true;
    }
    return 0;
}

int main(int argc, char **argv) {
    assert(argc == 2); scenario=argv[1];
    if (scenario == "init-fail") fail_tx=1;
    if (scenario == "init-window-fail") fail_tx=2;
    if (scenario == "init-data-fail") fail_tx=3;
    if (scenario == "on-fail") fail_tx=4;
    display_init(scenario == "no-bus" ? nullptr : &probes);
    if (scenario == "success" || scenario == "shutdown-fail" || scenario.rfind("update-", 0) == 0) {
        assert(power && !reset && live && turned_on && ms-on_at >= 100);
        if (scenario == "update-window-fail") fail_tx=tx_count+1;
        if (scenario == "update-data-fail") fail_tx=tx_count+2;
        display_pixel(0, 0, true);
        display_update();
        if (scenario.rfind("update-", 0) == 0) {
            assert(!power && reset && removed);
        } else {
            assert(last_frame[0] == 1);
        }
        if (scenario == "shutdown-fail") fail_tx=tx_count+1;
        assert(shutdown_handler);
        shutdown_handler();
        assert(removed);
    } else {
        assert(!turned_on);
        if (scenario != "on-fail") assert(!ever_powered);
    }
    assert(!power && reset && !live && !locked);
    const int stopped_at=tx_count;
    display_update();
    if (shutdown_handler) shutdown_handler();
    assert(tx_count == stopped_at); // no repeated traffic after absence or failure
    if (scenario == "no-bus" || scenario == "no-mutex") assert(probes == 0);
    std::cout << scenario << " passed\n";
}
'''

with tempfile.TemporaryDirectory(prefix="nucula-display-test-") as temp:
    root = Path(temp)
    for name, content in headers.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    (root / "test.cpp").write_text(harness)
    subprocess.run([
        "c++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
        "-I" + str(root), "-I" + str(source / "main"),
        str(root / "test.cpp"), str(source / "main/display.cpp"),
        "-o", str(root / "test"),
    ], check=True)
    for scenario in [
        "success", "no-bus", "no-mutex", "absent", "add-fail", "shutdown-register-fail",
        "init-fail", "init-window-fail", "init-data-fail", "power-fail", "on-fail",
        "update-window-fail", "update-data-fail", "shutdown-fail",
    ]:
        subprocess.run([str(root / "test"), scenario], check=True)
