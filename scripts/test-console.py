#!/usr/bin/env python3
"""Host-test the real firmware console and web protocol without touching hardware."""
import argparse
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("source", type=Path, help="nucula firmware repository")
parser.add_argument("idf", type=Path, help="ESP-IDF repository (for its cJSON sources)")
args = parser.parse_args()

headers = {
    "esp_err.h": """
#pragma once
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_ERR_INVALID_ARG 1
#define ESP_ERR_INVALID_STATE 2
const char *esp_err_to_name(int);
""",
    "freertos/FreeRTOS.h": """
#pragma once
#include <cstdint>
#include <cstdlib>
typedef int BaseType_t;
#define BIT0 1
#define portMAX_DELAY 1000
#define pdMS_TO_TICKS(x) (x)
#define portTICK_PERIOD_MS 1
#define pdPASS 1
""",
    "freertos/task.h": """
#pragma once
#include "FreeRTOS.h"
void vTaskDelay(int);
int xTaskCreate(void (*)(void *), const char *, unsigned, void *, int, void *);
""",
    "freertos/event_groups.h": "#pragma once\ntypedef void *EventGroupHandle_t;\n",
    "driver/usb_serial_jtag.h": """
#pragma once
#include <cstddef>
#include <cstdint>
#define ESP_OK 0
struct usb_serial_jtag_driver_config_t { size_t tx_buffer_size; size_t rx_buffer_size; };
int usb_serial_jtag_write_bytes(const void *, size_t, int);
int usb_serial_jtag_read_bytes(void *, size_t, int);
int usb_serial_jtag_driver_install(usb_serial_jtag_driver_config_t *);
""",
    "driver/usb_serial_jtag_vfs.h": "#pragma once\nvoid usb_serial_jtag_vfs_use_driver();\n",
    "esp_app_desc.h": """
#pragma once
struct esp_app_desc_t { const char *version; };
const esp_app_desc_t *esp_app_get_description();
""",
    "esp_system.h": "#pragma once\nvoid esp_restart();\n",
}

harness = r'''
#include "console.h"
#include "web_setup.h"
#include "wifi.h"
#include "esp_app_desc.h"
#include "driver/usb_serial_jtag.h"
#include <algorithm>
#include <cassert>
#include <cstring>
#include <iostream>
#include <string>

struct InputFinished {};
static void (*run_task)(void *);
static std::string input, output, saved_ssid, saved_password;
static size_t position, packet_size;
static bool rebooted;
int usb_serial_jtag_write_bytes(const void *p, size_t n, int) { output.append((const char *)p,n); return n; }
int usb_serial_jtag_read_bytes(void *p, size_t n, int) {
    if (position == input.size()) throw InputFinished{};
    n = std::min({n, packet_size, input.size() - position});
    memcpy(p, input.data() + position, n); position += n; return n;
}
int usb_serial_jtag_driver_install(usb_serial_jtag_driver_config_t *) { return 0; }
void usb_serial_jtag_vfs_use_driver() {}
void vTaskDelay(int) {}
int xTaskCreate(void (*task)(void *), const char *, unsigned, void *, int, void *) { run_task=task; return 1; }
const esp_app_desc_t *esp_app_get_description() { static esp_app_desc_t d={"test-version"}; return &d; }
const char *esp_err_to_name(int n) { return n == 1 ? "ESP_ERR_INVALID_ARG" : "ESP_ERR_INVALID_STATE"; }
void esp_restart() { rebooted=true; }
extern "C" {
bool wifi_setup_configured() { return true; }
bool wifi_setup_restart_required() { return !saved_ssid.empty(); }
bool wifi_is_connected() { return true; }
void wifi_setup_ssid(char *out,size_t n) { snprintf(out,n,"Workshop"); }
void wifi_setup_ip(char *out,size_t n) { snprintf(out,n,"192.168.1.2"); }
esp_err_t wifi_save_credentials(const char *ssid,const char *password) {
    saved_ssid=ssid; saved_password=password; return ESP_OK;
}
}

static std::string send(const std::string &text, size_t chunk=64) {
    input=text; position=0; packet_size=chunk; output.clear();
    try { run_task(nullptr); } catch (InputFinished &) {}
    return output;
}
int main() {
    assert(console_init(nullptr)==0);
    web_setup_register(true);
    assert(console_start()==0);
    const std::string secret="73656372657470617373";
    const std::string request="web {\"id\":\"a\",\"op\":\"wifi.set\",\"ssid_hex\":\"20436166c3a920\",\"password_hex\":\""+secret+"\"}\r";
    for (size_t chunk=1;chunk<=64;chunk++) {
        auto reply=send(request,chunk);
        assert(reply.find(secret)==std::string::npos);
        assert(reply.find("secretpass")==std::string::npos);
        assert(reply.find("\"ok\":true")!=std::string::npos);
        assert(saved_ssid==" Café " && saved_password=="secretpass");
    }
    auto info=send("web {\"id\":\"b\",\"op\":\"info\"}\r",1);
    assert(info.find("@NUCULA ")!=std::string::npos);
    assert(info.find("\"id\":\"b\"")!=std::string::npos);
    assert(info.find("\"protocol\":1")!=std::string::npos);
    assert(info.find("secretpass")==std::string::npos);
    for (const auto &bad : {"00", "0d", "0a", "zz", "1"}) {
        auto reply=send(std::string("web {\"id\":\"c\",\"op\":\"wifi.set\",\"ssid_hex\":\"")+bad+"\",\"password_hex\":\"\"}\r");
        assert(reply.find("\"ok\":false")!=std::string::npos);
    }
    assert(send("web not-json\r").find("invalid_request")!=std::string::npos);
    assert(send("help\r").find("Available commands")!=std::string::npos);
    auto reset=send("web {\"id\":\"d\",\"op\":\"reboot\"}\r");
    assert(rebooted && reset.find("\"ok\":true")!=std::string::npos);
    web_setup_register(false);
    assert(send(request).find("ESP_ERR_INVALID_STATE")!=std::string::npos);
    std::cout << "Firmware console/protocol checks passed: 64 packet sizes, private echo, UTF-8, invalid fields, storage failure and reboot.\n";
}
'''

with tempfile.TemporaryDirectory(prefix="nucula-console-test-") as temp:
    root = Path(temp)
    for name, content in headers.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    (root / "test.cpp").write_text(harness)
    cjson = args.idf.resolve() / "components/json/cJSON"
    subprocess.run(["cc", "-c", str(cjson / "cJSON.c"), "-o", str(root / "cjson.o")], check=True)
    subprocess.run(["c++", "-std=c++17", "-I" + str(root), "-I" + str(args.source.resolve() / "main"), "-I" + str(cjson),
        str(root / "test.cpp"), str(args.source.resolve() / "main/console.cpp"), str(args.source.resolve() / "main/web_setup.cpp"),
        str(root / "cjson.o"), "-o", str(root / "test")], check=True)
    subprocess.run([str(root / "test")], check=True)
