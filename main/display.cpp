// display.cpp — stub implementation pending ST7789 SPI rewrite
// The old SSD1306 I2C driver conflicts with the new i2c_master driver used
// by the PN7160 NFC component. All functions are no-ops until the display
// is rewritten for the Waveshare 1.47" ST7789 panel.
#include "display.h"
#include <esp_log.h>

#define TAG "display"

void display_init(void) { ESP_LOGI(TAG, "display stub (ST7789 not yet implemented)"); }
void display_clear(void) {}
void display_update(void) {}
void display_text(int, int, const char *, int) {}
void display_text_inv(int, int, const char *, int) {}
int  display_text_width(const char *, int) { return 0; }
void display_hline(int, int, int) {}
void display_pixel(int, int, bool) {}
