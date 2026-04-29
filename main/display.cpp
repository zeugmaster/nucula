#include "display.h"

#include <cstring>
#include <esp_log.h>
#include <driver/gpio.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#define TAG "display"

// SSD1309 I2C address (SA0 low = 0x3C, SA0 high = 0x3D)
#define SSD1309_ADDR  0x3C
#define SSD1309_CMD   0x00   // control byte: following bytes are commands
#define SSD1309_DATA  0x40   // control byte: following bytes are GDDRAM data

// Optional hardware reset pin (D3 on XIAO C3 = GPIO 5). Set to -1 if not wired.
#define PIN_RST  GPIO_NUM_5

static i2c_master_dev_handle_t s_dev = nullptr;

// Page-format framebuffer: 8 pages × 128 columns = 1024 bytes.
// Each byte holds 8 vertical pixels; bit 0 = topmost in the page.
static uint8_t s_fb[LCD_H / 8 * LCD_W];

// Transmit buffer: one control byte + framebuffer (static to avoid stack use)
static uint8_t s_tx[1 + sizeof(s_fb)];

// -------------------------------------------------------------------------
// 5×7 bitmap font (ASCII 32-126, 5 bytes per char, column-major, LSB=top)
// -------------------------------------------------------------------------
static const uint8_t font5x7[][5] = {
    {0x00,0x00,0x00,0x00,0x00}, // 32 space
    {0x00,0x00,0x5F,0x00,0x00}, // 33 !
    {0x00,0x07,0x00,0x07,0x00}, // 34 "
    {0x14,0x7F,0x14,0x7F,0x14}, // 35 #
    {0x24,0x2A,0x7F,0x2A,0x12}, // 36 $
    {0x23,0x13,0x08,0x64,0x62}, // 37 %
    {0x36,0x49,0x55,0x22,0x50}, // 38 &
    {0x00,0x05,0x03,0x00,0x00}, // 39 '
    {0x00,0x1C,0x22,0x41,0x00}, // 40 (
    {0x00,0x41,0x22,0x1C,0x00}, // 41 )
    {0x08,0x2A,0x1C,0x2A,0x08}, // 42 *
    {0x08,0x08,0x3E,0x08,0x08}, // 43 +
    {0x00,0x50,0x30,0x00,0x00}, // 44 ,
    {0x08,0x08,0x08,0x08,0x08}, // 45 -
    {0x00,0x60,0x60,0x00,0x00}, // 46 .
    {0x20,0x10,0x08,0x04,0x02}, // 47 /
    {0x3E,0x51,0x49,0x45,0x3E}, // 48 0
    {0x00,0x42,0x7F,0x40,0x00}, // 49 1
    {0x42,0x61,0x51,0x49,0x46}, // 50 2
    {0x21,0x41,0x45,0x4B,0x31}, // 51 3
    {0x18,0x14,0x12,0x7F,0x10}, // 52 4
    {0x27,0x45,0x45,0x45,0x39}, // 53 5
    {0x3C,0x4A,0x49,0x49,0x30}, // 54 6
    {0x01,0x71,0x09,0x05,0x03}, // 55 7
    {0x36,0x49,0x49,0x49,0x36}, // 56 8
    {0x06,0x49,0x49,0x29,0x1E}, // 57 9
    {0x00,0x36,0x36,0x00,0x00}, // 58 :
    {0x00,0x56,0x36,0x00,0x00}, // 59 ;
    {0x00,0x08,0x14,0x22,0x41}, // 60 <
    {0x14,0x14,0x14,0x14,0x14}, // 61 =
    {0x41,0x22,0x14,0x08,0x00}, // 62 >
    {0x02,0x01,0x51,0x09,0x06}, // 63 ?
    {0x32,0x49,0x79,0x41,0x3E}, // 64 @
    {0x7E,0x11,0x11,0x11,0x7E}, // 65 A
    {0x7F,0x49,0x49,0x49,0x36}, // 66 B
    {0x3E,0x41,0x41,0x41,0x22}, // 67 C
    {0x7F,0x41,0x41,0x22,0x1C}, // 68 D
    {0x7F,0x49,0x49,0x49,0x41}, // 69 E
    {0x7F,0x09,0x09,0x01,0x01}, // 70 F
    {0x3E,0x41,0x41,0x51,0x32}, // 71 G
    {0x7F,0x08,0x08,0x08,0x7F}, // 72 H
    {0x00,0x41,0x7F,0x41,0x00}, // 73 I
    {0x20,0x40,0x41,0x3F,0x01}, // 74 J
    {0x7F,0x08,0x14,0x22,0x41}, // 75 K
    {0x7F,0x40,0x40,0x40,0x40}, // 76 L
    {0x7F,0x02,0x04,0x02,0x7F}, // 77 M
    {0x7F,0x04,0x08,0x10,0x7F}, // 78 N
    {0x3E,0x41,0x41,0x41,0x3E}, // 79 O
    {0x7F,0x09,0x09,0x09,0x06}, // 80 P
    {0x3E,0x41,0x51,0x21,0x5E}, // 81 Q
    {0x7F,0x09,0x19,0x29,0x46}, // 82 R
    {0x46,0x49,0x49,0x49,0x31}, // 83 S
    {0x01,0x01,0x7F,0x01,0x01}, // 84 T
    {0x3F,0x40,0x40,0x40,0x3F}, // 85 U
    {0x1F,0x20,0x40,0x20,0x1F}, // 86 V
    {0x7F,0x20,0x18,0x20,0x7F}, // 87 W
    {0x63,0x14,0x08,0x14,0x63}, // 88 X
    {0x03,0x04,0x78,0x04,0x03}, // 89 Y
    {0x61,0x51,0x49,0x45,0x43}, // 90 Z
    {0x00,0x00,0x7F,0x41,0x41}, // 91 [
    {0x02,0x04,0x08,0x10,0x20}, // 92 backslash
    {0x41,0x41,0x7F,0x00,0x00}, // 93 ]
    {0x04,0x02,0x01,0x02,0x04}, // 94 ^
    {0x40,0x40,0x40,0x40,0x40}, // 95 _
    {0x00,0x01,0x02,0x04,0x00}, // 96 `
    {0x20,0x54,0x54,0x54,0x78}, // 97 a
    {0x7F,0x48,0x44,0x44,0x38}, // 98 b
    {0x38,0x44,0x44,0x44,0x20}, // 99 c
    {0x38,0x44,0x44,0x48,0x7F}, // 100 d
    {0x38,0x54,0x54,0x54,0x18}, // 101 e
    {0x08,0x7E,0x09,0x01,0x02}, // 102 f
    {0x08,0x14,0x54,0x54,0x3C}, // 103 g
    {0x7F,0x08,0x04,0x04,0x78}, // 104 h
    {0x00,0x44,0x7D,0x40,0x00}, // 105 i
    {0x20,0x40,0x44,0x3D,0x00}, // 106 j
    {0x00,0x7F,0x10,0x28,0x44}, // 107 k
    {0x00,0x41,0x7F,0x40,0x00}, // 108 l
    {0x7C,0x04,0x18,0x04,0x78}, // 109 m
    {0x7C,0x08,0x04,0x04,0x78}, // 110 n
    {0x38,0x44,0x44,0x44,0x38}, // 111 o
    {0x7C,0x14,0x14,0x14,0x08}, // 112 p
    {0x08,0x14,0x14,0x18,0x7C}, // 113 q
    {0x7C,0x08,0x04,0x04,0x08}, // 114 r
    {0x48,0x54,0x54,0x54,0x20}, // 115 s
    {0x04,0x3F,0x44,0x40,0x20}, // 116 t
    {0x3C,0x40,0x40,0x20,0x7C}, // 117 u
    {0x1C,0x20,0x40,0x20,0x1C}, // 118 v
    {0x3C,0x40,0x30,0x40,0x3C}, // 119 w
    {0x44,0x28,0x10,0x28,0x44}, // 120 x
    {0x0C,0x50,0x50,0x50,0x3C}, // 121 y
    {0x44,0x64,0x54,0x4C,0x44}, // 122 z
    {0x00,0x08,0x36,0x41,0x00}, // 123 {
    {0x00,0x00,0x7F,0x00,0x00}, // 124 |
    {0x00,0x41,0x36,0x08,0x00}, // 125 }
    {0x08,0x04,0x08,0x10,0x08}, // 126 ~
};

#define FONT_W       5
#define FONT_H       8
#define FONT_ADVANCE 6

// -------------------------------------------------------------------------
// SSD1309 I2C helpers
// -------------------------------------------------------------------------

static void ssd1309_send_cmds(const uint8_t *cmds, size_t len)
{
    // Prepend command control byte
    uint8_t buf[32];
    buf[0] = SSD1309_CMD;
    size_t chunk;
    while (len > 0) {
        chunk = (len > sizeof(buf) - 1) ? sizeof(buf) - 1 : len;
        memcpy(buf + 1, cmds, chunk);
        i2c_master_transmit(s_dev, buf, chunk + 1, 100);
        cmds += chunk;
        len  -= chunk;
    }
}

// -------------------------------------------------------------------------
// Init
// -------------------------------------------------------------------------

void display_init(i2c_master_bus_handle_t bus)
{
    if (!bus) {
        ESP_LOGW(TAG, "no I2C bus, display disabled");
        return;
    }

    // Optional hardware reset
    if ((int)PIN_RST >= 0) {
        gpio_reset_pin(PIN_RST);
        gpio_set_direction(PIN_RST, GPIO_MODE_OUTPUT);
        gpio_set_level(PIN_RST, 0);
        vTaskDelay(pdMS_TO_TICKS(10));
        gpio_set_level(PIN_RST, 1);
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    // Add SSD1309 as device on the shared I2C bus
    i2c_device_config_t dev_cfg = {};
    dev_cfg.dev_addr_length = I2C_ADDR_BIT_LEN_7;
    dev_cfg.device_address  = SSD1309_ADDR;
    dev_cfg.scl_speed_hz    = 400000;

    esp_err_t err = i2c_master_bus_add_device(bus, &dev_cfg, &s_dev);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "SSD1309 add failed: %s", esp_err_to_name(err));
        s_dev = nullptr;
        return;
    }

    // SSD1309 initialisation (compatible with SSD1306 modules too)
    static const uint8_t init[] = {
        0xAE,              // display off
        0xD5, 0x80,        // clock divide ratio
        0xA8, 0x3F,        // multiplex 64
        0xD3, 0x00,        // display offset 0
        0x40,              // start line 0
        0x8D, 0x14,        // charge pump enable
        0x20, 0x00,        // horizontal addressing mode
        0xA1,              // segment remap (mirror X)
        0xC8,              // COM scan reversed (mirror Y)
        0xDA, 0x12,        // COM pins: alternative, no LR remap
        0x81, 0xCF,        // contrast
        0xD9, 0xF1,        // pre-charge period
        0xDB, 0x40,        // VCOMH deselect level
        0xA4,              // output follows RAM
        0xA6,              // normal display (not inverted)
        0xAF,              // display on
    };
    ssd1309_send_cmds(init, sizeof(init));

    memset(s_fb, 0, sizeof(s_fb));
    display_update();

    ESP_LOGI(TAG, "SSD1309 initialized (%dx%d I2C 0x%02X)", LCD_W, LCD_H, SSD1309_ADDR);
}

// -------------------------------------------------------------------------
// Framebuffer → display transfer
// -------------------------------------------------------------------------

void display_update(void)
{
    if (!s_dev) return;

    // Set draw window to full screen
    static const uint8_t window[] = {
        0x21, 0x00, 0x7F,   // column range 0–127
        0x22, 0x00, 0x07,   // page range 0–7
    };
    ssd1309_send_cmds(window, sizeof(window));

    // Push framebuffer
    s_tx[0] = SSD1309_DATA;
    memcpy(s_tx + 1, s_fb, sizeof(s_fb));
    i2c_master_transmit(s_dev, s_tx, sizeof(s_tx), 200);
}

void display_clear(void)
{
    memset(s_fb, 0, sizeof(s_fb));
}

// -------------------------------------------------------------------------
// Drawing primitives
// -------------------------------------------------------------------------

void display_pixel(int x, int y, bool on)
{
    if (x < 0 || x >= LCD_W || y < 0 || y >= LCD_H) return;
    if (on)
        s_fb[(y >> 3) * LCD_W + x] |=  (1 << (y & 7));
    else
        s_fb[(y >> 3) * LCD_W + x] &= ~(1 << (y & 7));
}

void display_fill_rect(int x, int y, int w, int h, uint16_t color)
{
    int x2 = x + w, y2 = y + h;
    if (x < 0) x = 0;
    if (y < 0) y = 0;
    if (x2 > LCD_W) x2 = LCD_W;
    if (y2 > LCD_H) y2 = LCD_H;
    if (x2 <= x || y2 <= y) return;

    bool on = (color != 0);
    for (int row = y; row < y2; row++) {
        uint8_t mask = 1 << (row & 7);
        int page_off = (row >> 3) * LCD_W;
        if (on) {
            for (int col = x; col < x2; col++)
                s_fb[page_off + col] |= mask;
        } else {
            uint8_t nmask = ~mask;
            for (int col = x; col < x2; col++)
                s_fb[page_off + col] &= nmask;
        }
    }
}

void display_hline(int x, int y, int w)
{
    display_fill_rect(x, y, w, 1, COLOR_WHITE);
}

// -------------------------------------------------------------------------
// Text rendering
// -------------------------------------------------------------------------

void display_text_color(int x, int y, const char *text,
                        uint16_t fg, uint16_t bg, int scale)
{
    if (!text || !*text) return;
    bool fg_on = (fg != 0);
    bool bg_on = (bg != 0);

    for (; *text; text++, x += FONT_ADVANCE * scale) {
        if (x + FONT_ADVANCE * scale > LCD_W) break;

        char ch = *text;
        if (ch < 32 || ch > 126) ch = '?';
        const uint8_t *glyph = font5x7[ch - 32];

        for (int row = 0; row < FONT_H; row++) {
            int py = y + row * scale;
            if (py >= LCD_H) break;
            for (int col = 0; col < FONT_ADVANCE; col++) {
                bool on = (col < FONT_W) && (glyph[col] & (1 << row));
                bool pixel = on ? fg_on : bg_on;
                int px = x + col * scale;
                for (int sy = 0; sy < scale && py + sy < LCD_H; sy++)
                    for (int sx = 0; sx < scale && px + sx < LCD_W; sx++)
                        display_pixel(px + sx, py + sy, pixel);
            }
        }
    }
}

void display_text(int x, int y, const char *text, int scale)
{
    display_text_color(x, y, text, COLOR_WHITE, COLOR_BLACK, scale);
}

void display_text_inv(int x, int y, const char *text, int scale)
{
    display_text_color(x, y, text, COLOR_BLACK, COLOR_WHITE, scale);
}

int display_text_width(const char *text, int scale)
{
    return (int)strlen(text) * FONT_ADVANCE * scale;
}
