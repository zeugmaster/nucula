#include "display.h"

#include <cstring>
#include <esp_log.h>
#include <esp_lcd_panel_io.h>
#include <esp_lcd_panel_ops.h>
#include <esp_lcd_panel_vendor.h>
#include <driver/spi_master.h>
#include <driver/gpio.h>
#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#define TAG "display"

#define PIN_MOSI  GPIO_NUM_6
#define PIN_SCLK  GPIO_NUM_7
#define PIN_CS    GPIO_NUM_14
#define PIN_DC    GPIO_NUM_15
#define PIN_RST   GPIO_NUM_21
#define PIN_BL    GPIO_NUM_22
#define LCD_SPI   SPI2_HOST

static esp_lcd_panel_handle_t s_panel   = nullptr;
static SemaphoreHandle_t      s_dma_sem = nullptr;

// Framebuffer: allocated once at init in DMA-capable SRAM.
// All drawing goes here; display_update() pushes it to the panel in one shot,
// eliminating the visible top-to-bottom redraw artifact.
static uint16_t *s_fb = nullptr;

// -------------------------------------------------------------------------
// DMA helpers (used only for the framebuffer push in display_update)
// -------------------------------------------------------------------------

static bool IRAM_ATTR lcd_trans_done(esp_lcd_panel_io_handle_t io,
                                      esp_lcd_panel_io_event_data_t *edata,
                                      void *ctx)
{
    BaseType_t hp = pdFALSE;
    xSemaphoreGiveFromISR(s_dma_sem, &hp);
    return hp == pdTRUE;
}

// Push one rectangle from the framebuffer synchronously.
static void fb_push_rect(int x, int y, int x2, int y2)
{
    xSemaphoreTake(s_dma_sem, portMAX_DELAY);          // wait for prev transfer
    esp_lcd_panel_draw_bitmap(s_panel, x, y, x2, y2,
                              s_fb + y * LCD_W + x);   // DMA directly from framebuffer
    // ISR will give sem when done; the NEXT call or the final wait will catch it
}

// -------------------------------------------------------------------------
// 5x7 bitmap font (ASCII 32-126, 5 bytes per char, column-major, LSB=top)
// Standard embedded font, public domain.
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
// LCD panel init
// -------------------------------------------------------------------------

void display_init(void)
{
    s_dma_sem = xSemaphoreCreateBinary();
    xSemaphoreGive(s_dma_sem); // start idle

    // Allocate framebuffer early (heap is emptiest at boot).
    // DMA-capable so display_update() can push it directly without copying.
    s_fb = (uint16_t *)heap_caps_malloc(LCD_W * LCD_H * sizeof(uint16_t),
                                         MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
    if (s_fb) {
        memset(s_fb, 0, LCD_W * LCD_H * sizeof(uint16_t));
        ESP_LOGI(TAG, "framebuffer allocated (%d bytes)", LCD_W * LCD_H * 2);
    } else {
        ESP_LOGW(TAG, "framebuffer OOM — display disabled");
        return;
    }

    // Force-reset backlight pin to clear any latched hold from previous firmware
    gpio_reset_pin(PIN_BL);
    gpio_set_direction(PIN_BL, GPIO_MODE_OUTPUT);
    gpio_set_level(PIN_BL, 1);

    spi_bus_config_t bus_cfg = {};
    bus_cfg.mosi_io_num     = PIN_MOSI;
    bus_cfg.miso_io_num     = -1;
    bus_cfg.sclk_io_num     = PIN_SCLK;
    bus_cfg.quadwp_io_num   = -1;
    bus_cfg.quadhd_io_num   = -1;
    // Large enough for the full framebuffer in a single DMA transaction
    bus_cfg.max_transfer_sz = LCD_W * LCD_H * sizeof(uint16_t);

    ESP_ERROR_CHECK(spi_bus_initialize(LCD_SPI, &bus_cfg, SPI_DMA_CH_AUTO));

    esp_lcd_panel_io_spi_config_t io_cfg = {};
    io_cfg.dc_gpio_num         = PIN_DC;
    io_cfg.cs_gpio_num         = PIN_CS;
    io_cfg.pclk_hz             = 40 * 1000 * 1000;
    io_cfg.lcd_cmd_bits        = 8;
    io_cfg.lcd_param_bits      = 8;
    io_cfg.spi_mode            = 0;
    io_cfg.trans_queue_depth   = 1;
    io_cfg.on_color_trans_done = lcd_trans_done;
    io_cfg.user_ctx            = nullptr;

    esp_lcd_panel_io_handle_t io_handle;
    ESP_ERROR_CHECK(esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)LCD_SPI,
                                              &io_cfg, &io_handle));

    esp_lcd_panel_dev_config_t panel_cfg = {};
    panel_cfg.reset_gpio_num  = PIN_RST;
    panel_cfg.rgb_ele_order   = LCD_RGB_ELEMENT_ORDER_BGR;
    panel_cfg.bits_per_pixel  = 16;

    ESP_ERROR_CHECK(esp_lcd_new_panel_st7789(io_handle, &panel_cfg, &s_panel));
    ESP_ERROR_CHECK(esp_lcd_panel_reset(s_panel));
    ESP_ERROR_CHECK(esp_lcd_panel_init(s_panel));
    ESP_ERROR_CHECK(esp_lcd_panel_invert_color(s_panel, true));
    ESP_ERROR_CHECK(esp_lcd_panel_swap_xy(s_panel, true));
    ESP_ERROR_CHECK(esp_lcd_panel_mirror(s_panel, true, false));
    ESP_ERROR_CHECK(esp_lcd_panel_set_gap(s_panel, 0, 34));
    ESP_ERROR_CHECK(esp_lcd_panel_disp_on_off(s_panel, true));

    gpio_set_level(PIN_BL, 1);
    ESP_LOGI(TAG, "display initialized (%dx%d ST7789)", LCD_W, LCD_H);
}

// -------------------------------------------------------------------------
// Framebuffer drawing primitives (pure CPU writes to RAM — no DMA)
// -------------------------------------------------------------------------

// Swap bytes for RGB565 little-endian over SPI
static inline uint16_t swap16(uint16_t c) { return (c >> 8) | (c << 8); }

void display_fill_rect(int x, int y, int w, int h, uint16_t color)
{
    if (!s_fb) return;
    int x2 = x + w, y2 = y + h;
    if (x < 0) x = 0;
    if (y < 0) y = 0;
    if (x2 > LCD_W) x2 = LCD_W;
    if (y2 > LCD_H) y2 = LCD_H;
    if (x2 <= x || y2 <= y) return;

    uint16_t c = swap16(color);
    for (int row = y; row < y2; row++) {
        uint16_t *p = s_fb + row * LCD_W + x;
        for (int col = 0; col < x2 - x; col++)
            p[col] = c;
    }
}

void display_clear(void)
{
    if (!s_fb) return;
    memset(s_fb, 0, LCD_W * LCD_H * sizeof(uint16_t)); // COLOR_BLACK = 0x0000
}

// Push the complete framebuffer to the panel in one DMA transaction.
// The screen is updated atomically — no visible sweep.
void display_update(void)
{
    if (!s_fb || !s_panel) return;

    // Full-frame push: one draw_bitmap call for the entire 320×172 buffer.
    // Semaphore starts idle (given). Take it to arm the transfer, ISR gives
    // it back when done, then we take again to confirm completion.
    xSemaphoreTake(s_dma_sem, portMAX_DELAY);
    esp_lcd_panel_draw_bitmap(s_panel, 0, 0, LCD_W, LCD_H, s_fb);
    xSemaphoreTake(s_dma_sem, portMAX_DELAY); // wait for transfer to finish
    xSemaphoreGive(s_dma_sem);                // restore idle
}

// -------------------------------------------------------------------------
// Text rendering (writes directly into the framebuffer)
// -------------------------------------------------------------------------

void display_text_color(int x, int y, const char *text, uint16_t fg, uint16_t bg, int scale)
{
    if (!s_fb || !text || !*text) return;

    uint16_t fg_sw = swap16(fg);
    uint16_t bg_sw = swap16(bg);

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
                uint16_t c = on ? fg_sw : bg_sw;
                int px = x + col * scale;
                for (int sy = 0; sy < scale && py + sy < LCD_H; sy++)
                    for (int sx = 0; sx < scale && px + sx < LCD_W; sx++)
                        s_fb[(py + sy) * LCD_W + (px + sx)] = c;
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

void display_hline(int x, int y, int w)
{
    display_fill_rect(x, y, w, 1, COLOR_WHITE);
}

void display_pixel(int x, int y, bool on)
{
    display_fill_rect(x, y, 1, 1, on ? COLOR_WHITE : COLOR_BLACK);
}
