#ifndef NUCULA_DISPLAY_H
#define NUCULA_DISPLAY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LCD_W 320
#define LCD_H 172

#define COLOR_BLACK  0x0000
#define COLOR_WHITE  0xFFFF
#define COLOR_GREEN  0x07E0
#define COLOR_CYAN   0x07FF
#define COLOR_AMBER  0xFDA0
#define COLOR_DGRAY  0x2104
#define COLOR_LGRAY  0x8410

void display_init(void);
void display_clear(uint16_t color);
void display_fill_rect(int x, int y, int w, int h, uint16_t color);
void display_text(int x, int y, const char *text, uint16_t fg, uint16_t bg, int scale);
int  display_text_width(const char *text, int scale);

#ifdef __cplusplus
}
#endif

#endif
