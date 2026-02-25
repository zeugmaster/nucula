#ifndef NUCULA_DISPLAY_H
#define NUCULA_DISPLAY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LCD_W 128
#define LCD_H 64

void display_init(void);
void display_clear(void);
void display_update(void);
void display_text(int x, int y, const char *text, int scale);
void display_text_inv(int x, int y, const char *text, int scale);
int  display_text_width(const char *text, int scale);
void display_hline(int x, int y, int w);
void display_pixel(int x, int y, bool on);

#ifdef __cplusplus
}
#endif

#endif
