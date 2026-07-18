#pragma once

// Screen composition on top of the display primitives (display.h) plus the
// keypad-driven payment UI. Safe to call with no display attached — the
// display layer no-ops then.

// Home screen: balance, mint list, wifi/pending status.
void display_refresh();

// Full-screen NFC status (line1 large, line2 small).
void display_nfc_status(const char *line1, const char *line2);

// Keypad payment state machine (amount entry -> NFC window). Run as a task.
void keypad_ui_task(void *arg);
