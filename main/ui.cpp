#include "ui.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <esp_system.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <string>
#include <vector>

#include "display.h"
#include "keypad.h"
#include "nfc.hpp"
#include "unit.hpp"
#include "wallet_store.hpp"
#include "wifi.h"

// -------------------------------------------------------------------------
// Screens
// -------------------------------------------------------------------------

static void draw_title_bar(const char *right_label)
{
    display_fill_rect(0, 0, LCD_W, 9, COLOR_WHITE);
    display_text_color(1, 1, "nucula", COLOR_BLACK, COLOR_WHITE, 1);
    if (right_label && right_label[0]) {
        int rx = LCD_W - display_text_width(right_label, 1) - 1;
        display_text_color(rx, 1, right_label, COLOR_BLACK, COLOR_WHITE, 1);
    }
}

void display_nfc_status(const char *line1, const char *line2)
{
    display_clear();
    draw_title_bar("nfc");

    // line1 — large, centered (scale 2)
    if (line1 && line1[0]) {
        int x = (LCD_W - display_text_width(line1, 2)) / 2;
        if (x < 0) x = 0;
        display_text_color(x, 20, line1, COLOR_WHITE, COLOR_BLACK, 2);
    }

    // line2 — small, centered (scale 1)
    if (line2 && line2[0]) {
        int x = (LCD_W - display_text_width(line2, 1)) / 2;
        if (x < 0) x = 0;
        display_text_color(x, 40, line2, COLOR_WHITE, COLOR_BLACK, 1);
    }

    display_update();
}

void display_refresh()
{
    // Layout (64px total, 128px wide):
    //   y= 0.. 8  title bar (scale 1)
    //   y=10..25  default-unit balance (scale 2, centered)
    //   y=27..34  unit label (scale 1, centered)
    //   y=36      separator
    //   y=38..53  two lines: per-mint balances (single-unit device) or
    //             other-unit totals (multi-unit device)
    //   y=56..63  status: proof count + heap + unit overflow (scale 1)

    // Never hard-block the UI on a long wallet operation (a melt can hold
    // the store for up to two minutes): skip this frame instead — every
    // wallet op ends with a display_refresh, so a skipped frame self-heals.
    // Recursive mutex: callers already holding the guard pass immediately.
    if (!wallet_store_try_lock(100))
        return;

    display_clear();

    // ---- Title bar ----
    int total_pending = wallet_store_total_pending();
    const char *base = wifi_is_connected() ? "wifi" : "----";
    char wifi_buf[16];
    if (total_pending > 0) {
        unsigned p = (total_pending > 99) ? 99 : (unsigned)total_pending;
        snprintf(wifi_buf, sizeof(wifi_buf), "%s+%u", base, p);
    } else {
        snprintf(wifi_buf, sizeof(wifi_buf), "%s", base);
    }
    draw_title_bar(wifi_buf);

    // ---- Tally ----
    const std::string def_unit = cashu::Wallet::default_unit();
    long long def_balance = wallet_store_balance_for_unit(def_unit.c_str());
    int total_proofs = 0;
    for (int i = 0; i < MAX_MINTS; i++) {
        auto *w = wallet_store_get(i);
        if (w)
            total_proofs += (int)w->proofs().size();
    }
    // Units other than the default that any wallet holds ("?" excluded).
    std::vector<std::string> units;
    wallet_store_collect_units(units);
    std::vector<std::string> others;
    for (const auto &u : units)
        if (u != def_unit && u != "?")
            others.push_back(u);

    // ---- Balance in the default unit (scale 2, centered) ----
    char buf[40];
    cashu::format_amount_value(buf, sizeof(buf), def_balance, def_unit.c_str());
    int scale = 2;
    if (display_text_width(buf, scale) > LCD_W - 4) scale = 1;
    int bx = (LCD_W - display_text_width(buf, scale)) / 2;
    if (bx < 0) bx = 0;
    display_text(bx, 10, buf, scale);

    // ---- Unit label (scale 1, centered) ----
    int ux = (LCD_W - display_text_width(def_unit.c_str(), 1)) / 2;
    if (ux < 0) ux = 0;
    display_text(ux, 27, def_unit.c_str(), 1);

    // ---- Separator ----
    display_hline(0, 36, LCD_W);

    int y = 38;
    int shown = 0;
    if (others.empty()) {
        // ---- Single-unit device: per-mint balances (up to 2 lines) ----
        for (int i = 0; i < MAX_MINTS && shown < 2; i++) {
            auto *w = wallet_store_get(i);
            if (!w) continue;
            const char *url = w->mint_url().c_str();
            if (strncmp(url, "https://", 8) == 0) url += 8;
            else if (strncmp(url, "http://", 7) == 0) url += 7;

            char amount[16];
            cashu::format_amount_value(amount, sizeof(amount),
                                       w->balance_for_unit(def_unit),
                                       def_unit.c_str());
            int ax = LCD_W - display_text_width(amount, 1) - 1;

            int url_chars = (ax - 2) / 6;
            char line[32];
            snprintf(line, sizeof(line), "%.*s", url_chars, url);
            display_text(1, y, line, 1);
            display_text(ax, y, amount, 1);
            y += 8;
            shown++;
        }
    } else {
        // ---- Multi-unit device: other-unit totals (up to 2 lines) ----
        for (const auto &u : others) {
            if (shown >= 2) break;
            char amount[16];
            cashu::format_amount_value(amount, sizeof(amount),
                                       wallet_store_balance_for_unit(u.c_str()),
                                       u.c_str());
            int ax = LCD_W - display_text_width(amount, 1) - 1;
            display_text(1, y, u.c_str(), 1);
            display_text(ax, y, amount, 1);
            y += 8;
            shown++;
        }
    }

    // ---- Status bar (scale 1) ----
    int overflow = (int)others.size() - shown;
    if (overflow > 0)
        snprintf(buf, sizeof(buf), "%dp heap:%luk +%du", total_proofs,
                 (unsigned long)(esp_get_free_heap_size() / 1024), overflow);
    else
        snprintf(buf, sizeof(buf), "%dp heap:%luk", total_proofs,
                 (unsigned long)(esp_get_free_heap_size() / 1024));
    display_text(1, 56, buf, 1);

    wallet_store_unlock();
    display_update();
}

// -------------------------------------------------------------------------
// Keypad UI
// -------------------------------------------------------------------------

// Amount entry screen: digits are integer minor units of `unit` (typing
// 123 with usd shows 1.23), * / # hints at the bottom.
static void show_amount_entry(const char *digits, const char *unit)
{
    display_clear();
    draw_title_bar("amount");

    // Amount (scale 2, centered), rendered with the unit's decimals
    long long v = (digits && digits[0]) ? atoll(digits) : 0;
    char show[24];
    cashu::format_amount_value(show, sizeof(show), v, unit);
    int scale = 2;
    if (display_text_width(show, scale) > LCD_W - 4) scale = 1;
    int ax = (LCD_W - display_text_width(show, scale)) / 2;
    if (ax < 0) ax = 0;
    display_text(ax, 14, show, scale);

    // Unit label
    int ulx = (LCD_W - display_text_width(unit, 1)) / 2;
    if (ulx < 0) ulx = 0;
    display_text(ulx, 32, unit, 1);

    // Hints at bottom
    display_text(1, 56, "* cancel", 1);
    const char *confirm_hint = "# ok";
    display_text(LCD_W - display_text_width(confirm_hint, 1) - 1, 56,
                 confirm_hint, 1);

    display_update();
}

void keypad_ui_task(void *arg)
{
    (void)arg;

    enum class UiState { IDLE, ENTERING_AMOUNT, NFC_ACTIVE };
    UiState ui = UiState::IDLE;

    char amount_buf[10] = {};
    int  amount_len     = 0;
    int  nfc_amount     = 0;
    char unit_buf[32]   = "sat";   // snapshot when amount entry starts
    NfcState last_nfc   = NfcState::off;

    for (;;) {
        // 200ms timeout: keeps us responsive to key presses and NFC state changes
        char key = keypad_wait_event(200);

        switch (ui) {

        case UiState::IDLE:
            if (key >= '1' && key <= '9' && wallet_store_count() > 0) {
                // Snapshot the default unit for this whole entry/NFC round
                // so a concurrent `unit` command can't switch mid-flow.
                snprintf(unit_buf, sizeof(unit_buf), "%s",
                         cashu::Wallet::default_unit().c_str());
                amount_len = 0;
                amount_buf[0] = key;
                amount_buf[1] = '\0';
                amount_len = 1;
                ui = UiState::ENTERING_AMOUNT;
                show_amount_entry(amount_buf, unit_buf);
            }
            break;

        case UiState::ENTERING_AMOUNT:
            if (key >= '0' && key <= '9') {
                if (amount_len == 0 && key == '0') break; // no leading zeros
                if (amount_len < 8) {
                    amount_buf[amount_len++] = key;
                    amount_buf[amount_len]   = '\0';
                    show_amount_entry(amount_buf, unit_buf);
                }
            } else if (key == '*') {
                ui = UiState::IDLE;
                display_refresh();
            } else if (key == '#') {
                nfc_amount = atoi(amount_buf);
                if (nfc_amount <= 0) break;             // nothing entered yet
                if (nfc_state() == NfcState::off) break; // NFC unavailable
                if (!nfc_request_start(nfc_amount, unit_buf, nullptr)) break;
                ui = UiState::NFC_ACTIVE;
                last_nfc = NfcState::off;
                char amt_str[24];
                cashu::format_amount(amt_str, sizeof(amt_str), nfc_amount,
                                     unit_buf);
                display_nfc_status("waiting", amt_str);
            }
            break;

        case UiState::NFC_ACTIVE: {
            if (key == '*') {
                nfc_request_stop();
                ui = UiState::IDLE;
                display_refresh();
                break;
            }
            // Refresh display whenever NFC state changes
            NfcState cur = nfc_state();
            if (cur == last_nfc) break;
            last_nfc = cur;

            char amt_str[24];
            cashu::format_amount(amt_str, sizeof(amt_str), nfc_amount, unit_buf);
            switch (cur) {
            case NfcState::waiting:
                display_nfc_status("waiting", amt_str);   break;
            case NfcState::active:
                display_nfc_status("reading...", amt_str); break;
            case NfcState::received:
            case NfcState::redeeming:
                display_nfc_status("redeeming", amt_str);  break;
            case NfcState::success:
                display_nfc_status("success!", "");         break;
            case NfcState::error:
                display_nfc_status("error", "try again");   break;
            default:
                break;
            }

            // Terminal states: pause so the user sees the result, then return home
            if (cur == NfcState::success || cur == NfcState::error) {
                vTaskDelay(pdMS_TO_TICKS(2000));
                nfc_request_stop();
                ui = UiState::IDLE;
                last_nfc = NfcState::off;
                display_refresh();
            }
            break;
        }

        } // switch
    } // for
}
