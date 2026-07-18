#include "unit.hpp"

#include <cstdio>
#include <cstring>
#include <esp_log.h>

#define TAG "unit"

namespace cashu {

std::string normalize_unit(const std::string& unit)
{
    std::string out = unit;
    for (auto& c : out)
        if (c >= 'A' && c <= 'Z')
            c += 'a' - 'A';
    return out;
}

// Display metadata only. The protocol has no decimals field; ISO-4217 minor
// units are implied by the unit string (NUT-01). Units missing here render
// as raw integers, which is always a faithful (if unpretty) display.
struct UnitMeta {
    const char* name;
    int decimals;
};

static const UnitMeta k_units[] = {
    {"sat", 0}, {"msat", 0}, {"btc", 8},
    {"usd", 2}, {"eur", 2}, {"gbp", 2}, {"chf", 2}, {"jpy", 0},
};

int unit_decimals(const char* unit)
{
    if (!unit)
        return 0;
    for (const auto& m : k_units)
        if (strcmp(m.name, unit) == 0)
            return m.decimals;
    return 0;
}

int format_amount_value(char* buf, size_t buflen, int64_t amount, const char* unit)
{
    if (!buf || buflen == 0)
        return 0;
    const int d = unit_decimals(unit);
    if (d == 0)
        return snprintf(buf, buflen, "%lld", (long long)amount);

    int64_t scale = 1;
    for (int i = 0; i < d; i++)
        scale *= 10;
    // Magnitude as unsigned so INT64_MIN doesn't overflow on negation.
    const unsigned long long mag = amount < 0
        ? 0ULL - (unsigned long long)amount
        : (unsigned long long)amount;
    return snprintf(buf, buflen, "%s%llu.%0*llu",
                    amount < 0 ? "-" : "",
                    mag / (unsigned long long)scale,
                    d, mag % (unsigned long long)scale);
}

int format_amount(char* buf, size_t buflen, int64_t amount, const char* unit)
{
    if (!buf || buflen == 0)
        return 0;
    char val[32];
    format_amount_value(val, sizeof(val), amount, unit);
    return snprintf(buf, buflen, "%s %s", val,
                    (unit && unit[0]) ? unit : "?");
}

bool unit_token_valid(const char* s)
{
    if (!s || !s[0])
        return false;
    for (; *s; s++) {
        const char c = *s;
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '-'))
            return false;
    }
    return true;
}

bool unit_run_tests()
{
    bool ok = true;
    auto check = [&](const char* name, const char* got, const char* want) {
        if (strcmp(got, want) != 0) {
            ESP_LOGE(TAG, "%s FAIL: got=\"%s\" want=\"%s\"", name, got, want);
            ok = false;
        } else {
            ESP_LOGI(TAG, "%s ok (\"%s\")", name, got);
        }
    };

    char buf[48];
    format_amount(buf, sizeof(buf), 21, "sat");
    check("fmt sat", buf, "21 sat");
    format_amount(buf, sizeof(buf), 1234, "usd");
    check("fmt usd cents", buf, "12.34 usd");
    format_amount(buf, sizeof(buf), 5, "usd");
    check("fmt usd zero-pad", buf, "0.05 usd");
    format_amount(buf, sizeof(buf), 100, "jpy");
    check("fmt jpy whole", buf, "100 jpy");
    format_amount(buf, sizeof(buf), 123456789, "btc");
    check("fmt btc 8dp", buf, "1.23456789 btc");
    format_amount(buf, sizeof(buf), 42, "widget-42");
    check("fmt custom raw", buf, "42 widget-42");
    format_amount(buf, sizeof(buf), -250, "eur");
    check("fmt negative", buf, "-2.50 eur");
    format_amount(buf, sizeof(buf), INT64_MAX, "sat");
    check("fmt int64 max", buf, "9223372036854775807 sat");
    format_amount(buf, sizeof(buf), 7, nullptr);
    check("fmt null unit", buf, "7 ?");
    check("normalize", normalize_unit("USD").c_str(), "usd");

    if (!unit_token_valid("usd") || !unit_token_valid("credit-2026_q3") ||
        unit_token_valid("") || unit_token_valid(nullptr) ||
        unit_token_valid("USD") || unit_token_valid("a b") ||
        unit_token_valid("a/b")) {
        ESP_LOGE(TAG, "unit_token_valid FAIL");
        ok = false;
    } else {
        ESP_LOGI(TAG, "unit_token_valid ok");
    }
    return ok;
}

} // namespace cashu
