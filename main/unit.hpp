#pragma once

#include <string>
#include <cstdint>
#include <cstddef>

namespace cashu {

// NUT-01: units are an open set of lowercase strings — there is no closed
// enum and no metadata endpoint. This module holds display-only conventions
// (ISO-4217 minor-unit decimals for units we expect to see); everything else
// treats a unit as an opaque token.

// ASCII-lowercased copy, for comparison and serialization.
std::string normalize_unit(const std::string& unit);

// Minor-unit decimals for known units ("usd" -> 2); 0 for anything unknown
// (raw integer display). Display-only: amounts on the wire are always
// integer minor units.
int unit_decimals(const char* unit);

// Float-free rendering of a minor-unit amount:
//   format_amount(buf, n, 1234, "usd") -> "12.34 usd"
//   format_amount(buf, n, 21, "sat")   -> "21 sat"
// Returns snprintf-style count; always NUL-terminates when buflen > 0.
int format_amount(char* buf, size_t buflen, int64_t amount, const char* unit);

// Number only, no unit suffix (big balance line on the display).
int format_amount_value(char* buf, size_t buflen, int64_t amount, const char* unit);

// True iff s is non-empty and contains only [a-z0-9_-] — the NUT-04/05
// method charset. Must pass before a unit or method name from console input
// is interpolated into a mint URL or request body.
bool unit_token_valid(const char* s);

// Formatter/validator self-test, logged at info level like the other suites.
bool unit_run_tests();

} // namespace cashu
