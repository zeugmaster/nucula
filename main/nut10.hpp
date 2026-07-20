#pragma once

#include "cashu.hpp"
#include <string>

namespace cashu {

// Parse a Proof.secret. Returns true and fills `out` if the string is a
// well-formed NUT-10 array. Returns false for legacy raw-hex secrets or
// malformed input -- callers can use that as the "is this a structured
// secret?" probe.
bool parse_nut10_secret(const std::string& s, NUT10Secret& out);

} // namespace cashu

