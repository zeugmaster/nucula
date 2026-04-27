#ifndef CASHU_NUT10_HPP
#define CASHU_NUT10_HPP

#include "cashu.hpp"
#include <string>

namespace cashu {

// Serialize a NUT-10 structured secret to its JSON-array form:
//   ["<kind>", {"nonce":"<str>","data":"<str>","tags":[["k","v"...], ...]}]
// Tags array is omitted when empty (the spec allows either form).
std::string serialize_nut10_secret(const NUT10Secret& s);

// Parse a Proof.secret. Returns true and fills `out` if the string is a
// well-formed NUT-10 array. Returns false for legacy raw-hex secrets or
// malformed input -- callers can use that as the "is this a structured
// secret?" probe.
bool parse_nut10_secret(const std::string& s, NUT10Secret& out);

} // namespace cashu

#endif
