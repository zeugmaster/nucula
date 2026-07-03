#ifndef KEYSET_HPP
#define KEYSET_HPP

#include <string>
#include <vector>
#include "cashu.hpp"
#include "cashu_suite.h"

// NUT-02 keyset versioning + ID derivation/verification, and the per-version
// crypto-suite selection. This is the single place that knows how a keyset ID
// is computed and which signature scheme a keyset version uses. Adding a new
// version (e.g. v3/BLS) means: a new derive_keyset_id_vN, a registry row in
// keyset_profile()/suite_for_id(), and a new cashu_suite_t — nothing else.

namespace cashu {

// NUT-02 keyset ID version (the first byte of the hex ID).
enum class KeysetVersion {
    unknown = -1,
    v1 = 0x00,   // deprecated: "00" + 14 hex of sha256(sorted pubkeys); 8 bytes / 16 hex
    v2 = 0x01,   // current:    "01" + sha256(amt:pk,...|unit|fee|expiry); 33 bytes / 66 hex
    v3 = 0x02,   // scaffold:   BLS12-381 (crypto_bls.c); id codec not yet implemented
};

// Per-version policy. Independent of the crypto suite, which v1 and v2 share.
struct KeysetProfile {
    KeysetVersion version;
    bool can_mint;   // may the wallet generate NEW outputs against this version
    bool has_dleq;   // NUT-12 DLEQ applies
};

// Parse the version from a hex keyset ID, validating the expected hex length
// for that version. Returns unknown for malformed / unrecognised IDs.
KeysetVersion keyset_version(const std::string &id);

// Look up the policy for a version.
KeysetProfile keyset_profile(KeysetVersion v);

// Select the crypto suite for a keyset ID. v1/v2 -> &cashu_suite_secp256k1.
// Returns nullptr for unknown/unsupported versions.
const cashu_suite_t *suite_for_id(const std::string &id);

// Re-derive the keyset ID from a keyset's keys (+ unit/fee/expiry for v2).
// Returns the lowercase hex ID, or "" on error / unsupported version.
std::string derive_keyset_id(const Keyset &ks);

// True iff the keyset's claimed ID matches the ID re-derived from its keys
// (case-insensitive). Closes the NUT-02 gap where the mint's claimed ID was
// trusted verbatim.
bool verify_keyset_id(const Keyset &ks);

// The 8-byte (16-hex) short form of a keyset ID, as used in cashuB (V4) tokens.
std::string keyset_id_short(const std::string &id);

// Resolve a (possibly short-form) keyset ID carried in a received token to a
// loaded keyset. Matches exact, else a unique 8-byte (or any) prefix; sets
// *ambiguous and returns nullptr if more than one keyset matches the prefix.
const Keyset *resolve_keyset(const std::vector<Keyset> &keysets,
                             const std::string &token_id,
                             bool *ambiguous = nullptr);

// On-device happy-path self-test of the v1/v2 derivation codecs against the
// spec's worked examples. Returns true if all vectors pass. Call at startup.
bool keyset_run_tests();

} // namespace cashu

#endif // KEYSET_HPP
