#pragma once

#include <string>
#include <vector>
#include <map>
#include <optional>
#include <cstdint>

// NUT-12: when set, a BlindSignature returned by the mint without a DLEQ
// is rejected (instead of being accepted with only a warning). Default on.
#ifndef CASHU_REQUIRE_DLEQ_FROM_MINT
#define CASHU_REQUIRE_DLEQ_FROM_MINT 1
#endif

// NUT-02: when set, a keyset whose ID does not match the ID re-derived from
// its public keys (plus unit/fee/final_expiry for v2) is rejected at load
// time instead of being accepted with only a warning. Default on. During
// first bring-up against a new mint you may build with this set to 0 to log
// mismatches without rejecting, confirm the IDs match, then restore to 1.
#ifndef CASHU_REQUIRE_VALID_KEYSET_ID
#define CASHU_REQUIRE_VALID_KEYSET_ID 1
#endif

// When set (default), a suite with intrinsic verification (verify_proofs —
// the v3 pairing check) must pass it on every unblind/receive; 0 downgrades
// a verification failure to a warning for first bring-up against an
// experimental v3 mint. Unlike DLEQ there is nothing the mint can omit —
// verification needs only the published keys — so this should stay 1.
#ifndef CASHU_REQUIRE_PROOF_VERIFY
#define CASHU_REQUIRE_PROOF_VERIFY 1
#endif

namespace cashu {

// NUT-12: Discrete Log Equality proof
struct DLEQ {
    std::string e;
    std::string s;
    std::optional<std::string> r;
};

// NUT-00: Blinded message sent from wallet to mint (also called Output)
struct BlindedMessage {
    int amount;
    std::string B_;
    std::string id;
};

// NUT-00: Blind signature returned by the mint (also called Promise)
struct BlindSignature {
    std::string id;
    int amount;
    std::string C_;
    std::optional<DLEQ> dleq;
};

// NUT-00: Ecash proof (unblinded token)
struct Proof {
    std::string id;
    // TODO(uint64): widening amounts to uint64 requires an NVS schema
    // migration (cJSON numbers are doubles) — deferred; deserializers
    // reject amounts outside [0, INT32_MAX] instead.
    int amount;
    std::string secret;
    std::string C;
    std::optional<DLEQ> dleq;
    std::optional<std::string> witness;
};

// Sum of proof amounts, 64-bit so a large wallet can't overflow int.
inline int64_t proofs_sum(const std::vector<Proof>& proofs) {
    int64_t total = 0;
    for (const auto& p : proofs)
        total += p.amount;
    return total;
}

enum class ProofState {
    unspent,
    pending,
    spent,
};

// NUT-02: Keyset published by the mint
struct Keyset {
    std::string id;
    std::string unit;
    bool active;
    int input_fee_ppk;
    std::optional<int64_t> final_expiry;  // NUT-02 v2: unix epoch, part of id preimage
    std::map<uint64_t, std::string> keys;
};

// NUT-03: Swap request/response
struct SwapRequest {
    std::vector<Proof> inputs;
    std::vector<BlindedMessage> outputs;
};

struct SwapResponse {
    std::vector<BlindSignature> signatures;
};

// NUT-04: Mint quote, method-generic (bolt11/NUT-23 and custom payment
// methods, nuts PR#382). Parsed leniently: `state` is the legacy bolt11
// field (deprecated in NUT-23, absent on custom-method mints); the
// amount_paid/amount_issued accounting pair is the current source of truth.
struct MintQuote {
    std::string quote;
    std::string request;      // opaque payment target (bolt11, URL, account ref)
    int amount = 0;
    std::string unit;         // echoed by the mint; "" when absent
    std::string method;       // from the response, else stamped wallet-side
    std::string state;        // legacy UNPAID/PAID/ISSUED; "" when absent
    int64_t expiry = 0;
    std::optional<int> amount_paid;
    std::optional<int> amount_issued;

    // Claimable now: paid minus issued when the accounting pair is
    // present, else `amount` iff the legacy state says PAID.
    int mintable() const {
        if (amount_paid && amount_issued)
            return *amount_paid > *amount_issued ? *amount_paid - *amount_issued
                                                 : 0;
        return state == "PAID" ? amount : 0;
    }
};

// NUT-04: Mint request/response
struct MintRequest {
    std::string quote;
    std::vector<BlindedMessage> outputs;
};

struct MintResponse {
    std::vector<BlindSignature> signatures;
};

// NUT-05: Melt quote, method-generic. `state` (UNPAID/PENDING/PAID) is
// still normative for melt; fee_reserve and the request echo are optional
// (PR#382 custom methods may omit them).
struct MeltQuote {
    std::string quote;
    int amount = 0;
    int fee_reserve = 0;
    std::string unit;         // echoed by the mint; "" when absent
    std::string method;       // from the response, else stamped wallet-side
    std::string state;
    int64_t expiry = 0;
    std::optional<std::string> request;
    std::optional<std::string> payment_preimage;
    std::optional<std::vector<BlindSignature>> change;
};

// NUT-05: Melt request
struct MeltRequest {
    std::string quote;
    std::vector<Proof> inputs;
    std::optional<std::vector<BlindedMessage>> outputs;
};

// NUT-00: Token (groups proofs by mint)
struct Token {
    std::string mint;
    std::string unit;
    std::optional<std::string> memo;
    std::vector<Proof> proofs;
};

// Keyset info returned by GET /v1/keysets
struct KeysetInfo {
    std::string id;
    std::string unit;
    bool active;
    int input_fee_ppk;
    std::optional<int64_t> final_expiry;  // NUT-02 v2: unix epoch, part of id preimage
};

// NUT-06: one row of the nuts."4"/"5" method-unit matrix
struct MintMethodSetting {
    std::string method;
    std::string unit;
    std::optional<std::string> method_name;  // display name (nuts PR#374)
    std::optional<int64_t> min_amount;       // bounds in the unit's minor units
    std::optional<int64_t> max_amount;
};

// NUT-06 subset the wallet uses: display name plus the method-unit pairs
// the mint will mint/melt. Cached in RAM only, never persisted.
struct MintInfo {
    std::string name;
    std::vector<MintMethodSetting> mint_methods;  // nuts."4".methods
    std::vector<MintMethodSetting> melt_methods;  // nuts."5".methods
};

// NUT-18: Transport method for payment requests
struct Transport {
    std::string type;
    std::string target;
    std::optional<std::vector<std::vector<std::string>>> tags;
};

// NUT-10: Locking condition option for payment requests
struct NUT10Option {
    std::string kind;
    std::string data;
    std::optional<std::vector<std::vector<std::string>>> tags;
};

// NUT-10: well-known structured secret carried inside Proof.secret
// when serialized as JSON: ["<kind>", {"nonce":"<str>", "data":"<str>", "tags":[...]}]
struct NUT10Secret {
    std::string kind;
    std::string nonce;
    std::string data;
    std::vector<std::vector<std::string>> tags;
};

// NUT-18: Payment request
struct PaymentRequest {
    std::optional<std::string> payment_id;
    std::optional<int> amount;
    std::optional<std::string> unit;
    std::optional<bool> single_use;
    std::optional<std::vector<std::string>> mints;
    std::optional<std::string> description;
    std::optional<std::vector<Transport>> transports;
    std::optional<NUT10Option> nut10;
};

} // namespace cashu

