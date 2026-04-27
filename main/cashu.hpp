#ifndef CASHU_HPP
#define CASHU_HPP

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
    int amount;
    std::string secret;
    std::string C;
    std::optional<DLEQ> dleq;
    std::optional<std::string> witness;
};

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

// NUT-04: Mint quote (Bolt11/NUT-23)
struct MintQuote {
    std::string quote;
    std::string request;
    int amount;
    std::string state;
    int64_t expiry;
};

// NUT-04: Mint request/response
struct MintRequest {
    std::string quote;
    std::vector<BlindedMessage> outputs;
};

struct MintResponse {
    std::vector<BlindSignature> signatures;
};

// NUT-05: Melt quote (Bolt11)
struct MeltQuote {
    std::string quote;
    int amount;
    int fee_reserve;
    std::string state;
    int64_t expiry;
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

#endif
