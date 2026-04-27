#ifndef CASHU_WALLET_HPP
#define CASHU_WALLET_HPP

#include "cashu.hpp"
#include "secp256k1.h"
#include <string>
#include <vector>

static const int MAX_MINTS = 3;

namespace cashu {

class Wallet {
public:
    Wallet(const std::string& mint_url, secp256k1_context* ctx, int nvs_slot = 0);

    bool load_keysets();
    bool load_from_nvs();
    bool save_mint_url();
    bool erase_nvs();
    const Keyset* active_keyset(const std::string& unit = "sat") const;
    const Keyset* keyset_for_id(const std::string& id) const;
    int calculate_fee(const std::vector<Proof>& inputs) const;
    static std::vector<int> split_amount(int amount);

    static std::string load_mint_url_for_slot(int slot);

    // NUT-13: Deterministic seed management (global, shared across wallets)
    static bool load_seed();
    static bool save_seed(const unsigned char seed[64], const char* mnemonic);
    static bool seed_exists();
    static bool load_mnemonic(std::string& out);
    static bool erase_seed();
    static bool has_seed() { return s_seed_loaded; }

    // NUT-11: P2PK identity derived from seed. Lazy; recomputed each boot.
    // ensure_p2pk_keypair returns false if no seed is loaded.
    static bool ensure_p2pk_keypair(secp256k1_context* ctx);
    static const char* p2pk_pubkey_hex();         // 66-char compressed hex, "" if absent
    static const unsigned char* p2pk_privkey();   // 32 bytes, NULL if absent

    // Per-keyset counter management
    static uint32_t load_counter(const std::string& keyset_id);
    static bool save_counter(const std::string& keyset_id, uint32_t counter);

    struct BlindingData {
        std::vector<BlindedMessage> outputs;
        std::vector<std::string> secrets;
        std::vector<std::string> blinding_factors;
    };

    bool generate_outputs(const std::vector<int>& amounts,
                          const std::string& keyset_id,
                          BlindingData& out);

    bool unblind_signatures(const std::vector<BlindSignature>& signatures,
                            const BlindingData& blinding,
                            const Keyset& keyset,
                            std::vector<Proof>& proofs_out);

    bool swap(std::vector<Proof>& inputs,
              int amount,
              std::vector<Proof>& new_proofs,
              std::vector<Proof>& change);

    bool receive(const Token& token, std::vector<Proof>& proofs_out);

    // Offline-receive queue: tokens stashed when WiFi is down and drained on
    // reconnect. Each entry is a complete cashuA/cashuB token string from one
    // NFC tap (which itself bundles N proofs). Cap is per-wallet, see
    // PEND_MAX in wallet.cpp.
    bool stash_pending_token(const std::string& raw_token);
    bool list_pending_tokens(std::vector<std::string>& out);
    bool drain_pending_tokens(int& accepted, int& failed);
    int  pending_count() const;

    // NUT-04: Mint tokens (bolt11)
    bool request_mint_quote(int amount, MintQuote& quote_out);
    bool check_mint_quote(const std::string& quote_id, MintQuote& quote_out);
    bool mint_tokens(const std::string& quote_id, int amount);

    // NUT-05: Melt tokens (bolt11)
    bool request_melt_quote(const std::string& bolt11, MeltQuote& quote_out);
    bool check_melt_quote(const std::string& quote_id, MeltQuote& quote_out);
    bool melt_tokens(const MeltQuote& quote, int& change_amount);

    int balance() const;
    bool select_proofs(int amount_needed, std::vector<Proof>& selected,
                       std::vector<Proof>& remaining);

    const std::string& mint_url() const { return mint_url_; }
    const std::vector<Keyset>& keysets() const { return keysets_; }
    const std::vector<Proof>& proofs() const { return proofs_; }
    int nvs_slot() const { return nvs_slot_; }
    bool clear_proofs();

private:
    std::string mint_url_;
    std::vector<Keyset> keysets_;
    std::vector<Proof> proofs_;
    secp256k1_context* ctx_;
    int nvs_slot_;

    bool save_proofs();
    bool load_proofs();
    bool save_keysets();
    bool load_keysets_nvs();
    void merge_keysets(const std::vector<Keyset>& fresh);

    bool keyset_pubkey_for_amount(const Keyset& ks, uint64_t amount,
                                  secp256k1_pubkey& out) const;

    static unsigned char s_seed[64];
    static bool s_seed_loaded;

    static unsigned char s_p2pk_priv[32];
    static char          s_p2pk_pub_hex[67];   // 66 + NUL
    static bool          s_p2pk_loaded;
};

} // namespace cashu

#endif
