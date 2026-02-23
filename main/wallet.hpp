#ifndef CASHU_WALLET_HPP
#define CASHU_WALLET_HPP

#include "cashu.hpp"
#include "secp256k1.h"
#include <string>
#include <vector>

namespace cashu {

class Wallet {
public:
    Wallet(const std::string& mint_url, secp256k1_context* ctx);

    bool load_keysets();
    const Keyset* active_keyset(const std::string& unit = "sat") const;
    int calculate_fee(const std::vector<Proof>& inputs) const;
    static std::vector<int> split_amount(int amount);

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

    const std::string& mint_url() const { return mint_url_; }
    const std::vector<Keyset>& keysets() const { return keysets_; }
    const std::vector<Proof>& proofs() const { return proofs_; }

private:
    std::string mint_url_;
    std::vector<Keyset> keysets_;
    std::vector<Proof> proofs_;
    secp256k1_context* ctx_;
};

} // namespace cashu

#endif
