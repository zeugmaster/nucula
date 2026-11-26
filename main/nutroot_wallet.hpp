#pragma once
#include "cashu.hpp"
#include "nutroot.h"
#include <array>

namespace cashu {
// v3 hashes decoded point bytes; pre-v3 hashes the original UTF-8 secret.
bool proof_secret_bytes(const Proof& proof, std::vector<unsigned char>& bytes);
// Key-path spending (bearer or NUT-28 receiver). Refuses proofs we cannot spend.
bool nutroot_spend_key(const secp256k1_context* ctx, const Proof& proof,
                      const unsigned char* receiver_key, unsigned char key[32], bool offline = false);
bool nutroot_sign_proofs(const secp256k1_context* ctx, std::vector<Proof>& inputs,
                        const std::vector<BlindedMessage>& outputs,
                        const unsigned char* receiver_key,
                        const nutroot_quote_t* melt = nullptr);
bool nutroot_sign_quote(const secp256k1_context* ctx, const MintQuote& quote, int amount,
                       const std::vector<BlindedMessage>& outputs,
                       const unsigned char key[32], std::string& signature);
}
