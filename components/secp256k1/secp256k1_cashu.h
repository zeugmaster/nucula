#ifndef SECP256K1_CASHU_H
#define SECP256K1_CASHU_H

#include <stddef.h>
#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

int secp256k1_cashu_hash_to_curve(const secp256k1_context *ctx,
                                  secp256k1_pubkey *out,
                                  const unsigned char *msg,
                                  size_t msg_len);

int secp256k1_cashu_blind_message(const secp256k1_context *ctx,
                                  secp256k1_pubkey *B_out,
                                  const unsigned char *secret,
                                  size_t secret_len,
                                  const unsigned char r[32]);

int secp256k1_cashu_blind_message_ser(const secp256k1_context *ctx,
                                      unsigned char B_out33[33],
                                      const unsigned char *secret,
                                      size_t secret_len,
                                      const unsigned char r[32]);

int secp256k1_cashu_unblind(const secp256k1_context *ctx,
                            secp256k1_pubkey *C_out,
                            const secp256k1_pubkey *C_,
                            const unsigned char r[32],
                            const secp256k1_pubkey *K);

int secp256k1_cashu_unblind_ser(const secp256k1_context *ctx,
                                unsigned char C_out33[33],
                                const unsigned char C_33[33],
                                const unsigned char r[32],
                                const unsigned char K33[33]);

int secp256k1_cashu_verify_dleq(const secp256k1_context *ctx,
                                const secp256k1_pubkey *A,
                                const secp256k1_pubkey *B_,
                                const secp256k1_pubkey *C_,
                                const unsigned char e[32],
                                const unsigned char s[32]);

int secp256k1_cashu_verify_dleq_ser(const secp256k1_context *ctx,
                                    const unsigned char A33[33],
                                    const unsigned char B_33[33],
                                    const unsigned char C_33[33],
                                    const unsigned char e[32],
                                    const unsigned char s[32]);

/* Combined DLEQ verification + unblinding from compressed SEC1 inputs:
 * parses K, B_, C_ once (avoiding 2 redundant modular square roots). */
int secp256k1_cashu_verify_dleq_and_unblind_ser(const secp256k1_context *ctx,
                                                const unsigned char K33[33],
                                                const unsigned char B_33[33],
                                                const unsigned char C_33[33],
                                                const unsigned char e[32],
                                                const unsigned char s[32],
                                                const unsigned char r[32],
                                                unsigned char C_out33[33]);

int secp256k1_cashu_verify_dleq_unblinded(const secp256k1_context *ctx,
                                          const secp256k1_pubkey *A,
                                          const secp256k1_pubkey *C,
                                          const unsigned char *secret,
                                          size_t secret_len,
                                          const unsigned char e[32],
                                          const unsigned char s[32],
                                          const unsigned char r[32]);

int secp256k1_cashu_verify_dleq_unblinded_ser(const secp256k1_context *ctx,
                                              const unsigned char A33[33],
                                              const unsigned char C33[33],
                                              const unsigned char *secret,
                                              size_t secret_len,
                                              const unsigned char e[32],
                                              const unsigned char s[32],
                                              const unsigned char r[32]);

void secp256k1_cashu_hmac_sha256(const unsigned char *key, size_t key_len,
                                 const unsigned char *msg, size_t msg_len,
                                 unsigned char out32[32]);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_CASHU_H */
