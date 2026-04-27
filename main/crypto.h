#ifndef CASHU_CRYPTO_H
#define CASHU_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Hash a message to a point on the secp256k1 curve.
 * Implements the Cashu hash_to_curve function (NUT-00).
 *
 * Domain separator: "Secp256k1_HashToCurve_Cashu_"
 * Algorithm: tries counter values 0..2^16, computes SHA256(SHA256(domain || msg) || counter_le)
 * and attempts to parse 0x02 || hash as a compressed public key.
 *
 * @param ctx      secp256k1 context
 * @param out      resulting curve point
 * @param msg      message bytes
 * @param msg_len  length of message
 * @return 1 on success, 0 on failure
 */
int cashu_hash_to_curve(const secp256k1_context *ctx,
                        secp256k1_pubkey *out,
                        const unsigned char *msg,
                        size_t msg_len);

/**
 * Compute a blinded message: B_ = hash_to_curve(secret) + r*G
 *
 * @param ctx         secp256k1 context
 * @param B_out       resulting blinded message (curve point)
 * @param secret      secret bytes (raw bytes or UTF-8 encoded string)
 * @param secret_len  length of secret in bytes
 * @param r           32-byte blinding factor scalar
 * @return 1 on success, 0 on failure
 */
int cashu_blind_message(const secp256k1_context *ctx,
                        secp256k1_pubkey *B_out,
                        const unsigned char *secret,
                        size_t secret_len,
                        const unsigned char *r);

/**
 * Unblind a mint's blind signature: C = C_ - r*K
 *
 * @param ctx    secp256k1 context
 * @param C_out  resulting unblinded signature (curve point)
 * @param C_     blind signature from mint
 * @param r      32-byte blinding factor used during blinding
 * @param K      mint's public key for the denomination
 * @return 1 on success, 0 on failure
 */
int cashu_unblind(const secp256k1_context *ctx,
                  secp256k1_pubkey *C_out,
                  const secp256k1_pubkey *C_,
                  const unsigned char *r,
                  const secp256k1_pubkey *K);

/**
 * Verify a DLEQ proof on a BlindSignature (Alice's verification).
 *
 * Checks: e == hash(R1, R2, A, C_)
 * where R1 = s*G - e*A, R2 = s*B_ - e*C_
 *
 * @param ctx  secp256k1 context
 * @param A    mint public key
 * @param B_   blinded message
 * @param C_   blind signature
 * @param e    32-byte DLEQ challenge
 * @param s    32-byte DLEQ response
 * @return 1 if valid, 0 if invalid or error
 */
int cashu_verify_dleq(const secp256k1_context *ctx,
                      const secp256k1_pubkey *A,
                      const secp256k1_pubkey *B_,
                      const secp256k1_pubkey *C_,
                      const unsigned char *e,
                      const unsigned char *s);

/**
 * Verify a DLEQ proof on a Proof (Carol's verification).
 * Reconstructs B_ and C_ from the unblinded values, then verifies.
 *
 * Reconstruction:
 *   Y  = hash_to_curve(secret)
 *   C_ = C + r*A
 *   B_ = Y + r*G
 *
 * @param ctx         secp256k1 context
 * @param A           mint public key
 * @param C           unblinded signature from proof
 * @param secret      secret bytes (raw bytes or UTF-8 encoded string)
 * @param secret_len  length of secret in bytes
 * @param e           32-byte DLEQ challenge
 * @param s           32-byte DLEQ response
 * @param r           32-byte blinding factor
 * @return 1 if valid, 0 if invalid or error
 */
int cashu_verify_dleq_unblinded(const secp256k1_context *ctx,
                                const secp256k1_pubkey *A,
                                const secp256k1_pubkey *C,
                                const unsigned char *secret,
                                size_t secret_len,
                                const unsigned char *e,
                                const unsigned char *s,
                                const unsigned char *r);

/**
 * Serialize a public key to 33-byte compressed SEC1 format.
 * Convenience wrapper around secp256k1_ec_pubkey_serialize.
 *
 * @param ctx  secp256k1 context
 * @param out  33-byte output buffer
 * @param pk   public key to serialize
 * @return 1 on success, 0 on failure
 */
int cashu_pubkey_serialize(const secp256k1_context *ctx,
                           unsigned char out[33],
                           const secp256k1_pubkey *pk);

/**
 * Parse a 33-byte compressed public key.
 * Convenience wrapper around secp256k1_ec_pubkey_parse.
 *
 * @param ctx   secp256k1 context
 * @param out   output public key
 * @param input 33-byte compressed public key
 * @return 1 on success, 0 on failure
 */
int cashu_pubkey_parse(const secp256k1_context *ctx,
                       secp256k1_pubkey *out,
                       const unsigned char input[33]);

/**
 * NUT-13: Derive a deterministic secret using HMAC-SHA256 KDF.
 *
 * message = "Cashu_KDF_HMAC_SHA256" || hex_decode(keyset_id) || counter_be64 || 0x00
 * secret  = HMAC-SHA256(seed, message)
 *
 * @param seed        wallet seed bytes (typically 64 bytes from BIP39)
 * @param seed_len    length of seed
 * @param keyset_id   hex-encoded keyset ID (e.g. "01...")
 * @param counter     per-keyset counter value
 * @param secret_out  32-byte output buffer
 * @return 1 on success, 0 on failure
 */
int cashu_derive_secret(const unsigned char *seed, size_t seed_len,
                        const char *keyset_id, uint32_t counter,
                        unsigned char secret_out[32]);

/**
 * NUT-13: Derive a deterministic blinding factor using HMAC-SHA256 KDF.
 *
 * message = "Cashu_KDF_HMAC_SHA256" || hex_decode(keyset_id) || counter_be64 || 0x01
 * r       = OS2IP(HMAC-SHA256(seed, message)) mod N
 *
 * @param seed        wallet seed bytes (typically 64 bytes from BIP39)
 * @param seed_len    length of seed
 * @param keyset_id   hex-encoded keyset ID (e.g. "01...")
 * @param counter     per-keyset counter value
 * @param r_out       32-byte output buffer (reduced mod secp256k1 order)
 * @return 1 on success, 0 on failure (including r == 0)
 */
int cashu_derive_r(const unsigned char *seed, size_t seed_len,
                   const char *keyset_id, uint32_t counter,
                   unsigned char r_out[32]);

/**
 * NUT-11: BIP-340 Schnorr-sign SHA256(secret_bytes) with a P2PK private key.
 *
 * Used to construct the witness signature on `Proof.secret` when spending a
 * P2PK-locked input with sigflag SIG_INPUTS.
 *
 * @param ctx         secp256k1 context (sign-capable)
 * @param priv        32-byte private key
 * @param secret_bytes message to sign (typically the unescaped Proof.secret)
 * @param secret_len  length of message
 * @param sig64_out   64-byte output buffer for the BIP-340 signature
 * @return 1 on success, 0 on failure
 */
int cashu_schnorr_sign_secret(const secp256k1_context *ctx,
                              const unsigned char priv[32],
                              const unsigned char *secret_bytes,
                              size_t secret_len,
                              unsigned char sig64_out[64]);

#ifdef __cplusplus
}
#endif

#endif
