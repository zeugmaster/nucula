#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* NUT-00 v3 (BLS12-381) conformance vectors driven over the raw blst API:
 * hash_to_curve_G1, multiplicative blind/unblind round-trip, pairing
 * verification, Fiat-Shamir batch verification, and point validation.
 * Returns 1 if all pass, 0 otherwise. */
int crypto_bls_run_tests(void);

/* On-device benchmark of the BLS12-381 primitives (results logged at info
 * level). Rows mirror bls-bench RESULTS.md so the numbers are directly
 * comparable against the Rust reference on the same hardware. */
void crypto_bls_run_benchmark(void);

#ifdef __cplusplus
}
#endif
