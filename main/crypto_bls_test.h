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
void crypto_bls_run_contention(unsigned flags);
void crypto_bls_run_scaling(unsigned flags, unsigned capacity, unsigned count, unsigned distinct, unsigned repetitions);
void crypto_bls_run_benchmark(void);
void crypto_bls_run_fast_benchmark(void);
void crypto_bls_run_mpi_benchmark(int options);
void crypto_bls_run_verifier_benchmark(unsigned options, unsigned capacity);

/* i in [0,9]: hex of K_i = (2+i)*g2, the host-precomputed bench mint keys
 * (blst's G2 mult keeps a ~9 KB window table on the stack — the device
 * never derives these). Shared with the nutroot receive benchmark. */
const char *crypto_bls_bench_key_hex(int i);

#ifdef __cplusplus
}
#endif
