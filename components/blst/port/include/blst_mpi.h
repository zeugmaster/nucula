#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ESP32-C3 RSA/MPI acceleration for blst's 384-bit Fp Montgomery multiply
 * (technique from github.com/zeugmaster/bls-bench, ~4.4x on the full
 * protocol). The patched no_asm.h routes every mul_mont call to
 * mpi_mul_mont_n() below; 384-bit operands go to the peripheral, everything
 * else (256-bit Fr) takes the software path.
 *
 * LOCKING: the RSA peripheral is shared with mbedTLS's bignum port (TLS
 * handshakes, including the background http_prewarm task). Wrap every burst
 * of blst calls in blst_hw_acquire()/blst_hw_release() — the same
 * lock + clock + memory-clean protocol mbedTLS uses, so the two interleave
 * safely. The lock is NON-recursive: never nest acquires, and never perform
 * TLS/HTTP/mbedTLS work while holding it. A blst call outside a hold window
 * still computes correctly (one-time warning + per-call acquire), just
 * slowly: acquiring pulses the peripheral reset, which clears the operand
 * caches that make the fast path fast.
 *
 * On targets other than the ESP32-C3 all of this compiles to the software
 * path and acquire/release are no-ops.
 */

/* Acquire the RSA/MPI peripheral for a burst of blst calls. Blocks while
 * mbedTLS holds it (TLS handshake bignum ops are short bursts). */
void blst_hw_acquire(void);
void blst_hw_release(void);

/* Runtime kill-switch (default on, C3 only): lets the benchmark measure
 * the portable and MPI paths in one binary. */
void blst_mpi_set_enabled(int enabled);
int  blst_mpi_enabled(void);

/* The symbol the patched no_asm.h calls in place of blst's own mul_mont_n:
 * ret = a*b*R^-1 mod p, R = 2^(32n), fully reduced into [0, p). */
void mpi_mul_mont_n(uint32_t ret[], const uint32_t a[], const uint32_t b[],
                    const uint32_t p[], uint32_t n0, size_t n);

/* Software Montgomery multiply at n=12 (the exact blst portable algorithm) —
 * exposed so the self-test can check the peripheral path bit-for-bit. */
void blst_mpi_sw_mul_mont_384(uint32_t ret[12], const uint32_t a[12],
                              const uint32_t b[12], const uint32_t p[12],
                              uint32_t n0);

#ifdef __cplusplus
}
#endif
