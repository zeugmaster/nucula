#pragma once

#include <secp256k1.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Nutroot (NUT-10 rev. cashubtc/nuts#421) conformance vectors from the
 * shared tests/nutroot_v3_vectors.json: leaf serialization, merkle fold,
 * tweak math, transaction transcripts, signatures, and full witness
 * verification incl. designed-to-fail cases. Returns 1 if all pass. */
int nutroot_run_tests(const secp256k1_context *ctx);

/* On-device nutroot benchmark (results logged at info level, tag
 * "nutroot"): witness-verification cases and sweeps mirroring nutshell's
 * scripts/bench_nutroot_witness.py for direct comparison, then the
 * 10-proof v3 receive benchmark (BLS verify + spend-info reconstruction +
 * witness signing + blind/unblind). full != 0 adds the large sweep points
 * (more inputs/leaves/threshold sizes; minutes, not seconds). */
void nutroot_run_benchmark(const secp256k1_context *ctx, int full);

#ifdef __cplusplus
}
#endif
