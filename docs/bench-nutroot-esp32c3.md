# Nutroot witness verification on ESP32-C3

Benchmarks of the nutroot proposal (taproot-style v3 secrets,
[cashubtc/nuts#421](https://github.com/cashubtc/nuts/pull/421)) on this
wallet's target hardware, mirroring nutshell's
`scripts/bench_nutroot_witness.py` (branch
`bench/nutroot-witness-verification`) case-for-case, plus the crypto cost of
the wallet's standard 10-proof v3 receive.

| | |
|---|---|
| Device | ESP32-C3 (RV32IMC, 160 MHz, single core), bare board |
| Firmware | nucula `feat/keyset-v3` + this benchmark, ESP-IDF v5.5.1, `-Os` project / `-O2` nutroot+crypto / `-O3` blst |
| secp256k1 | vendored libsecp256k1, no asm, `ECMULT_WINDOW_SIZE=8`, `ECMULT_GEN_PREC_BITS=4`, SCHNORRSIG+EXTRAKEYS |
| Host baseline | Apple M2 Max, Python 3.10.4, nutshell `bench/nutroot-witness-verification` @ `0300a45`, coincurve — run the same day |
| Date | 2026-09-01 |

## Methodology

The timed unit is one call to `nutroot_verify_transaction()` — the C mirror
of nutshell's `LedgerVerification._verify_nutroot_transaction_witnesses` —
with the same boundary: v3 point-secret detection, transaction-digest
computation, witness JSON parsing, and all schnorr/merkle/script checks
happen inside the timed region. Both implementations are pinned to the
shared vectors (`tests/nutroot_v3_vectors.json`), and the threshold
evaluation loop iterates all leaf keys without early exit exactly as
nutshell's does, so BIP-340 verify counts match 1:1.

Cases are built once on the heap, sanity-verified untimed, then timed over
2–5 iterations (device) with a FreeRTOS yield *between* iterations;
mean/median/min microseconds are reported like nutshell's table. Rows whose
single call approaches the 5 s idle-watchdog window (script N≥32,
8-of-15) run with a cooperative yield hook inside verification (one 1 ms
tick per input / per 4 signature verifies, ≤2 % distortion). Host numbers
are means over thousands of iterations from the nutshell script run on the
same day on this machine.

Reproduce on device: `log i nutroot`, then `bench nutroot` (default points,
~90 s) or `bench nutroot full` (all sweep points, ~3 min). `selftest` runs
the vector conformance suite (leaf wire forms, merkle fold, tweaks,
transcripts, deterministic signatures, e2e witness verification incl.
designed-to-fail cases).

## Named cases

Case names as in nutshell's benchmark. Device columns are µs (mean of 3–5);
host column is the same-day M2 Max mean; the PR discussion's reference
hardware reported ~87 / ~171 / ~395 µs for keypath / 1-of-1 / 2-of-3.

| case | C3 mean (µs) | C3 min (µs) | M2 Max (µs) | C3 / M2 |
|---|---:|---:|---:|---:|
| keypath_bare | 24,176 | 23,835 | 45.3 | 534× |
| keypath_tweaked | 23,829 | 23,475 | 45.6 | 522× |
| script_threshold_1of1 | 41,376 | 40,529 | 85.1 | 486× |
| script_threshold_2of3 | 119,306 | 118,424 | 196.4 | 607× |
| script_after_refund | 40,856 | 40,664 | 88.3 | 463× |
| script_hashlock | 40,539 | 40,306 | 88.4 | 459× |
| script_multileaf_8 | 40,789 | 40,776 | 89.4 | 456× |
| script_multileaf_64 | 41,529 | 41,469 | 94.0 | 442× |
| script_p2bk_blinded | 40,345 | 40,345 | 86.4 | 467× |
| multi_input_4_keypath | 89,039 | 89,033 | 161.4 | 552× |
| multi_input_4_script | 156,086 | 156,086 | 320.4 | 487× |

Anchors on the C3: one BIP-340 schnorr verify ≈ **19.7 ms**, one tweak-add
(`K + t·G`) ≈ **16 ms**, so key-path ≈ 24 ms (digest + JSON + 1 verify) and
script-path 1-of-1 ≈ 41 ms (adds the commitment reconstruction). Merkle
depth, leaf parsing, and hashing are noise at this scale (multileaf_64 costs
~0.2 ms more than a single-leaf tree).

## Sweeps

Inputs sweep (N inputs + N outputs per call; C3 µs/input vs host µs/input):

| N | keypath C3 (µs/in) | keypath M2 (µs/in) | script C3 (µs/in) | script M2 (µs/in) |
|---:|---:|---:|---:|---:|
| 1 | 23,864 | 45.5 | 40,829 | 86.5 |
| 2 | 22,904 | 42.0 | 39,449 | 81.7 |
| 4 | 22,299 | 40.0 | 39,003 | 79.6 |
| 8 | 22,009 | 38.8 | 38,795 | 78.6 |
| 16 | 21,747 | 38.3 | 38,640 | 77.7 |
| 32 | 21,723 | 37.9 | 38,968 | 78.4 |
| 64 | 22,367 | 38.2 | 39,076 | 78.2 |

Perfectly linear on both machines — the per-transaction overhead (digest
setup) amortizes away by N=4 and per-input cost is flat thereafter.

Leaves sweep (1 script input on an L-leaf tree; path length in parentheses):
flat within noise on the C3 — 40.5 ms (L=1, path 0) to 41.3 ms (L=256, path
8). Each extra merkle level costs one tagged hash (~100 µs); the schnorr
verify dominates everything. The host shows the same shape (86 → 95 µs).

Threshold sweep (single leaf, n-of-m, signatures by the first n keys;
`sv` = measured BIP-340 verify count, identical on both implementations):

| case | sv | C3 mean (µs) | M2 Max (µs) | C3 / M2 |
|---|---:|---:|---:|---:|
| 1-of-1 | 1 | 41,101 | 85.7 | 480× |
| 2-of-3 | 5 | 119,738 | 194.4 | 616× |
| 3-of-5 | 12 | 250,256 | 388.3 | 645× |
| 5-of-8 | 30 | 590,262 | 866.6 | 681× |
| 8-of-15 | 92 | 1,729,269 | 2,524.0 | 685× |

Cost tracks `sv` linearly (~19.7 ms per verify on the C3). Large thresholds
are the one nutroot construct that gets genuinely heavy on embedded
hardware: a single 8-of-15 input costs **1.73 s**.

## 10-proof v3 receive (the wallet's standard operation)

10 proofs under 10 distinct mint keys (real-token shape), 33-byte
compressed-point secrets throughout, receiver-keyed spend info (internal
key ours, one disclosed 1-of-1 refund leaf per proof). RSA/MPI-accelerated
BLS path.

| phase | what it does | mean (µs) |
|---|---|---:|
| recv verify n=10 | BLS batch pairing verify of the incoming proofs | 1,886,479 |
| recv spendinfo n=10 | 10× parse leaf, rebuild root, tweak `K+t·G`, compare secret | 166,180 |
| swap sign n=10 | tx digest + 10× (tweaked-key derivation + BIP-340 sign + witness JSON) | 832,368 |
| swap blind n=10 | 10× BLS blind | 400,463 |
| swap unblind n=10 | 10× BLS unblind | 404,532 |
| recv verify out n=10 | BLS batch verify of the returned proofs | 1,886,468 |

| receive shape | total |
|---|---:|
| Variant A — verify at tap (offline NFC), swap later | tap **2.05 s** + later **3.52 s** |
| Variant B — immediate swap + verify returned proofs | **5.58 s** |
| nutroot-specific overhead vs the pre-nutroot v3 swap (spendinfo + sign) | **+1.00 s** (4.58 s → 5.58 s, +22 %) |

The BLS pairing work still dominates (3.77 s of the 5.58 s); nutroot adds
~100 ms per proof — 16.6 ms spend-info reconstruction at receive plus
~83 ms tweaked-key derivation + signing + witness assembly at spend. The
offline-tap path (variant A) absorbs 2.05 s at tap time, of which the new
nutroot share is only 166 ms.

Comparison to the pre-nutroot benchmark rows (`bench bls`, short ASCII
secrets): `suite_verify n=10 dk` 1.93 s → 1.89 s here with 33-byte point
secrets (shorter hash-to-curve input), `swap crypto n=10 dk` 4.67 s → 4.60 s
equivalent phases.

## Notes

- Spec status: PR #421 is unmerged; this implementation mirrors nutshell's
  bench branch (the comparison target) and is pinned by the shared
  `nutroot_v3_vectors.json`, which nutshell and cashu-ts also pin. The same
  core passes the vector suite compiled for the host (arm64) and on-device.
- Every input signs the transaction digest itself on this branch; the
  per-input `Cashu_TransactionInput` tagged digest described in earlier
  spec revisions is not in the verified path.
- Device timing variance is negligible (min ≈ mean; no caches to warm
  beyond the first untimed sanity call), which is why 2–5 iterations
  suffice where nutshell needs thousands.
- Memory: the benchmark holds one ~12 KB case buffer plus transient witness
  JSON (~23 KB at the 64-input script point, gated on a 28 KB largest free
  block); heap returns to baseline afterwards. Console-task stack
  high-water across selftest + full bench: ~17.2 KB of 24 KB
  (see `main/console.h`).
