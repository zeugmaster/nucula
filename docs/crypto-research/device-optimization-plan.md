# ESP32-C3 optimization campaign

Started 2026-09-15, following the device-free assessment. Target: ESP32-C3 revision 0.4, USB serial ending `2A:C8`, existing 4 MB flash layout. The measured implementation campaign is complete through build **52-final** and reboot/read-back check **53**. See the [hardware report](../esp32c3-optimization-results.md) for comparisons, limits and exact configuration.

Original working tree and build are backed up privately under `/tmp/nucula-opt-20260915`. Existing uncommitted Nutroot work is the starting point. Synthetic benchmarks do not spend wallet funds. Application-only flashes preserve the partition layout. Experiment 25 additionally installs a QIO-capable bootloader. Final flash read-back matches build 52; the partition table and all live wallet NVS entries match the original. Four live PHY calibration entries changed through normal startup. Full flash backups remain private.

## Experiment ledger

| Family | Explored variants | Outcome |
|---|---|---|
| Baseline | Existing self-tests, BLS, secp, Nutroot; corrected signing and full-width fixtures | Original firmware recorded (00), duplicate-sign benchmark fixed; distinct historical/current fixtures retained |
| Peripheral | Session configuration, inline registers, operand caches, modulus invariant, task ownership, RV32 copy | Session/inline/immutable modulus/no operand cache retained; alternative cache lookup and RV32 copy lost (01, 48) |
| Fixed arithmetic | Square chains, public-exponent sqrt/inverse, fused/pipelined Fp2, general secp field hook | BLS/secp sqrt and pipelined Fp2 retained; hardware inverse, square chains and general secp field multiplication lost (02, 23, 44–52) |
| Pairing | Capacities 1/4/8/11/16, bounded workspace, batch affine, fixed-generator/hot-key preparation | Capacity 11 with smaller-input/OOM allocation; prepared generator retained, optional 19.6 KB hot-key table rejected as default (03, 06, 48–50) |
| BLS verifier | Exact key cache, grouping, window/bucket/GLV MSM, retained points, batch Fr inverse | Bucket/GLV and grouped Y MSM retained; combined unblind/verify integrated in wallet, private factors wiped (03–06, 24–25c, 40–50) |
| Hash cache | 16 projective, 32 affine, 64 affine; oversized scan admission | 64 affine entries selected; prevent cyclic eviction for oversized batches; dynamic workspace pays some memory cost (38, 44–50) |
| Nutroot | Current transcripts/limits/disclosure, threshold matching, parsed objects, keypair reuse, ECDH/slots, KDF | Current NUT-10/13/28 core and vectors implemented; retained signing and commitment batch API measured; production token/storage migration explicitly separate (21–25c, 43–52) |
| Schnorr batches | Strauss/Pippenger, variable windows 3/4/5, adaptive scratch | Strauss/window 4 selected; adaptive chunks improve 16/32/64 key-path fixtures about 20%, and pass current per-input host vectors (39, 42, 51–52) |
| secp256k1 | Signing combs 2/11/43, generator windows 4/8/10/12/14, compiler flags, RAM tables | 2 KB comb, window 12, Os; even 2 KB RAM table gave under 2% and was disabled; legacy joint DLEQ retained (04–18, 26, 30–32, 40–50) |
| Build/memory | O2/O3/Os, full/selective IRAM, whole/BLS-only LTO, QIO, SHA | QIO80, hardware SHA, O3 blst/MPI, Os secp/caller, hot-only MPI IRAM; LTO lost; whole IRAM caused allocation/startup failures (19–20, 25–36, 41, 49–52) |
| Workflow | Fresh-output preparation, task ownership, proof/key scaling, accelerator contention | Preparation API implemented but persistent pool remains caller work; measured 1–64 proofs and 1–10 keys; IDF MPI/SHA peer passes. Real radio/TLS/payment latency unavailable (37–52) |
| Speculative | Wide RSA packing, affine Miller, final exponent, lazy field backend, delegation and other hardware | Wide products lose before reduction; measured Fp2/FE costs bound affine/FE gains. Alternative backends, protocol changes and new hardware evaluated as separate research, not claimed impossible |

## Final evidence

- [52-final.log](device-results/52-final.log): current proposal operations, large adaptive Schnorr cases, ten-proof verification, 64-proof repeat, heap and stack; all diagnostics pass.
- [50-final.log](device-results/50-final.log): complete scaling matrix, same-binary threshold/legacy comparisons and IDF MPI/SHA task contention; all diagnostics pass.
- [53-reboot.log](device-results/53-reboot.log) and [final-verification.json](device-results/final-verification.json): reboot self-tests, exact installed-image comparison, source consistency, clean upstream secp submodule and private NVS comparison.
- [host-validation.json](device-results/host-validation.json): source snapshots and sanitizer/differential tests for full suite and subsequent cache/workspace/adaptive changes.
- [fresh-build.json](device-results/fresh-build.json): separate SDK configuration/build from defaults; settings match the measured firmware.
- [measurements.csv](device-results/measurements.csv): parsed timing rows retaining command, source line and diagnostic status. Logs 00/01/02/04 include watchdog warnings; 17/18/20/21/25/25b/46/51 include known failures explained in the report. Failed cryptographic checks are not speedups.

The finite measured campaign covers compiler, memory, accelerator, point arithmetic, batching, caching and workflow variants. It does not establish global algorithmic optimality. Connected-network/NFC testing, full current-Nutroot wallet migration, persistent preparation allocation, alternative field backends and protocol/hardware changes are explicitly bounded follow-up projects. No device access, firmware build or requested measurement is still running.
