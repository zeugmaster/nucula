# Cashu BLS and Nutroot performance on ESP32-C3

> Historical device-free assessment, September 13, 2026. The subsequent implementation and connected-device measurements are in the [September 15 hardware report](esp32c3-optimization-results.md). This document's projections and “not yet implemented” statements describe the earlier checkout.

There is meaningful optimization headroom on the existing ESP32-C3. The best route combines removal of repeated work, a memory-aware pairing implementation, improvements to the RSA/MPI driver, and a less wasteful Nutroot witness path. A compiler flag alone will not turn the current ten-proof receive into an instant operation. Several large improvements sometimes suggested for this problem—hardware Montgomery multiplication, GLV multiplication, batching, and a shared final exponentiation—are already implemented.

The strongest immediate findings are concrete. The historical Nutroot receive benchmark signs each input twice. The BLS verifier calls a library function whose fixed stack allocation is much larger than its four-element caller assumes. The secp256k1 build defines an obsolete generator-table parameter. The latest Nutroot specification differs substantially from the local benchmark, and the production wallet has not integrated Nutroot yet. These findings should shape both the next benchmark and the implementation work.

This assessment uses repository history and recorded device measurements, current primary specifications checked on September 13, 2026, host arithmetic experiments, and RV32 cross-compilation. **No new hardware timings were obtained.** Times labeled “recorded” are existing observations, operation counts are new host results, and projections are hypotheses. The accompanying [evidence directory](crypto-research/) includes source fingerprints, reproducible probes, CSV results, and a sensitivity workbook.

## Repository and benchmark inventory

The relevant branch is `feat/keyset-v3`, at `85ac407659e271db0e95bb6293f406cbf54ab564`. Its remote tip matches the local tip. The current remote `main`, `8ad081219c`, contains a failing BLS scaffold, not the working BLS implementation. The local `main` branch is older still. Only `origin/feat/keyset-v3` contains the BLS benchmark introduction commit among the available remote branches.

| Location or revision | What it establishes |
|---|---|
| [main/crypto_bls_test.c](../main/crypto_bls_test.c), `bench bls` | Primitive benchmarks, conformance checks, and production-suite ten-distinct-key verification/swap rows |
| `acfc297` | Introduces BLS vectors and benchmark; documents the large G2 multiplication stack |
| `857c135` | Installs the existing RSA/MPI acceleration and software/hardware comparison tests |
| `e9b3b5a` | Recorded `-O3` benefit for blst: single verification 497 → 372 ms; its ten-proof row was a different, same-key workload |
| `cbdea01` | Fixes rejection of more than eight distinct mint keys; records 2.22 s verification and 5.30 s wallet swap crypto for ten distinct keys |
| `85ac407` | Four-pair Miller chunks: those rows improve to 1.93 s and 4.67 s; eight-pair chunks were another approximately 75 ms faster per verify |
| `eb53f21` | secp256k1 `-O2` regressed measured operations by 13–25%; current `-Os` was deliberate |
| [docs/bench-nutroot-esp32c3.md](bench-nutroot-esp32c3.md) | Existing September 1 device report, including threshold sweeps and a modeled six-phase receive |
| [main/nutroot.c](../main/nutroot.c), [main/nutroot_test.c](../main/nutroot_test.c) | Uncommitted Nutroot implementation and benchmark, wired into console tests |
| [zeugmaster/bls-bench](https://github.com/zeugmaster/bls-bench), especially [RESULTS.md](https://github.com/zeugmaster/bls-bench/blob/main/RESULTS.md) | Earlier independent firmware benchmark from which this repository’s peripheral technique was ported |

The pre-existing uncommitted files were preserved. New files from this assessment are research artifacts only. Individual commits can be inspected with `git show --format=fuller --stat <commit>`; the detailed performance observations above are in their commit messages.

**A keyset is not one pairing key.** Amounts have separate mint keys. Ten denominations within one keyset commonly mean ten distinct G2 keys. The older external benchmark’s interpretation of its approximately 0.93-second *same-key* case as a typical one-keyset token is misleading for this workload. Its distinct-key model, approximately 1.82 seconds for ten proofs, is the relevant comparator to the wallet’s approximately 1.9 seconds. Neither bare-firmware results nor its projected Wi-Fi slowdown substitute for measurements of this application.[^1]

## What the wallet actually does

The production cryptographic boundary is [cashu_suite_t](../main/cashu_suite.h). The BLS suite has 48-byte G1 token points, 96-byte G2 mint keys, multiplicative blinding, and pairing verification. The main operations are:

```
Y = hash_to_G1(secret_bytes)
B_ = r Y
C = r⁻¹ C_
verify: e(C, G2) = e(Y, K)
```

For a batch, [crypto_bls.c](../main/crypto_bls.c) derives full-width Fiat–Shamir weights, validates each incoming signature, hashes each secret, performs two G1 scalar multiplications per proof, and evaluates the pairing product in chunks. There is already **one final exponentiation for the entire batch**. Only the last encountered G2 key is cached, and that cache lasts one call.

[Wallet::receive](../main/wallet.cpp) verifies incoming proofs, swaps them, and verifies the unblinded outputs. `unblind_signatures()` validates each received `C_`, computes and serializes `C`, and sends the result through the byte-oriented batch interface. Consequently, the batch reparses/revalidates the locally computed `C`, recomputes output `Y`, and revalidates mint keys. The byte interface is simple but discards useful provenance and intermediate points.

Nutroot is currently a test/benchmark path. There are no production Nutroot calls in `wallet.cpp`; [Proof](../main/cashu.hpp) has no spend-info field. The existing six-phase receive is therefore a composition of cryptographic calls, not a measured production Nutroot receive over NFC, HTTP, and NVS.

### Recorded baseline and its limitations

| Historical ten-proof Nutroot benchmark phase | Recorded mean |
|---|---:|
| Incoming BLS verification | 1,886.479 ms |
| Spend-info commitment reconstruction | 166.180 ms |
| Witness signing and JSON construction | 832.368 ms |
| Output blinding | 400.463 ms |
| Output unblinding | 404.532 ms |
| Returned-proof BLS verification | 1,886.468 ms |
| Sum | **5,576.490 ms** |

These numbers come from the existing [device report](bench-nutroot-esp32c3.md). The two verification calls occupy 67.7% of this recorded sum. Improving only those calls by 2× would reduce the sum to approximately 3.69 s, before correcting the benchmark or accounting for omitted production work. This is an Amdahl-law calculation, not a forecast.

The benchmark requires the following corrections before it becomes a current-protocol baseline:

1. **It signs twice.** In `bench_recv_v3()`, the timed signing loop calls `nutroot_sign_digest()`, then calls `wit_keypath_json()`. The latter calls `sig_hex_for()`, which calls `nutroot_sign_digest()` again. Each signing helper also creates a keypair. Together with `nutroot_tweak_seckey()`, this means five generator multiplications per input: one to reconstruct the internal key and two per signing invocation. A straightforward single-sign implementation needs three. Eliminating the extra call corrects the measurement; it is not evidence of a firmware optimization already deployed.
2. **It omits receiver-key derivation.** The “receiver-keyed” fixture starts with the internal secret key and public key already available. It does not time NUT-28 ECDH from the received ephemeral `E`, slot recovery, or production policy checking.
3. **It omits output secret-key generation.** Fresh output public keys are created in setup, outside the timer. Current Nutroot requires those points. Their cost belongs somewhere: foreground preparation or an explicitly measured precomputation pool.
4. **It uses the older transcript and limits.** Current per-input digests, disclosure leaves, and receive rules are not all represented. See the next section.
5. **Its scalar/workload coverage is narrow.** The swap fixtures use `r = 3`; the raw primitive benchmark also includes a full-width scalar. Production measurements should use deterministic full-width, independently derived blinding factors and a distribution of keys, signatures, and amounts.
6. **Its timing explanation overstates cache certainty.** This chip has a 16 KB flash cache. A stable repeated fixture does not establish absence of cache effects or adequate tail-latency sampling. Also, the production BLS comparison fixture uses short ASCII secrets such as `swap_in_0`; a 33-byte secret is not shorter than those. The 1.93 → 1.89 s difference cannot simply be credited to a shorter hash input.

The witness benchmark remains useful: it identifies approximately 19.7 ms per Schnorr verification, approximately 16 ms per public tweak, and a severe threshold-search multiplier. Preserve its original results as a historical comparison, then add corrected cases.

## Current BLS and Nutroot compatibility

The live GitHub API reports BLS PR **#371 still open against `main`**. Nutroot PR **#421 merged on September 10 into `bls-protocol`**, with merge commit `4fd8112fdd7dceb5ba2def1a460a884c82735c39`. This is staging-branch integration, not a completed merge of the entire stack to `main`. The reviewed Nutroot head is `a3f04b97154b036626d27ca437d75b348a6a4407`; the [provenance manifest](crypto-research/provenance.json) records both API snapshots. Search-index copies of the PR description were stale.[^2]

| Current requirement | Local benchmark / wallet gap |
|---|---|
| Version selects Nutroot rules; v3 secrets decode to 33 bytes | Benchmark detects point shape; production still uses the old secret-generation path |
| Plain transaction hash, then a tagged digest specific to each input | Local `Cashu_Transaction_v1` prefix and one shared signing digest |
| Leaf body ≤512 bytes; ≤8 tree leaves; witness path ≤3 siblings | Local 1024-byte body; up to 256 leaves; depth 8 |
| `disclosure` is a defined leaf field | Local parser rejects it |
| Spend info is carried and checked | No production `si` model/integration |

These are correctness gaps, not optional performance settings. The 64- and 256-leaf sweeps characterize an earlier design, not currently admissible trees.[^3]

Current NUT-13 frames the keyset identifier and attempt counter, uses distinct derivation purposes, and derives an internal secp256k1 private key whose public key becomes the secret. Its proof counter is 64-bit. The current suite’s `derive_secret` returns the older HMAC bytes and exposes a 32-bit counter. Update derivation and recovery together; optimizing the older KDF would optimize an incompatible path.[^4]

NUT-28 introduces actual work absent from the synthetic receive row: ECDH and key matching. Reuse the shared secret within one proof and receiver key, then derive the necessary slots. Match candidate keys by value. Do not amortize by reusing the sender’s ephemeral across outputs; v3 requires a fresh ephemeral per output.[^5]

A useful migration boundary is a validated internal representation containing raw secret bytes, parsed mint keys, parsed signature points, spend-info commitments, and derived key material where available. Keep JSON/CBOR at transport and persistence boundaries. Select legacy versus Nutroot behavior from the resolved keyset version. Preserve the exact compressed secret, including parity, in commitments and cache keys.

## The ESP32-C3 execution model

The C3 has **one RV32IMC application CPU**, up to 160 MHz, with a four-stage in-order scalar pipeline according to the current TRM. It has 400 KB SRAM including 16 KB allocated to cache. It has no second application core, vector extension, floating-point unit, or dedicated BLS/secp256k1 engine. The RSA, SHA, and AES peripherals are separate hardware engines; they are the useful source of computation overlap.[^6]

The checked configuration already selects 160 MHz, disables dynamic power management, and runs flash in DIO at 80 MHz. Therefore “set the CPU to maximum frequency” is already done. A second FreeRTOS crypto task cannot provide a second CPU’s throughput; it adds scheduling and memory costs unless it overlaps genuine peripheral or network waits.

The RSA accelerator can perform modular arithmetic on lengths including the 384-bit BLS field, and raw multiplication up to 1536-bit inputs. The existing port uses exponentiation’s early-exit behavior to obtain a single Montgomery reduction. Ordinary RSA modular exponentiation is also worth testing for *base-field* fixed exponents. RSA is not directly an Fp12 exponentiation engine. GDMA’s documented peripheral connections do not include RSA, so a proposed RSA DMA path needs independent validation rather than an assumed driver switch.[^7]

The driver already preserves the modulus and zero exponent within an acquisition window and avoids rewriting operand A when it equals the previous result. It polls for completion. The earlier external benchmark measured approximately 6.4 μs for a chained multiply including I/O, with roughly 1.5 μs attributed to the arithmetic engine. Those figures motivate work on data movement; they do not measure this firmware’s current driver.[^1]

The source’s global `lock_held` flag is not an ownership check. Existing wallet serialization reduces exposure, but new asynchronous callers must not treat “someone holds the lock” as authorization to access the peripheral. Introduce a single owner or explicit task ownership before expanding concurrency. A timing improvement that corrupts an unrelated TLS bignum operation is unusable.

## New device-free evidence

The [host probe](crypto-research/run_host_probes.py) compiles this repository’s patched blst using its 32-bit limb representation, instruments the 384-bit Montgomery dispatch, and checks algebraic results. It exercises valid pairing products, a modified-message rejection, equality of MSM and sequential sums, and prepared versus ordinary Miller results. The SHA adapter exists only to let the suite run on the host. No host elapsed times are presented as C3 measurements.

### Stack allocation

Cross-compilation uses the existing ESP-IDF compile commands and GCC 14.2.0, adding `-fstack-usage`, with object outputs in a temporary directory.

| Library / caller configuration | Miller function frame | Verifier caller frame | Sum of these two frames |
|---|---:|---:|---:|
| Existing internal limit 16, caller chunk 4 | 10,128 B | 3,488 B | 13,616 B |
| Internal limit 4, caller chunk 4 | 3,216 B | 3,488 B | 6,704 B |
| Internal limit 11, caller chunk 11 | 7,248 B | 5,568 B | 12,816 B |

These are compiler-reported frames, not complete task high-water marks. Deeper arithmetic calls, other callers, interrupts, and future compiler changes still matter. However, the result is decisive: the public `blst_miller_loop_n()` uses **fixed arrays sized by `MILLER_LOOP_N_MAX`**, default 16. The nearby private helper uses VLAs, which appears to have confused the local commentary. Four-pair calls do not shrink the public function’s fixed arrays.

For the standard ten-proof case, eleven pairs include the folded signature side. Setting both capacities to eleven potentially permits all eleven pairs in one loop with a *smaller combined pair of frames than today*. Alternatively, setting the internal capacity to four immediately reclaims 6,912 bytes of frame space. Evaluate both before increasing task-stack reservations.

### Arithmetic experiments

Detailed results are in the [CSV files](crypto-research/). Counts exclude additions, inversion internals, hashing, memory traffic, and CPU/control overhead, so percentage count reductions are not wall-clock speedups.

| Experiment | 384-bit Montgomery calls |
|---|---:|
| Production verifier, ten distinct keys, caller chunks of 4 | 159,730 |
| Same fixture, chunks of 8 | 157,483 |
| Same fixture, one chunk of 11 | 155,236 |
| Eleven Miller pairs alone, chunks of 4 | 58,155 |
| Eleven Miller pairs alone, one chunk of 11 | 53,661 |
| Final exponentiation of the valid product | 7,735 |
| Prepare one G2 key’s line table | 1,750 |
| One ordinary Miller loop | 6,867 |
| One prepared Miller loop | 5,117 |

Each prepared-key table occupies **19,584 bytes**: 68 entries × three Fp2 coefficients × 96 bytes. Ten tables use 195,840 bytes; 64 use 1,253,376 bytes. A blanket “precompute every mint key in RAM” recommendation is inappropriate for this wallet.

The MSM probe also exposes a trap. Calling `blst_p1s_mult_pippenger()` for ten points normally selects a four-bit window-table implementation. It allocates a 7,680-byte affine table plus approximately 15,360 bytes of preparation scratch on the stack. The API’s reported 384-byte Pippenger scratch requirement does **not** describe that path’s peak memory. A forced bucket/Pippenger variant uses less memory and still saves arithmetic; the exact counts and tradeoffs are retained in separate CSV files.

Finally, batching affine conversions can help even when the multiplication count rises: ten individual conversions need ten inversions, while the batch uses one inversion and additional multiplies. The probe records 6 Montgomery calls for a single conversion and 69 for ten batched conversions. It deliberately does not turn that into “batch conversion is slower”—the removed software inversions are outside that counter.

## BLS optimization priorities

### 1. Preserve validated keys and locally computed points

Create a cache of canonical, subgroup-checked G2 affine keys keyed by the exact mint/keyset/amount binding and key bytes. Populate lazily, or during keyset refresh, and invalidate on a changed binding. A full set of 64 affine G2 points is 12,288 bytes before metadata; a small LRU can be cheaper. Keeping compressed bytes for transcripts is still necessary. The current keyset codec’s length/distinctness checks are not a substitute for G2 subgroup validation.

This removes repeated decompression and subgroup checking from warm receives, repeated incoming/outgoing key use, and later offline-queue draining. The probe's ten cold G2 validations account for 22,150 Montgomery calls—13.9% of its full verifier count—plus CPU work. The older standalone measurement suggests an order of 0.2 s per ten cold keys, but the actual current-device saving must be measured. Cold validation still has to occur once; background preparation moves it out of foreground latency.

The current blst subgroup checks already use curve endomorphisms and the short BLS parameter, rather than multiplying every point by the full subgroup order. Those fast tests are visible in `map_to_g1.c` and `map_to_g2.c`; importing a paper's headline improvement over full-order multiplication would overstate the remaining opportunity. Preserve each untrusted point's required validation. A randomized aggregate subgroup test needs a separate soundness analysis, especially for torsion components; it is not implied by the existing pairing-batch weights.

Carry `Y` from output generation into returned-proof verification. It is already computed by blinding. Likewise, retain the validated `C_` and locally generated `C` as internal point objects. Multiplication by a nonzero scalar preserves prime-subgroup membership and nonidentity. A combined unblind-and-verify path can exploit that invariant instead of serializing, decompressing, and repeating a full subgroup test. Check bytes again when importing untrusted data or reloading an untrusted representation; do not expose an external “already validated” flag.

These changes require a richer internal API, perhaps a `BlsOperationContext`, while retaining the simple suite interface for ordinary callers. Ten cached affine `Y` values are 960 bytes; projective values are 1,440 bytes. This is a much better first use of limited RAM than ten prepared pairing tables.

Another clean boundary is to verify returned blinded signatures against the retained blinded outputs: `e(C_, G2) = e(B_, K)`, then unblind the verified points. This equation is equivalent because the same nonzero `r` multiplies both sides. Bind each response to its exact requested `B_`, amount, and key, and derive batch coefficients from the complete appropriate transcript. This is an internal returned-signature check, not permission to change the protocol's incoming-proof transcript. It can preserve validation through unblinding without a second serialized-proof verification. Do not feed secret `r⁻¹`-weighted coefficients into a variable-time public MSM as a shortcut.

### 2. Aggregate the signature side with an MSM

Replace ten independent `w_i C_i` products and additions with a multi-scalar multiplication for `Σ w_i C_i`. The weights are public verification coefficients; a variable-time implementation is appropriate for this calculation. Keep constant-time scalar multiplication for secret blinding factors, unblinding factors, long-term keys, and signing nonces.

| Ten-point signature sum, same fixture and weights | Montgomery calls | Reduction versus independent products |
|---|---:|---:|
| Existing products plus sum | 19,934 | — |
| blst API’s default small-batch window path | 11,344 | 43.1% |
| Forced bucket/Pippenger path | 15,210 | 23.7% |

The first saving is attractive only with explicitly bounded scratch. A direct default-API substitution inside the current task could overflow its stack. Options are an explicit heap/arena-backed small-window implementation, a forced bucket path, or a custom Strauss/GLV implementation whose memory and arithmetic are tuned together. The current single-point blst path already uses GLV; account for that when comparing algorithms.

This optimization reduces one portion of verification. It does not remove all twenty scalar multiplications: with distinct `K_i`, each `w_i Y_i` remains a separate right-hand pairing argument. `e(ΣY_i, ΣK_i)` introduces cross terms and is not a valid shortcut.

### 3. Restore grouping where denominations repeat

Group the right side by **identical validated G2 key bytes**, computing `Σ w_i Y_i` for each group. This is useful for duplicate denominations, accumulated wallets, and some change patterns. It brings little benefit to the ten-distinct-key baseline but can remove many Miller pairs in other workloads.

A bounded implementation should not reintroduce the old “at most eight distinct keys” failure. Options include a small inline group map with overflow handling, grouping indices after the transcript is finalized, or a reusable workspace sized to the admitted batch. Preserve the original proof order for the Fiat–Shamir transcript; internal arithmetic may be reordered afterward using the already assigned weights.

Benchmark by both proof count `n` and distinct-key count `d`. A single “ten proofs” number hides the main pairing cost variable. Prefer coin selection minimizing a calibrated combination of proof count, distinct keys, fees, and change, rather than assuming any repeated-key shape is inherently better.

### 4. Use the right Miller capacity and workspace

The strongest small change is to coordinate the caller’s capacity and `MILLER_LOOP_N_MAX`. For ten distinct proofs, test capacity eleven first, including the folded left side. The arithmetic saving from current chunks is 4,494 field calls, 2.8% of the entire verifier’s count. The existing device observation of a roughly 75 ms benefit for capacity eight is historical support for the direction, not a precise prediction for eleven.

For general batch sizes, provide an explicit scratch/arena interface rather than growing every task stack. Keep one shared Fp12 accumulator, run line steps across as many keys as the workspace supports, and finish with one final exponentiation. Avoid multiplying an initial `1` accumulator by the first chunk when a direct assignment suffices. That last change is small and should not distract from capacity and cache work.

If using a single crypto worker, a statically allocated workspace can be reused across operations. If multiple callers remain, make the workspace ownership explicit. Never turn stack arrays into unsynchronized globals just to reduce the reported stack usage.

### 5. Prepare pairing lines selectively

Precompute the fixed G2 generator’s lines once; they are public and constant across the wallet. Then consider one or two hot mint-key tables, rather than every key. The probe saves 1,750 Montgomery calls per prepared pairing—the G2 line-generation work—while line evaluation and Fp12 accumulation remain.

Prepared tables must participate in a **shared multi-Miller schedule** to retain accumulator-squaring savings. Eleven separate calls to `blst_miller_loop_lines()` would repeat those squarings. On the probe, eleven prepared standalone loops need about 56,287 calls before product accumulation, versus 53,661 for one *unprepared* eleven-pair loop. “Prepared” does not automatically mean faster at the batch level.

Store generator lines as a generated read-only asset, bound to the exact field representation and library version. For mint-key tables, evaluate an LRU and idle-time generation. Persisting all 64 tables would consume approximately 1.2 MiB per keyset, before application code or other mints; flash bandwidth and the partition layout then become important. A table supplied by an external party must be authenticated or recomputed against the validated key.

An exploratory compression direction is normalizing line coefficients by a nonzero Fp2 factor, whose contribution vanishes under the final exponentiation, and storing ratios. This could remove one of three coefficients in suitable cases. It requires a proof of the exact normalization, handling zero coefficients, and differential tests; it is not a safe serialization tweak to apply blindly.

### 6. Batch inversions and affine conversion

Batch-convert the weighted G1 points to affine before pairing. Batch-invert output blinding factors when unblinding a group: one inversion plus approximately `3(n−1)` multiplications replaces `n` inversions. Retain individual scalar validation and never include zero in the product.

The library already uses a constant-time Euclidean/safegcd-style path for ordinary Fp/Fr reciprocals, with a Fermat fallback for Fp. Do not assume every inversion is currently hundreds of exponentiation multiplies. Compare the actual RV32 inverse against batching and peripheral exponentiation. At ten points, batching is promising but lower priority than repeated-key validation and the driver.

## RSA/MPI and field-arithmetic work

### Driver changes with plausible broad benefit

The most promising driver improvement is a specialized BLS-field session with fixed modulus and mode. Currently every field multiply makes four HAL configuration calls and rewrites mode, constant-time control, search enable, and search position. The cross-compiled assembly confirms ordinary calls to these wrappers. For the 159,730-call probe, that is 638,920 repeated configuration calls/writes. Set these values once after obtaining exclusive ownership; reset the state after any operation that changes mode.

Replace the repeated modulus `memcmp` with a validated session invariant for the specialized 384-bit kernel. Keep a correct generic dispatch for other moduli and widths. Evaluate inlining the tiny start/wait/register helpers or selective LTO across the driver/HAL boundary. Inspect the generated assembly rather than assuming `-O3` inlines functions compiled in another component.

Operand caching needs a dataflow-aware design. The current driver compares all 48 bytes of operand A with a saved result, and reads/stores the entire result after every call. A specialized Fp2/Fp6 operation could keep intermediates resident where the hardware permits, swap commutative operands when useful, and avoid unnecessary readback. Start with squaring chains, sparse line products, and measured sequences with high reuse. The peripheral overwrites its X/Z state, so pointer equality alone is insufficient evidence of residency.

For secret-dependent operations, replacing comparisons and cache decisions must preserve the intended side-channel properties. The current `memcmp`-controlled operand-write optimization already needs such review. Separate public verification kernels from secret-scalar paths if an aggressive scheduling technique cannot meet both requirements. Do not replace the fixed-zero-exponent workaround with a secret exponent under variable-time hardware settings.

### Fixed-exponent hardware operations

The most concrete higher-level offload candidate is `recip_sqrt_fp_3mod4()`: it evaluates a fixed exponent used in decompression and hash-to-curve. Today its addition chain repeatedly crosses the peripheral boundary. A single hardware modular exponentiation could keep hundreds of intermediate operations on the accelerator. Convert Montgomery representations correctly and preserve the existing square/residue and sign-selection checks.

Also test a fused repeated-squaring driver for `sqr_n_mul_mont_383()`, which could reduce transfers without replacing the whole addition chain. Hardware inversion via exponent `p−2` is another candidate, but competes with the existing Euclidean inverse; it is not automatically faster.

These calls overwrite the exponent and mode used by the single-reduction trick. A correct session API must restore or invalidate all cached state afterward. Fixed public exponents make timing behavior easier to reason about, but secret base values still warrant review for observable operand-dependent behavior.

### Fp2/Fp6/Fp12 arithmetic and software kernels

Review the formulas against a cost model that prices MMIO, additions, reductions, scratch traffic, and multiplies separately. A desktop-optimized formula may cease to be optimal when the multiply engine is fast but operand movement is expensive. Candidates include fusing sparse line products, reducing intermediate copies, scheduling CPU additions while one multiply runs, and comparing Karatsuba against formulas with simpler dependency chains.

The `__FP2x2__` widened/lazy arithmetic path in `fp12_tower.c` is disabled under `__BLST_NO_ASM__`. Enabling it is a substantial port: some operations use raw wide products and software reduction, which would bypass the current accelerated Montgomery path. The earlier local fix to keep Fp2 squaring operands reduced demonstrates why lazy ranges cannot simply be restored. Prove bounds at every hardware call, including aliasing and subtraction cases.

For RV32 assembly, target measured software hotspots: limb add/subtract, carry propagation, field normalization, scalar arithmetic, and peripheral transfer loops. Use `mul`/`mulhu` and explicit carry handling where profitable. The C3 does not gain an instruction extension because a compiler accepts its name. A hand-written 32-bit full multiplication kernel must beat an already accelerated path; a smaller software kernel may still help Fr arithmetic and TLS contention.

A more speculative idea is packing independent polynomial coefficients into a wider raw RSA multiplication, then extracting cross-products for extension-field arithmetic. Wide I/O, coefficient carries, modular reduction, and the accelerator’s width-dependent execution time can erase the benefit. Treat this as a microbenchmark and algebra experiment after the simpler driver changes, not as parallel field multiplication already available in hardware.

### Code and data placement

Test QIO at 80 MHz if the board’s actual flash package and routing support it. It improves cache-fill bandwidth, not arithmetic throughput by a universal 2×. Move a measured hot set—driver, multiply helpers, and selected secp256k1 field routines—to IRAM, and selected constant tables to DRAM. IRAM consumes the same scarce memory budget needed by scratch and Wi-Fi.[^8]

Keep the recorded secp256k1 `-Os` result as the baseline. Evaluate code placement before repeating `-O2/-O3` experiments, and record text/rodata size and cache behavior together. blst is already `-O3`; its amalgamated translation unit already permits substantial inlining. LTO’s remaining benefit is most likely across the driver and application boundaries. GCC versus Clang is worth a controlled same-source comparison; the standalone Rust/Clang benchmark is not evidence that a language rewrite would improve this application.

The latest blst release checked is 0.3.17; this repository vendors 0.3.16. Its release notes include interface hardening and x86 `mulx_mont` carry-chain work, not a new RV32 assembly backend. Review the upstream delta and retain the local peripheral correctness tests, but assign no C3 speedup to the version bump without evidence.[^9]

### SHA and transcript construction

Enabling ESP-IDF hardware SHA does not accelerate every hash in this build. The batch transcript uses mbedTLS, while blst's hash-to-field and weight helper use its own SHA implementation, with a portable block function in `no_asm.h`. A hardware-backed blst SHA path is therefore a real experiment. Measure complete short-message and expand-message workloads, including locks, state loading, and transfers; a hardware engine can lose to software when setup dominates. Keep exact XMD padding and domain conventions. blst already precomputes the initial zero-padding block state, so that saving is not new.

For current Nutroot, compute the common transaction digest once, cache each input-container digest, and derive each input's tagged digest from those values. Do not reserialize and hash the full transaction separately for every signature. Parsed binary TLV fields can feed hashes directly while retaining canonical ordering and lengths. Reusing public tagged-hash midstates and protected HMAC inner/outer states can reduce repeated blocks. These are secondary opportunities after field arithmetic and unnecessary ECC operations; they should never change the transcript bytes.

## Nutroot optimizations

### Threshold verification: avoid searching every pairing of key and signature

The local verifier loops over every leaf key, tries signatures until a match, and continues to later keys even after the threshold has been satisfied. For signatures belonging to the first `n` of `m` keys, this produces

```
checks = n(n+1)/2 + (m−n)n
```

That explains the recorded 5 checks for 2-of-3, 30 for 5-of-8, and 92 for 8-of-15. The cost is largely failed signature-to-key matching, not intrinsic multisignature complexity.

The host probe compiles the existing Nutroot core and compares two small experimental changes. These are well-formed test cases, not a complete parser-equivalence audit:

| 8-of-15 fixture | Existing loop | Stop once threshold satisfied | Try first eight ordered pairs, then existing fallback |
|---|---:|---:|---:|
| Eight signatures in matching key order | 92 | 36 | **8** |
| Same signatures reversed | 92 | 36 | 93 |
| Eighth signature missing | 84, reject | 84, reject | 84, reject |
| Eighth entry duplicates first | 84, reject | 84, reject | 92, reject |

The useful production design combines the ideas: parse and validate structure first, decode signatures once, reject duplicate-x leaf keys, try likely pairs, cache attempted pair results, and stop once enough **distinct keys** have valid signatures. If a proposed mapping fails, fall back to a complete matching procedure. A sender-controlled signature order or optional hint is an optimization hint, never authority to select a signer without verifying it.

Pre-validating mandatory syntax matters. A fast return must not bypass malformed trailing fields or accept an otherwise invalid witness. Preserve the rule about distinct satisfied keys; do not count signature entries, and do not silently strengthen the rule to require every submitted signature to verify. An early impossibility bound can reject once the remaining keys cannot reach the threshold.

Using the recorded per-verification costs only as a scale estimate, the old 1.73-second 8-of-15 case could plausibly fall to roughly **0.65–0.75 s** with simple early success, or **0.17–0.20 s** when the eight candidate pairs are right. These are fixture-dependent estimates, not new C3 timings. Incorrect ordering retains the fallback cost; bounded memoization avoids repeating failed attempts. Benchmark unfavorable ordering, outsiders, malformed entries, and failures as seriously as the favorable case.

### Batch Schnorr signatures and commitment equations

After selecting the signatures that satisfy each leaf, batch their BIP340 equations:

```
(Σ a_i s_i) G = Σ a_i R_i + Σ a_i e_i P_i
```

Every `e_i` uses that input’s actual digest. Different input digests are fully compatible with batch verification; they prevent reusing one signature across inputs. Use coefficients derived securely from the complete immutable batch, enforce BIP340 range/lift/parity rules, and reject or fall back on failure. BIP340 describes a concrete batch construction.[^10]

Do **not** batch the entire key/signature search matrix: most of those equations are intentionally false. First try a candidate assignment, then batch only candidate valid equations. For a failed speculative assignment, use bounded individual checks to recover the correct matching. This is most useful for multiple key-path inputs or thresholds whose signer assignments are known.

The vendored secp256k1 exposes individual Schnorr verification, not a supported batch API. Upstream PR #1134 remains open in the checked API snapshot. Its historical reported gains are evidence of the technique, not C3 measurements or an API already available in this project.[^11]

Commitment checks can also be batched. For each full compressed-point commitment, let `D_i = P_i − K_i − t_i G`; verify a securely weighted sum of residuals is zero. This shares the generator work and may combine with a general verification-equation engine. Bind all full points and scalars into the coefficient derivation. Independently validate each point and every leaf/policy condition first, and account for failed-batch handling. This is a custom cryptographic implementation requiring differential tests and review.

### Reuse keypairs and fix the signing path

Once a received proof’s spending scalar and tweak have been established, retain the internal key, tweak, and signing keypair for its subsequent sweep. Avoid reconstructing the same public key from the private scalar at every layer. Serialize the signature already produced instead of asking the JSON helper to sign again.

The historical 832 ms row cannot simply be halved: it contains five generator multiplications per input, and only two belong to the duplicate signing call. A rough equal-generator-cost decomposition attributes about two fifths of this row to that duplication. This is a diagnostic explanation, not a replacement timing. A reusable final keypair can remove further recomputation, but current receiver ECDH and output-key generation must be added back to the full operation’s cost.

Nutroot tweaks the **full compressed internal key**, not a Bitcoin x-only key. A generic x-only keypair-tweak API can normalize parity differently. Preserve the proposal’s scalar and point rules when building the cached keypair. Do not optimize signing by reusing nonces; deterministic BIP340 signing still binds the message, and any nonce precomputation scheme needs its own correct one-use protocol.

### Tune the actual secp256k1 implementation

The project defines `ECMULT_GEN_PREC_BITS=4`, but the vendored revision (`v0.7.1-38-gac56160`) no longer uses that parameter. [ecmult_gen.h](../components/secp256k1/libsecp256k1/src/ecmult_gen.h) defaults to `COMB_BLOCKS=11`, `COMB_TEETH=6`, a 22 KiB generator table. Its available generated configurations include approximately 2, 22, and 86 KiB tables. Change the real comb parameters and the matching generated table, not the stale macro.

Sweep the 2/22/86 KiB configurations with their actual flash/DRAM placements. The largest table is not necessarily best on this chip. Also sweep `ECMULT_WINDOW_SIZE` around the current 8 for public verification and compare total code/table working sets. Keep secret-scalar table access constant-time; a specialized direct-index table can be considered for **public** tweak scalars, with a separate API that cannot accidentally receive secret material.

The implementation already has endomorphism splitting, joint multiplication, optimized secp256k1 field arithmetic, and safegcd inverses. Those are baselines, not missing techniques. A 256-bit RSA Montgomery backend for secp256k1 is an experiment rather than an obvious improvement: its field uses a favorable pseudo-Mersenne prime and 10×26-bit software limbs on RV32, so representation conversion, reduction, and peripheral contention must be included in the comparison.

### NUT-28, policy checks, and choosing the spending path

Try the receiver’s internal-key slot first when the transfer shape permits key-path spending. Compute ECDH once per `(E, receiver key)` within a proof; cache the matching slot and derived result for later signing. When script-key recovery is needed, use value-indexed lookup against parsed leaf keys. Verified slot hints from a signing package can avoid a scan, with a complete value-matching fallback when a hint is wrong.[^5]

This can become a substantial new bottleneck. Even with eight leaves, recovering many candidate slots means many secp256k1 generator operations. A fixture that starts with every internal key already known cannot estimate that cost. Include worst-case “no matching receiver key” scans in the new benchmark, not just successful slot-zero transfers.

Prefer a key-path spend when it satisfies the intended ownership and policy. A cooperative aggregate key can keep common-path verification at one ordinary Schnorr signature. MuSig2 is an **n-of-n** cooperative scheme, not general t-of-n threshold signing. A threshold alternative must specifically produce BIP340-compatible signatures; generic FROST compatibility should not be assumed. Coordination and nonce-state costs move to the signers, and fallback script leaves may still be needed.[^12]

Aggregation changes how a lock is constructed and cooperatively spent; it is not something a receiver can unilaterally apply to arbitrary existing threshold proofs. Likewise, the current normative tree fold prevents choosing an arbitrary Huffman-shaped tree to shorten a favorite leaf’s path. Merkle hashing is already a small cost, and current tree limits make it even less important. Cache tagged-hash constants or midstates after the larger ECC savings are addressed.

## Workflow and architecture changes

### Distinguish authenticity, spendability, and settlement

A valid BLS signature establishes mint authenticity. Nutroot validation establishes that the holder can exercise a path under the disclosed conditions. Neither offline computation proves the token has not already been spent at the mint. An optimized offline path must preserve these distinctions in stored state and user-visible completion.

For offline NFC, verify signature authenticity and relevant Nutroot ownership/policy before treating the payment as accepted under the wallet’s offline policy. Defer the mint swap until connectivity returns. Store the verified proof identity and spend information durably; caching a verification result avoids repeating immutable signature work when draining the queue, but does not replace the mint’s current spent-state check.

For an immediate online swap, a separate mode can omit the **incoming** local BLS pairing check and accept payment only after a successful swap and validation of the returned proofs. The current proposal recommends incoming pairing verification, while acknowledging implicit spendability checking through immediate sweeping.[^3] This changes the verification policy and request timing; it is not an algebraic acceleration. It can remove approximately 1.89 s from the historical modeled foreground flow, but may send doomed requests to the mint and provides no offline acceptance result. Keep it explicit and do not apply it as a blanket skip to offline receive.

### Prepare work before the tap

Precompute fresh output allocations during idle time: seed-derived secret keypairs, `Y`, `r`, `r⁻¹`, and `B_`, tied to a known active keyset and reserved counter. Within a keyset, the blinded secret can be prepared before its amount is assigned. Recheck active-keyset/amount availability before use. This removes output generation from the foreground but does not reduce total computation.

Reserve counters durably before making a precomputed allocation usable, and handle power loss without secret reuse. Do not turn a pool into repeated `r`, repeated `E`, or repeated secrets. Keep recovery’s gap limits and discarded allocations in the design. Persist only what is justified; regenerable data may be cheaper and safer to reconstruct than to write repeatedly to flash.

Prepare validated mint keys and likely public tables while idle. Continue using the existing HTTP connection reuse and NFC-triggered prewarming. Overlap network waits with independent output preparation where memory permits. Nutroot signing depends on the final output transcript, so the final signatures cannot be completed before the outputs are fixed.

### Use one crypto owner with cooperative scheduling

The firmware currently has large stacks for console, NFC, and Wi-Fi drain paths, all of which may participate in wallet work. A single worker can own the RSA session and a reusable crypto arena; other tasks submit bounded jobs and receive results. This does not add compute throughput, but can reduce duplicated worst-case stack reservations and simplify peripheral ownership.

Break long verification jobs at safe points so NFC, Wi-Fi, UI, and the idle watchdog can run. A `taskYIELD()` alone does not guarantee that a lower-priority idle task runs; use the intended scheduling mechanism and measure its effect. Release/reacquire RSA at deliberate boundaries if TLS needs it, invalidating resident state correctly. Never call HTTP/TLS while holding the nonrecursive RSA lock.

Do not put a task switch or interrupt-driven completion around each roughly microsecond-scale field operation. Its overhead can exceed the work. Instead, overlap CPU additions or independent preparation inside a fused arithmetic kernel, or schedule at proof/chunk boundaries. The core and bus remain shared; a DMA engine does not create free bandwidth.

Streaming or tightly bounded parsing also matters because memory fragmentation already caused a recorded `std::bad_alloc` when loading a roughly 27 KB v3 keyset response. Reserve batch arrays once, avoid repeated compressed-key hex copies, release HTTP/JSON buffers before allocating cryptographic scratch, and measure the largest contiguous free block. Memory stability is a prerequisite for larger batches and caches.

### Reduce the amount of cryptography requested

Select inputs and outputs with an explicit cost model including `n`, `d`, change, and input fees. Consolidate accumulated proofs while idle if fees and privacy policy allow. A mint that already supports an exact amount can sometimes reduce a multi-proof payment to one proof. Arbitrary new denominations require mint cooperation and new independent keys; they are not a local wallet optimization.

Do not make all denominations share a mint key, or derive denomination keys by publicly known scalar multiples. That would permit changing a signature into one for a different amount. Do not shrink Fiat–Shamir coefficients, reuse blinding factors, replace RFC 9380 hashing with `H(secret)·G`, or drop cofactor checks to hit a latency target. Those changes alter the security construction, and the first several are directly unsafe.

Batch failure handling should remain bounded. For an incoming invalid token, rejecting the batch is often sufficient; automatically performing all individual pairing checks afterward creates an expensive denial-of-service path. If diagnostics require isolation, use limited bisection or background work. Admit a bounded number of proofs/bytes based on both the protocol and available resources, and distinguish resource exhaustion from cryptographic invalidity.

## More aggressive alternatives

### Different hardware

| Candidate | Relevant architectural difference | What it does not establish |
|---|---|---|
| ESP32-S3 | Two Xtensa LX7 application cores up to 240 MHz, 512 KB SRAM, external RAM options | Neither two cores nor SIMD automatically doubles this RSA-bound port; the peripheral is shared and RV32-specific work needs porting |
| ESP32-C6 | One high-performance core up to 160 MHz and a separate low-power core up to 20 MHz; larger memory/cache than C3 | It is not two symmetric application cores; its P-192/P-256 ECC accelerator does not implement either required curve |
| ESP32-P4 | Two high-performance RISC-V cores up to 400 MHz and substantially more on-chip memory | Its NIST P-192/P-256/P-384 ECC support is not secp256k1 or BLS12-381 support; board, networking, power, and cost require a new design |

These are datasheet capabilities, not measured Cashu rankings.[^13][^14][^15] If changing boards, benchmark the complete crypto stack before selection. On a dual-core device, one core could handle secp256k1/policy preparation while another owns the BLS accelerator; two simultaneous MPI streams still contend. Pairing kernels using software multiplication may instead parallelize independently, but must beat the hardware-assisted alternative including synchronization and memory costs. External RAM is useful for cold tables and parsing buffers; its latency makes it an uncertain home for the hottest field scratch.

A dedicated pairing accelerator is technically credible: published BLS12-381 ASIC research implements the relevant arithmetic hierarchy.[^16] It is a custom-hardware direction, not an available C3 firmware switch or a demonstrated inexpensive module. An FPGA/companion processor can also move the boundary, but communication, verification of its results, trust, power, and bill of materials become part of the comparison. A secure element offering an unrelated curve is not a substitute for the required operations.

### Delegation and verification certificates

Trusted phone or server assistance can remove local pairing work, at the price of trusting that party's authenticity verdict. Nutroot's point-shaped secret does not make all transfer metadata public: delegation can reveal holdings, mint relationships, and payment correlations. Never send private spend scalars, blinding factors, or unnecessary witnesses merely to outsource a public pairing calculation.

Untrusted delegation needs a cryptographic verification protocol. The recent pairing-delegation literature distinguishes substantial setup/precomputation and privacy assumptions; one cannot safely replace a pairing with an unauthenticated returned target-group value.[^17] This is worth a separate research prototype if local independent verification remains mandatory and a helper is already available. Include setup amortization, communications, soundness, malicious helpers, and token privacy in the measured result.

Likewise, a certificate that replaces final exponentiation addresses only the final exponentiation. That phase is already shared, and accounts for 7,735 of the probe's 159,730 Montgomery calls, about 4.8%, before considering witness verification. A technique valuable in a proof system can be irrelevant to C3 wall time. Prioritize certificates only if they also replace substantial Miller or input-validation work under an appropriate security model.

### Protocol extensions

One exploratory mint-assisted alternative is publishing a companion G1 key `A = aG1`, verifying its relation to the existing `K = aG2` once, and using a discrete-log-equality proof for subsequent signatures. This trades repeated pairings for secp-style group equations on BLS G1, extra bytes, proof handling, and changes to issuance and transfer formats. A proof attached to a blinded response is not automatically a portable proof for every later holder. Blinding compatibility, transferability, offline verification, and privacy need a full construction and security review. This is not a compatible local optimization of the proposal.

Changing the pairing curve, hash suite, or signature group also requires protocol coordination. BLS12-381's field size and security parameters are not interchangeable with a smaller curve chosen for speed. The current hash-to-curve construction has specific domain-separation, mapping, and cofactor requirements.[^18] Retain those while optimizing its implementation. Benchmark an alternative library or language only after reproducing the exact suite, validation rules, and hardware backend; an implementation that omits them is not a performance win on the same task.

## Quantitative expectations and implementation order

The current evidence supports substantial improvements, but not a trustworthy universal multiplier. In particular, ten distinct-key verification below 100 ms would need roughly a 19× improvement over the recorded row. Nothing measured or counted here establishes such an improvement on unchanged C3 hardware. Sub-second verification is a worthwhile stretch target; it remains conditional on the driver profile and how much work can be cached or moved earlier.

The [workbook](crypto-research/performance-model.xlsx) separates observations from assumptions. Its single-verification model is:

```
T_new = T_baseline × [(1 − f) + f × (1 − r) / s]

f = measured baseline time fraction attributable to the affected field kernel
r = fraction of that kernel's calls removed by algorithm changes
s = speedup of each remaining kernel call
```

We do not yet know `f`. Operation counts alone cannot supply it. As an illustration, warm G2 validation, the eleven-pair loop, and the forced bucket MSM remove `(22,150 + 4,494 + 4,724) / 159,730 ≈ 19.6%` of counted calls in their respective components. Rounding this to `r = 20%` produces the following sensitivity table. This combination is an accounting exercise, not a tested integrated firmware variant; it also omits non-kernel savings and changed memory costs.

| Assumed field-kernel share `f` | 20% fewer calls, same kernel | Also 1.5× faster kernel | Also 2× faster kernel |
|---|---:|---:|---:|
| 50% | 1.698 s | 1.446 s | 1.321 s |
| 70% | 1.622 s | 1.270 s | 1.094 s |
| 85% | 1.566 s | 1.138 s | 0.924 s |

Each row starts from the historical **1.886479 s** verification. These are conditional calculations, not predicted current-Nutroot operation times. Larger savings require additional changes such as eliminating output revalidation, faster fixed exponents, prepared shared loops, or different workloads. Do not multiply advertised percentage improvements together: several target the same work, and precomputation shifts costs between cold and warm paths.

| Priority | Work package | Evidence / expected impact | Main constraint |
|---|---|---|---|
| 0 | Current Nutroot semantics and corrected benchmark | Removes a duplicate signing measurement and exposes real ECDH/output preparation costs | Required before claiming protocol-level improvement |
| 1 | Validated key/point context; returned-signature verification; bounded parsing | Removes concrete repeated validation, hashing, and serialization | Cache provenance and exact key/output binding |
| 1 | Coordinate Miller capacity and shared scratch; explicit RSA owner | Cross-compiler confirms smaller frames can support more pairs | Full task high-water mark and concurrency still need hardware checks |
| 1 | Threshold early success, candidate matching, cached decoding/keypairs | Host verifies 92 → 36 checks; favorable mapping needs eight | Malformed inputs, arbitrary signature order, policy equivalence |
| 2 | Fixed-mode MPI session, MMIO/inlining, fused exponent/squaring experiments | Affects a very large number of repeated calls | Actual cycle profile and peripheral correctness |
| 2 | Bounded small-batch MSM; repeated-key grouping; batch conversions | Host counts demonstrate arithmetic savings | Memory, distinct-key distribution, public/secret API separation |
| 2 | Idle output pool, durable counters, cost-aware coin selection | Can remove entire foreground phases or reduce proof count | Total work persists; recovery, fees, and privacy matter |
| 3 | Shared prepared Miller loops, public Schnorr batching, comb/table placement | Plausible additional gains | More implementation/review effort and RAM pressure |
| 4 | Wide-arithmetic reformulation, delegated verification, protocol/hardware changes | Potentially larger changes to the cost structure | Separate research and, where applicable, interoperability work |

Treat peak memory, worst-case failure time, and energy per accepted payment as co-equal acceptance criteria with median latency. A faster average that exhausts heap with Wi-Fi active or makes malformed proofs monopolize the wallet is not a successful implementation.

## Verification and measurement plan

### Work that can be completed without a device

1. Pin current BLS/Nutroot specification revisions and add their canonical vectors before porting semantics. Cover version routing, hex decoding and parity, per-input digest uniqueness, exact TLV framing, disclosure, current size/depth limits, seed/counter recovery, full-key tweaks, NUMS proofs, NUT-28 slots, and spend-info transport. Include mixed keysets and outputs, reordered inputs, and duplicate `Y` handling.
2. Introduce explicit validated types and operation lifetimes, then compare the old and new BLS paths on deterministic full-width fixtures. Include zero/identity, noncanonical encodings, off-curve and wrong-subgroup points, wrong keys, tampered secrets, batch cancellation attempts, repeated denominations, and maximum admitted batches. An internal validation cache must not be forgeable through imported tokens.
3. Differential-test custom arithmetic against unmodified software blst using random and boundary operands, including `0`, `1`, `p−1`, carry chains, aliasing, modulus transitions, and exponent/session restoration. Host simulation proves arithmetic relationships, not RSA register timing or electrical behavior.
4. For threshold changes, exhaust small key/signature assignment cases, then fuzz malformed witnesses and parser boundaries under sanitizers. Establish unchanged acceptance for reordered signatures, duplicate signatures, duplicate-x keys, irrelevant valid signatures, unsatisfied locks, and disclosure leaves. The included four-fixture probe is an initial check, not this complete suite.
5. Cross-compile candidate kernels with the same target flags; retain stack-usage reports, link maps, symbol sizes, and disassembly. Confirm no unbounded library `alloca` appears beneath an apparently small scratch API. Compile a full firmware image before any eventual device trial.

### First device session

Use a staged matrix so each measurement answers a question rather than running an enormous undirected sweep:

| Stage | Cases | Record |
|---|---|---|
| Corrected baseline | 1, 2, 4, 8, 10, and maximum admitted proofs; distinct and repeated keys; valid and rejected inputs | Phase times, `n`, `d`, fixture digest, exact commit/toolchain/config |
| Peripheral profile | Software reference and current hardware; unchained/chained multiply, square, Fp2, square-root exponent, inverse, sparse line product | CPU cycles in setup, operand writes, wait, readback, and surrounding code; counts of avoided transfers |
| Memory/cache | Cold and warm key caches; current chunk 4 versus coordinated 4 and 11; bounded MSM; selected IRAM/DRAM and comb sizes | Stack high-water marks, free heap, largest block, text/rodata/IRAM/DRAM sizes, latency distribution |
| Nutroot | Bearer and receiver-keyed; slot zero and late/no match; key path; 2-of-3 and 8-of-15; favorable/adversarial signature order | Parse, derive, commit, sign, match, verify, serialize times |
| Integrated receive | Real NFC and HTTP/TLS; Wi-Fi idle/active; fresh/reused connection; cold/warm output pool | Tap time, local acceptance, settled completion, watchdog/scheduler behavior, energy |
| Failure/recovery | Invalid batches, TLS contention, keyset rotation, cancellation, power interruption during pool reservation and swap | Correctness, bounded failure time, no secret/counter reuse, durable state |

Read the C3 cycle counter around sufficiently long regions, subtract calibrated measurement overhead, and accumulate counters instead of logging every field call. Instrumenting a roughly microsecond operation with printing would measure the logger. Report medians and upper percentiles over enough repetitions to estimate variance, with sample count, warmup, and cache state explicit. Keep a no-instrumentation end-to-end build to quantify profiling perturbation.

Use the ordinary supported 160 MHz configuration first. Re-test finalists under realistic radio/network activity and any intended power-management settings. Unsupported overclocking is not a default optimization: it creates a new timing, power, and reliability envelope. The hardware accelerator's effective clocking must be established separately; CPU frequency ratios alone cannot scale its timings.

## Reproducibility and scope

The [probe README](crypto-research/README.md) describes dependencies and commands. The included host probes passed their valid/invalid comparisons for all recorded variants. RV32 compilation produced the stack figures above. No device was connected, no new on-device timing was measured, and no production firmware sources were changed by this assessment. The pre-existing Nutroot work and historical benchmark remain intact.

The recommended first implementation is a corrected, current-proposal benchmark plus a validated operation context and coordinated pairing workspace. Follow that with measured MPI session improvements and the bounded threshold matcher. Those changes have identifiable mechanisms and tests; the resulting hardware profile will determine whether prepared pairing tables, custom batching, or a different board deserve the next investment.

## Primary sources

Repository statements above refer to the linked local sources and the commits in the inventory. External sources were checked on September 13, 2026. Proposal snapshots are pinned because the overall BLS change remains in progress.

[^1]: [zeugmaster/bls-bench, RESULTS.md](https://github.com/zeugmaster/bls-bench/blob/main/RESULTS.md). Earlier standalone firmware measurements; not this application's current timings.
[^2]: [Cashu BLS PR #371](https://github.com/cashubtc/nuts/pull/371) and [Nutroot PR #421](https://github.com/cashubtc/nuts/pull/421), with live state checked through [PR 371 API](https://api.github.com/repos/cashubtc/nuts/pulls/371) and [PR 421 API](https://api.github.com/repos/cashubtc/nuts/pulls/421). See the local provenance manifest for exact states and hashes.
[^3]: Nutroot snapshot `a3f04b97154b036626d27ca437d75b348a6a4407`: [NUT-10](https://github.com/robwoodgate/nuts/blob/a3f04b97154b036626d27ca437d75b348a6a4407/10.md), [NUT-00](https://github.com/robwoodgate/nuts/blob/a3f04b97154b036626d27ca437d75b348a6a4407/00.md), and [NUT-18](https://github.com/robwoodgate/nuts/blob/a3f04b97154b036626d27ca437d75b348a6a4407/18.md). Rules discussed here apply to this proposal snapshot.
[^4]: [Current-proposal NUT-13](https://github.com/robwoodgate/nuts/blob/a3f04b97154b036626d27ca437d75b348a6a4407/13.md), deterministic key and scalar derivation.
[^5]: [Current-proposal NUT-28](https://github.com/robwoodgate/nuts/blob/a3f04b97154b036626d27ca437d75b348a6a4407/28.md), receiver-keyed derivation and slot matching.
[^6]: Espressif, [ESP32-C3 datasheet](https://documentation.espressif.com/esp32-c3_datasheet_en.html), version 2.4, and [technical reference manual](https://www.espressif.com/sites/default/files/documentation/esp32-c3_technical_reference_manual_en.pdf), version 1.4, CPU chapter. The latter specifies the four-stage pipeline.
[^7]: Espressif, [ESP32-C3 TRM](https://www.espressif.com/sites/default/files/documentation/esp32-c3_technical_reference_manual_en.pdf), RSA and GDMA chapters; ESP-IDF 5.5.1 [C3 MPI register helpers](https://github.com/espressif/esp-idf/blob/v5.5.1/components/hal/esp32c3/include/hal/mpi_ll.h) and [MPI HAL](https://github.com/espressif/esp-idf/blob/v5.5.1/components/hal/mpi_hal.c).
[^8]: Espressif, [ESP-IDF 5.5.1 C3 speed optimization guide](https://docs.espressif.com/projects/esp-idf/en/v5.5.1/esp32c3/api-guides/performance/speed.html), cache, flash, optimization, and memory-placement guidance.
[^9]: Supranational, [blst v0.3.17 release](https://github.com/supranational/blst/releases/tag/v0.3.17). This project's port and vendored sources remain the authority for its current behavior.
[^10]: Bitcoin BIPs, [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki), individual and batch Schnorr verification.
[^11]: bitcoin-core/secp256k1, [batch Schnorr verification PR #1134](https://github.com/bitcoin-core/secp256k1/pull/1134), checked open; its performance discussion is not a C3 benchmark.
[^12]: Bitcoin BIPs, [BIP327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki), MuSig2.
[^13]: Espressif, [ESP32-S3 datasheet](https://www.espressif.com/sites/default/files/documentation/esp32-s3_datasheet_en.pdf), version 2.2, CPU/memory and security features.
[^14]: Espressif, [ESP32-C6 datasheet](https://documentation.espressif.com/esp32-c6_datasheet_en.html) and [PDF](https://www.espressif.com/sites/default/files/documentation/esp32-c6_datasheet_en.pdf), CPU/memory and ECC features.
[^15]: Espressif, [ESP32-P4 datasheet](https://www.espressif.com/sites/default/files/documentation/esp32-p4_datasheet_en.pdf), version 0.7, CPU/memory and ECC features.
[^16]: [A Low-Power BLS12-381 Pairing Crypto-Processor for Internet-of-Things Security Applications](https://arxiv.org/abs/2201.07496), hardware research paper, 2022.
[^17]: Adrián Pérez Keilty, [Delegating Bilinear Pairings: Systematization, Amortized Efficiency, and Future Directions](https://research.chalmers.se/publication/551401/file/551401_Fulltext.pdf), Chalmers thesis, 2026. Research direction; no claim of a deployed C3 solution.
[^18]: IETF, [RFC 9380: Hashing to Elliptic Curves](https://www.rfc-editor.org/rfc/rfc9380.html), especially the BLS12-381 suites. The proposal selects the exact suite/domain conventions.
