# ESP32-C3 Cashu cryptography: implementation and hardware results

This is the hardware follow-up to the [device-free investigation](crypto-optimization-esp32c3.md). The experiments use the actual connected ESP32-C3 and synthetic proofs. The earlier report contains the branch inventory, protocol equations, historical measurements, source references, and alternative hardware/protocol analysis. This report records what was implemented, what survived measurement, and what did not.

The campaign started on September 15, 2026 from `feat/keyset-v3`, commit `85ac407659e271db0e95bb6293f406cbf54ab564`, including the user's existing uncommitted Nutroot files. Those edits were preserved. See the [experiment ledger](crypto-research/device-optimization-plan.md) and [curated logs and build manifests](crypto-research/device-results/). Each numbered build is an experiment, not necessarily a recommended configuration.

## Measured results

The selected firmware is **52-final**. These numbers come from the connected board, not the earlier operation-count model. Times are elapsed cryptographic work; network transport is excluded. A smaller time is better.

| Operation | Earlier measurement | Selected implementation | Interpretation |
|---|---:|---:|---|
| BLS verification, ten proofs / ten keys, empty software caches | 1,886 ms | 1,224 ms | **1.54× faster**, about 35% less time |
| Same historical BLS suite, repeated proofs | 1,886 ms | 960 ms | **1.97× faster**, including validated-key and hash-point reuse |
| Historical ten-proof swap crypto fixture | 4,578 ms | 2,520 ms | **1.82× faster**, about 45% less time; a repeated synthetic fixture |
| Legacy Cashu DLEQ | 56.95 ms | 21.30 ms | **2.67× faster**; joint public scalar multiplication plus platform tuning |
| Nutroot 8-of-15 threshold fixture | 1,734 ms | 138 ms | **12.56× faster** for the ordered fixture; most gain is avoiding unnecessary checks |
| Raw Schnorr verification | 17.79 ms | 15.50 ms | **1.15× faster**; this is the arithmetic gain without threshold search savings |

Sources: original BLS/legacy [00](crypto-research/device-results/00-original.log), original threshold/secp [04](crypto-research/device-results/04-secp-baseline.log), final legacy/threshold [50](crypto-research/device-results/50-final.log), final BLS [52](crypto-research/device-results/52-final.log). The original verifier had no software verification caches. The optimized cold BLS row is one sample; the historical repeated suite averages two. The threshold rows average three and raw Schnorr eight. The 8-of-15 fixture uses the historical transaction wrapper; it is a controlled comparison of threshold evaluation, not a complete current-proposal receive. Shuffled/adversarial signature order can require fallback search and will not have the ordered fixture's speedup.

The current-proposal fixture separates the cache states that matter in a wallet. It uses ten distinct mint keys, 33-byte compressed point secrets, full-width blinding factors, and fresh receiver ephemeral keys:

| Current-proposal operation, ten proofs unless indicated | Mean (ms) | Samples | Min–max (ms) |
|---|---:|---:|---:|
| BLS verification, all software caches empty | 1,227.0 | 1 | 1,227.0 |
| BLS verification, known mint keys but fresh hash points | **1,075.1** | 3 | 1,075.0–1,075.1 |
| BLS verification, repeated proofs and known keys | **961.5** | 4 | 961.3–962.1 |
| Receiver recovery and signing, separate key setup | 639.2 | 3 | 639.0–639.4 |
| Receiver recovery and signing, retained keypairs | **444.8** | 3 | 444.0–445.9 |
| Current per-input witness verification | 141.0 | 3 | 140.8–141.3 |
| Public commitment equations, individually | 116.0 | 3 | 115.7–116.4 |
| Public commitment equations, batch API | **82.8** | 3 | 82.8–82.9 |
| Blind fresh secrets | 322.0 | 1 | 322.0 |
| Blind the same cached secrets again | 210.0 | 3 | 209.9–210.0 |
| Unblind then verify through separate APIs | 1,291.5 | 3 | 1,291.0–1,291.9 |
| Combined unblind and verify, retaining points | **1,177.1** | 3 | 1,176.8–1,177.7 |
| Prepare fresh bare outputs, including KDF | 410.2 | 3 | 410.1–410.2 |
| Read already prepared outputs | 0.014 | 3 | 0.013–0.018 |
| NUMS offset check, one | 9.75 | 5 | 9.71–9.88 |
| Receiver leaf-slot search reaching slot 120 | 1,034.5 | 2 | 1,034.0–1,035.0 |

All rows above are from [52-final](crypto-research/device-results/52-final.log). **About 1.08 seconds is the relevant ten-proof BLS figure for new proofs from a known mint; 0.96 seconds assumes the proof messages were previously hashed.** The preparation read is work moved out of the interaction, not a fresh-output generation time. The combined unblinding row already includes batch inversion; the separately printed “batch inverse” diagnostic does not represent another cumulative improvement.

### Proof count and denomination scaling

These measurements use the selected BLS settings. Each row has one cold sample, five repeated-proof samples, and a modified-proof rejection check. “Distinct keys” counts amount keys, not mint count. Software caches are cleared before each row. All measurements in this table are from [50-final](crypto-research/device-results/50-final.log); the BLS source/configuration is unchanged in 52. The final 52 repeat of 64 proofs / ten keys measured 3,569 ms cold and 2,624 ms warm median, consistent with this matrix. Exact values and sample counts are in [final-scaling.csv](crypto-research/device-results/final-scaling.csv).

| Proofs | Distinct keys | Cold (ms) | Warm median (ms) | Warm min–max (ms) |
|---:|---:|---:|---:|---:|
| 1 | 1 | 230.4 | 204.1 | 204.1–204.3 |
| 2 | 2 | 382.9 | 330.1 | 330.1–330.2 |
| 4 | 4 | 594.1 | 492.1 | 489.1–494.3 |
| 8 | 8 | 1,020.2 | 807.1 | 806.9–808.0 |
| 10 | 10 | 1,227.5 | 963.8 | 963.7–963.8 |
| 16 | 10 | 1,569.4 | 1,220.3 | 1,220.2–1,220.4 |
| 32 | 10 | 2,248.9 | 1,701.4 | 1,700.2–1,717.1 |
| 64 | 10 | 3,566.1 | 2,620.0 | 2,619.8–2,621.0 |
| 10 | 1 | 643.1 | 497.2 | 497.0–499.9 |
| 10 | 3 | 794.2 | 625.5 | 625.4–625.6 |
| 32 | 1 | 1,619.9 | 1,206.7 | 1,206.7–1,207.9 |
| 32 | 3 | 1,745.8 | 1,303.1 | 1,302.9–1,303.9 |
| 64 | 1 | 3,000.2 | 2,185.0 | 2,184.2–2,186.1 |
| 64 | 3 | 3,137.7 | 2,296.2 | 2,295.4–2,311.0 |

Pairing aggregation does not make verification constant-time in the number of proofs. Point decoding, subgroup checks, transcript hashing and weighted sums still grow with proof count. Grouping repeated denominations reduces the pairing terms; it does not remove those per-proof costs.

### Nutroot batching under memory pressure

The late change in 52 is adaptive Schnorr batching. A full Strauss batch often does not fit alongside the wallet. The verifier halves the requested chunk until it fits and individually verifies any small remainder. Every chunk must pass. The comparison below holds the final binary constant and averages three repetitions:

| Fixture | Individual, options 15 (ms) | Full-batch-or-individual, options 31 (ms) | Adaptive, options 95 (ms) | Actual adaptive batches |
|---|---:|---:|---:|---:|
| 15-of-15 threshold | 268.3 | 267.9 | **239.9** | 2 |
| 16 key paths | 315.4 | 325.1 | **252.4** | 2 |
| 32 key paths | 628.6 | 627.8 | **499.7** | 4 |
| 64 key paths | 1,256.3 | 1,256.6 | **1,010.9** | 9 |

The options-31 column executed individual checks because the large batch workspace did not fit or the old batch input cap was exceeded. The counters in [52-final](crypto-research/device-results/52-final.log) establish that options 95 actually batched. These large timing fixtures also use the historical transcript wrapper. Separate host tests verify 64 **current per-input digests**, constrained/no-scratch fallback and last-chunk tampering.

### Memory, scheduling and final configuration

The 52 run ended with **61,324 bytes free heap**, a **26,624-byte largest block**, an **11,540-byte minimum-ever free heap**, and **10,900 bytes unused at the console stack's deepest observed point**. The large Nutroot scratch experiments drive this minimum lower than the 50 scaling/peer matrix, whose minimum was 14,992 bytes. Original free heap was 76,688 bytes. This is a measured RAM-for-speed tradeoff, not a claim that all connected wallet workloads fit. Console and Wi-Fi drain stack allocations were retained; the offline watermarks are insufficient evidence to shrink them.

| Peer contention during 32-proof verification | Completed peer operations | Maximum MPI-call wait | Maximum peer completion gap |
|---|---:|---:|---:|
| No cooperative release, no hash-point cache | 36 | 2,164 ms | 2,212 ms |
| Cooperative release, no hash-point cache | 87 | 140 ms | 615 ms |
| Selected settings | 78 | 46 ms | 616 ms |
| Selected settings, repeat | 78 | 87 ms | 616 ms |

The peer exercises IDF MPI and SHA and checks their results. This shows improved access to shared accelerators, not a real TLS handshake measurement. Completion gaps include scheduling delay and remain much longer than MPI lock wait. The selected configurations passed without the baseline's idle watchdog warning. [50-final peer results](crypto-research/device-results/50-final.log).

The defaults and installed configuration are:

- CPU 160 MHz; supported QIO flash at 80 MHz. The ROM image header remains DIO because the bootloader enables QIO after identifying the flash.
- blst and MPI driver `-O3`; BLS caller and secp256k1 `-Os`; both LTO experiments disabled.
- Only hot MPI code in IRAM; secp tables and code stay in flash. Optional RV32 register-copy assembly is compiled out.
- secp signing comb `blocks=2, teeth=5`; generator window 12; variable-point window 4.
- BLS workspace capacity 11, reduced for small inputs and on allocation failure. Hash-point cache: 64 affine entries, 8,704 bytes. Validated G2 key cache: 16 entries.
- Runtime MPI mask `14927`, BLS mask `8047`, legacy mask `1`, Nutroot mask `95`. These are named options in the corresponding headers; reboot restores defaults.

The application is **1,521,264 bytes**, leaving about 20% of its existing partition free. [52 build manifest](crypto-research/device-results/52-final-build.json) records the exact source hashes and all CMake options. A separate build from `sdkconfig.defaults` succeeded with zero SDK configuration differences and matching CMake options; see [fresh-build.json](crypto-research/device-results/fresh-build.json).

## Measurement conditions

The identified board is an ESP32-C3 QFN32 revision 0.4, 160 MHz CPU, 40 MHz crystal, 4 MB embedded XMC flash, and a 16 KB flash cache. The build uses ESP-IDF 5.5.1, GCC 14.2, blst 0.3.16 and libsecp256k1 `ac56160`. The FreeRTOS tick is 1 kHz. The original firmware used DIO at 80 MHz; experiment 25 installed and verified a QIO-capable bootloader, also at 80 MHz.

The device has one application CPU. FreeRTOS tasks share that core; additional tasks do not create additional arithmetic throughput. The useful overlap is between that CPU and the RSA/SHA peripherals. The C3 implements RV32IMC, without vector instructions, an FPU, or a BLS/secp256k1 point accelerator. Its documented GDMA connections do not include RSA. These constraints guided the implementation. [Espressif datasheet](https://documentation.espressif.com/esp32-c3_datasheet_en.html), [technical reference manual](https://documentation.espressif.com/esp32-c3_technical_reference_manual_en.pdf).

Application flashes write only the existing application partition. The QIO experiment additionally writes the bootloader. The partition table and wallet NVS were never erased or rewritten by the flashing tools. A complete original flash backup and source/build archives are private files outside the repository; they may contain secrets and should remain private. The helper verifies the exact USB identity to avoid touching the other attached serial device.

Final read-back confirmed the installed application exactly matches the archived 52 image and the workspace build, with no firmware-source hash mismatches. The partition table and separate PHY partition are byte-for-byte unchanged. The shared NVS partition is not byte-for-byte identical: four live entries in the `phy` namespace changed during boots. Parsing both backups with ESP-IDF's NVS parser confirms **all live `wallet` entries are byte-for-byte unchanged**, namespace assignments are unchanged, and all live entry CRCs validate. No secret values or hashes of those values were exported. Reboot self-tests pass. [Final verification record](crypto-research/device-results/final-verification.json), [reboot log](crypto-research/device-results/53-reboot.log).

Wi-Fi remains enabled, but the configured network is unavailable (`reason: 201`). Reconnection attempts therefore occur during measurements. The display, keypad and NFC peripherals also report unavailable. These are **on-device cryptographic measurements, not measured online wallet receives, connected-radio load tests, or payment latency**. No mint requests or payments were made. A separate task exercises the real mbedTLS MPI and SHA APIs to test accelerator interoperability.

Timers use `esp_timer_get_time()`. Logs identify iteration counts, options, cache state and, for newer cases, individual samples or mean/min/max. Small differences can reflect code layout, interrupts and cache state. Claims of improvement use successful cryptographic checks; zero-duration/allocation-failure rows are not valid performance results. Cold means software verification caches were explicitly emptied, not that every flash-cache line was invalidated.

## Implemented optimizations

### RSA/MPI and extension-field arithmetic

The original port already accelerated 384-bit Montgomery multiplication. This work removes repeated mode setup within an acquisition, recognizes the immutable BLS modulus, compares operand-cache strategies, and uses direct register operations. The fastest measured strategy writes operands without the old data-dependent equality cache. Reversing operands to seek a cache hit and replacing `memcmp` with word comparisons did not win.

The peripheral state now records its owning task. A global “someone holds the lock” flag is insufficient when TLS or another task uses the same hardware. Acquisition/release follows the ESP-IDF peripheral reset, clock and mutex protocol; cached register state is invalidated across ownership changes.

Hardware fixed-exponent square roots help both BLS decompression and secp256k1 public-key parsing. The secp candidate is checked by squaring it in the software field representation. Hardware base-field inversion and repeated short square chains were implemented and measured, but remain disabled because they lost.

Fp2 multiplication and squaring now have fused peripheral paths. The faster variant starts a Montgomery product, computes independent CPU additions/subtractions while the engine runs, then collects the result. It preserves canonical field values, handles aliases, and was checked against the software implementation on zero, boundary and generated inputs. This is actual CPU/peripheral overlap on the C3's single core.

SHA-256 compression can use the SHA peripheral in both blst and libsecp256k1. Padding, XMD expansion, domains, tagged hashes and nonce derivation remain library code. Tests cover block/padding boundaries and unaligned input. SHA and MPI retain their separate hardware locks.

### BLS verification and mint responses

The verifier now has an explicitly bounded workspace. Miller capacity, MSM algorithm and cache behavior can be compared in the same binary. The selected maximum capacity is 11: ten distinct mint keys plus the generator-side term. Allocation is sized to the actual input and can fall back to smaller capacities. It avoids blst's much larger hidden stack allocation and shares one final exponentiation across the complete verification, as the original protocol verifier already did.

Validated G2 points are cached by exact compressed key bytes. Every uncached key still receives full validation. Hash-to-G1 mappings are cached by SHA-256 of the complete message and its length; cache entries can only be created by the real hash-to-curve function. No cache stores a proof-validity verdict. Every verification still checks the incoming signature points, derives the complete protocol transcript and weights, and evaluates the pairing equation.

The hash cache stores affine points. Moving only hot MPI code into IRAM freed enough SRAM to increase it from 32 to 64 entries. For batches larger than the cache, admission retains existing entries instead of cyclically evicting the entire useful working set on every scan. Cached public curve points are still wallet-sensitive metadata; this is a volatile performance cache, not exported diagnostic data.

The signature-side sum uses a bounded bucket MSM with explicit GLV decomposition. Full-width Fiat–Shamir coefficients are retained. A second grouped MSM helps when denominations repeat: it combines the weighted hash points belonging to the same mint key. A keyset is not a single pairing key—different amounts normally have different keys. Comparisons therefore distinguish proof count from distinct-key count.

Batch affine conversion amortizes inversions. The generator's Miller lines are an immutable flash table. An optional hot mint-key table was tested separately; its roughly 19.6 KB RAM requirement and small benefit make it unsuitable as a default. Allocation fallback reduces workspace/algorithm requirements; it never accepts a proof because allocation failed.

`cashu_bls_unblind_verify()` validates each external blinded signature once, performs secret unblinding, retains the resulting point through verification, and wipes private inverse intermediates. Optional batch Fr inversion saves several milliseconds for ten outputs. Responses larger than 32 outputs are processed as separately verified bounded chunks; any failed chunk invalidates the entire result. The wallet's BLS mint-response path now calls this API. This removes serialization/revalidation work from actual wallet code.

Cooperative release occurs at completed arithmetic boundaries. Private workspaces survive a yield; the next acquisition restores peripheral state. The optional mutable hot-key table is pinned by ownership while used. Measurements report both MPI-call wait and the peer task's completion gap, because lock wait alone misses time when a lower-priority task could not be scheduled.

### libsecp256k1 and legacy Cashu

The signing comb now uses two blocks and five teeth, a 2 KB table. Larger tables were slower on this cache, despite requiring fewer arithmetic operations. The public generator window was swept independently from the variable-point verification window. A smaller variable-point window allows useful Schnorr batches to fit in contiguous RAM.

The existing Cashu DLEQ verifier now evaluates `sG-eA` and `sB-eC` with joint public scalar multiplication, sharing doublings. The original path remains available for comparison and allocation fallback. Host tests compare both resulting points on full-width scalars, in addition to valid/tampered NUT-12 vectors.

Legacy unblinding uses libsecp256k1's constant-time secret-scalar multiplication internally. The public tweak-multiplication API is appropriate for verification scalars, but should not be selected as a speed shortcut for a private blinding factor. ECDH and signing also retain their secret-scalar paths.

The upstream secp256k1 submodule stays unchanged. A local wrapper contains the bounded extensions, and build-generated adapters apply the SHA compression and variable-window hooks. Configuration fails if the expected upstream hook signatures disappear.

### Current Nutroot

The implementation and vectors are pinned to Nutroot PR #421 head `a3f04b97154b036626d27ca437d75b348a6a4407`. The live proposal snapshot records its September 10 merge into `bls-protocol`; that is staging-branch integration, not a claim that the BLS stack has merged into `main`. [Pinned NUT-10](https://github.com/cashubtc/nuts/blob/a3f04b97154b036626d27ca437d75b348a6a4407/10.md), [PR #421](https://github.com/cashubtc/nuts/pull/421).

The core uses the current transaction transcript and per-input signing digests, version-based routing, compressed point secrets, current tree/leaf/witness bounds, and disclosure field. Threshold verification decodes signatures once, checks mandatory JSON types before early success, rejects duplicate use, reuses parsed keys, tries the likely matching signature first, and retains a complete fallback search.

BIP-340 batches use transcript-derived, full-width coefficients and bounded caller-owned scratch. Adaptive chunks retain batching when the whole batch does not fit; small remainders and allocation failures fall back to individual verification. Batch counters distinguish an actual batch from an allocation fallback; this matters when interpreting early experiments. [BIP-340 batch verification](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#batch-verification).

Public Nutroot commitments can also be verified together. The implementation computes `P-K`, batch-normalizes those differences, and checks a weighted MSM against the weighted tweak sum. `nutroot_verify_commitments()` validates bounded chunks, computes the normal tweak hashes, and falls back to individual checks on allocation failure. This API checks commitment equations; callers still validate tree serialization, disclosure and policy. An empty tweak and an untweaked bare secret remain different cases.

Signing retains keypairs across recovery and signing. Receiver-keyed fixtures include the actual ECDH and slot derivation, with fresh ephemeral keys per output. The current KDF has the specified framed identifier, 64-bit counter, purpose/index/attempt fields and strict scalar rejection. Cached HMAC prefix states avoid repeated setup. NUMS offsets and a bare-output preparation API are included. [Pinned NUT-13](https://github.com/cashubtc/nuts/blob/a3f04b97154b036626d27ca437d75b348a6a4407/13.md), [pinned NUT-28](https://github.com/cashubtc/nuts/blob/a3f04b97154b036626d27ca437d75b348a6a4407/28.md).

The preparation API takes a counter already durably reserved by its caller. It does not implement a persistent counter allocator or a production precomputation pool. Preparation moves work before a payment interaction; reading a prepared object is not a claim that fresh cryptography became free. Fresh-output benchmarks use new counters on every repetition.

**Migration boundary:** the production wallet still has its earlier v3 secret/KDF and token model. The current Nutroot core, KDF, commitment and preparation APIs are implemented and tested, but complete `si` transport/storage, restore migration, and production Nutroot receive orchestration remain separate work. Silently changing derivation for existing wallet counters would endanger restoration. Historical transcript entry points exist for reproducing earlier benchmark results.

## Rejected experiments and limits

| Experiment | Observation | Decision |
|---|---|---|
| blst `-O2` / `-Os` | About 1.25 / 1.34 s versus 1.06 s in the matched late sweep | Keep blst `-O3` |
| MPI driver `-O2` / `-Os` | About 1.33 / 1.40 s for that same verification | Keep driver `-O3` |
| secp `-O2` / `-O3` | Larger code made signing and verification slower | Keep `-Os` |
| Whole-crypto LTO | Roughly 2.03 s versus 1.06 s, and changed RAM placement | Disabled |
| BLS-only LTO with MPI placement preserved | Warm cached verification about 1.63 s versus 0.96 s | Disabled |
| Larger signing combs | 22 KB and 86 KB tables lost to the 2 KB table | Small comb |
| Generator windows 4/8/10/12/14 | Window 12 was near the best; 14 costs much more flash | Window 12 |
| Variable-point windows 3/4/5 | 3 slowed batch/individual work; 5 often exceeded batch scratch availability | Window 4 |
| Pippenger for these Schnorr batches | Considerably slower than Strauss; e.g. about 185 vs 135 ms at 8-of-15 | Strauss with fallback |
| 8 KB verification table in RAM | Small improvement with a substantial RAM cost | Disabled |
| 22 KB signing table / whole secp in IRAM | BLS allocation failures; one combined IRAM build aborted during startup | Reject failed configurations |
| 2 KB signing table in RAM | Less than 2% improvement in the late sweep | Preserve RAM |
| All MPI code in flash | Verification slowed from about 1.06 to 1.20 s | Keep MPI in IRAM |
| All MPI code versus hot MPI code in IRAM | Cold helpers/calibrators used about 6 KB of scarce SRAM without useful speed | Keep only the hot arithmetic path in IRAM |
| Only secp field multiply/square in IRAM | Roughly 1–2% secp benefit for about 5 KB SRAM | Compare against memory availability; not a free gain |
| Hand-written RV32 MMIO copy | About 6.88 vs 6.75 µs Montgomery multiply; cached ten-proof verify 0.972 vs 0.964 s | Disabled and compiled out by default |
| Hardware BLS Fp inversion | About 1.45 ms versus 1.13 ms software | Software inverse |
| General hardware secp field multiplication | About 14.1 µs versus 9.4–9.5 µs software; squaring 14.1 vs 5.85 µs | Calibration only; no production field hook |
| Wide RSA packing | Raw 768/1152/1536-bit products cost about 25.6/48.8/79.2 µs before reduction | No win over ordinary field products at these widths |
| Hot-key prepared lines | Approximately 19.6 KB per G2 key, sometimes allocation fallback, little measured benefit | Optional diagnostic only |

Experiments 17 and 18 contain misleadingly tiny verification durations after allocation failure; they are **not speedups**. Experiment 20 aborted in the C++ exception allocation stub at startup under the combined RAM pressure. The original baseline and early runs 01, 02 and 04 emitted idle-task watchdog warnings despite passing their crypto vectors. Those warnings are recorded separately from cryptographic rejection and explain the baseline diagnostic flags in the CSV. Early current-proposal experiments also exposed a diagnostic setter called while holding its own mutex, and a test seed-length mismatch; both were fixed before accepting subsequent measurements. The result files retain failures rather than concealing them.

Experiment 46's first assembly-copy command exceeded the then-current CLI option limit and did not execute; the actual comparison is in 48. Experiment 51's new 15-of-15 fixture exposed an eight-signature limit in the benchmark builder. Build 52 fixes that builder, checks fixture creation before timing, and passes the complete large-batch comparison. Neither failed diagnostic is counted as an optimization result.

The original Nutroot “receive” benchmark signed each input twice. Correcting that changes the benchmark, not the speed of a previously deployed production Nutroot receive. Its oversized-tree sweeps also belong to the older proposal. New current-proposal timings use 33-byte point secrets, full-width blinding factors and actual receiver ECDH.

## Remaining algorithm and architecture options

The measured Fp2 costs are approximately 18.2 µs for multiplication, 13.9 µs for squaring and 1.10 ms for inversion. That makes affine Miller formulas unattractive at the available pair capacities: even an optimistic affine doubling plus batched inversion needs roughly `2S + 2M + 3M(n-1)/n + I/n`, before all line work. At 16 pairs that already exceeds the existing doubling's `8S + 3M`. Ordinary ten-denomination transactions have fewer variable pairs still. Increasing pair capacity enough to amortize inversions also consumes the RAM needed for the wallet and TLS.

The final exponentiation was measured separately at about 100 ms, approximately one tenth of the optimized ten-distinct-key verification. Eliminating it entirely would therefore have a limited bound; a faster cyclotomic squaring formula can only save a fraction of that. Compressed cyclotomic methods additionally trade multiplications for inversions, whose relative cost is unfavorable here. x86 AVX-512/IFMA results do not transfer to a scalar RV32IMC core. [Primary AVX-512 BLS12-381 research](https://doi.org/10.46586/tches.v2025.i4.848-872).

More aggressive lazy field representations, compressed pairing-line tables, a different pairing library, a purpose-built full assembly field backend, or a new curve would be new implementation/research projects. The measurements above identify the costs they must beat; they are not proven impossible. Existing blst already supplies endomorphisms, specialized curve arithmetic, an optimized extension-field tower and final exponentiation. Replacing it requires proving protocol and subgroup equivalence, not only timing a multiplication.

Fewer proofs and fewer distinct denominations can reduce pairing work substantially. That is a wallet selection/denomination policy decision with privacy, fees and change consequences. Grouping equal keys internally is compatible and implemented; changing coin-selection policy or the protocol's coefficient derivation merely to improve a benchmark is not.

Public-input delegation, pairing witnesses, mint-assisted settlement, offline authenticity checks and delayed swaps have different trust, availability and settlement properties. They are not transparent substitutes for local proof verification. They need a corresponding protocol and service, not just a faster firmware build. The [earlier report](crypto-optimization-esp32c3.md#delegation-and-verification-certificates) evaluates these alternatives.

The CPU was already at its documented maximum. Undocumented overclocking, voltage changes, or destructive fuse changes are not validated optimizations. Likewise, a second crypto task cannot supply a second C3 core. The implemented Fp2 pipeline uses the independent arithmetic engine that actually exists. General RSA DMA and AVX/vector instructions are not available on this target.

## Verification and reproduction

The tools keep firmware and raw serial traffic private while exporting synthetic timing lines. Build manifests contain source hashes and application hashes, not firmware contents. Host test runners freeze a source snapshot, force blst's 32-bit layout, apply the measured secp window in that private snapshot, and run AddressSanitizer plus UndefinedBehaviorSanitizer. They exercise valid and tampered BLS proofs, scalar boundaries, cache changes, allocation failures, aliased output buffers, chunk boundaries, threshold matching, Schnorr batch equations, DLEQ points and commitment equations.

The full host pass in 45 includes **4,410 BLS differential cases**, **2,000 threshold comparisons**, **576 Schnorr batch cases**, **256 DLEQ point comparisons**, **512 secret multiplication/alias comparisons**, current proposal vectors and commitment batches. Subsequent changes received targeted sanitizer passes: cache admission and 64-entry storage; **288 workspace combinations** after dynamic sizing; and **2,500 threshold comparisons plus 64-input current key-path tests** after adaptive batching. Combined unblind/verify tests cover 64 outputs, full-width factors, aliases, first/last chunk failure, complete output clearing and zero-factor rejection. [Host validation index and source snapshots](crypto-research/device-results/host-validation.json).

The final device self-tests and current-proposal benchmark pass in [52](crypto-research/device-results/52-final.log), including hardware/software arithmetic comparisons. The complete scaling matrix checks a modified proof in every row. Host timing is never presented as C3 timing. The [measurement CSV](crypto-research/device-results/measurements.csv) retains source lines and diagnostic status so failed-run samples cannot silently become apparent wins.

```sh
python3 tools/run_crypto_host.py --output /tmp/nucula-crypto-tests
```

This requires Clang, OpenSSL and cJSON; the runner accepts a dependency prefix. ESP-IDF builds remain the normal project build. Existing CMake caches may preserve previous experimental values, so explicitly reset the `NUCULA_*` options when reproducing a configuration. Runtime `bench mpi`, `bench verify`, `bench legacy` and `bench nutroot ... opt=` switches are diagnostic state and reset on reboot.

```sh
python3 tools/crypto_device.py --flash build/nucula.bin \
  --log /tmp/nucula-crypto-device.log \
  --command 'log i' --command 'selftest' \
  --command 'bench nutroot current' --command 'heap' --command 'tasks'
```

The helper's default USB identity is this campaign's board. Another board requires its explicit identity and port. A fresh QIO configuration also needs the matching bootloader; this board already has it. App-only flashing cannot change an old bootloader's flash setup. Always retain the existing partition layout when preserving an installed wallet.

The code has extensive differential and device checks, but has not received an independent cryptographic audit. Connected Wi-Fi/TLS, populated wallet state, actual NFC interaction, realistic mint responses, long-duration fragmentation and power measurements remain unmeasured. No benchmark alone establishes those properties, or exhaustive optimality over every possible algorithm.
