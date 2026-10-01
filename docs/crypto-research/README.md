# Crypto research evidence

The original files accompany [the device-free assessment](../crypto-optimization-esp32c3.md), reviewed September 13, 2026. Their operation counts and sensitivity models are historical hypothetical evidence.

The September 15 hardware campaign is complete through firmware **52-final**: see the [hardware results and implementation report](../esp32c3-optimization-results.md), [experiment ledger](device-optimization-plan.md), and [final verification](device-results/final-verification.json). The earlier hypothetical workbook is not the source of the new speed claims. Raw firmware and full-flash backups stay outside the repository because they can contain private configuration or wallet data.

## Hardware campaign evidence

- [device-results/measurements.csv](device-results/measurements.csv): individual timing rows with their command, source line and diagnostic status.
- [device-results/final-scaling.csv](device-results/final-scaling.csv): cold and warm BLS statistics by proof count and distinct amount-key count.
- [device-results/52-final-build.json](device-results/52-final-build.json): measured source hashes, application hash and complete CMake configuration.
- [device-results/host-validation.json](device-results/host-validation.json): sanitizer/differential logs and frozen source manifests, including targeted validation after the full pass.
- [device-results/protocol-snapshot.json](device-results/protocol-snapshot.json): September 15 Nutroot PR state and pinned NUT-10/13/28 source hashes.
- [device-results/fresh-build.json](device-results/fresh-build.json): separate build from `sdkconfig.defaults` with matching settings.

Reproduce host validation with `python3 tools/run_crypto_host.py --output /tmp/nucula-crypto-tests` from the repository root. The [hardware report](../esp32c3-optimization-results.md#verification-and-reproduction) explains dependencies and the guarded device helper. `tools/record_crypto_build.py` archives firmware privately; `tools/collect_crypto_results.py` exports only approved synthetic log lines; `tools/summarize_crypto_results.py` rebuilds the timing CSV. Campaign archive paths and the helper's USB identity are specific to this run and must be selected explicitly for another board/campaign.

## Contents

- `provenance.json`: repository revision, hashes of the reviewed working-tree inputs, and live GitHub proposal states. Some reviewed Nutroot files were already uncommitted; their hashes identify them without altering them.
- `operation-counts-*.csv`: counts of 384-bit Montgomery multiplication dispatches using the production BLS verifier and isolated algebra experiments. Counts exclude software inverse internals and other CPU work.
- `stack-frames.csv`: compiler-reported frames from the actual ESP-IDF RV32 compile commands. These are not whole-task stack bounds.
- `nutroot-*.csv`: signature verification counts and acceptance results for four well-formed threshold fixtures. The experimental variants deliberately isolate mechanisms; they are not complete parser/security tests.
- `performance-model.xlsx` and `sensitivity.csv`: historical observations and explicitly hypothetical sensitivity calculations. Editable assumptions are separate from observations.
- `count_ops.c`, `nutroot_probe.c`, `sha_shim/`: host-only fixtures and an OpenSSL SHA adapter.
- `run_host_probes.py`, `build_model.py`: reproduction scripts. Firmware sources are read; temporary source copies contain experimental edits.

## Reproduce probes

Requirements: Python 3, Clang, OpenSSL headers/library, cJSON headers/library, and the initialized repository submodules. The recorded run used the installed Homebrew libraries under `/opt/homebrew`. Pass `--prefix` for another common include/lib prefix. Separate library installations may require adjusting include/library flags in the script.

```sh
python3 docs/crypto-research/run_host_probes.py \
  --output /tmp/nucula-research-reproduced \
  --compile-db build/compile_commands.json
```

Omit `--compile-db` for host probes only. Stack estimates additionally require an existing configured ESP-IDF build, its referenced target compiler and headers, and the compile database for this checkout. The script does not configure, link, flash, or run firmware. Outputs and intermediate object files go to the selected output directory or a temporary directory.

The arithmetic probe forces blst's 32-bit limb representation on the host, instruments the software Montgomery reference through the same port dispatch, and compares valid/modified-message batches, sequential/MSM sums, and prepared/ordinary Miller results. Its 33-byte secret fixtures are opaque BLS test messages, not a Nutroot point-encoding conformance test. Small deterministic mint scalars generate distinct fixture keys; Fiat–Shamir coefficients come from the production transcript implementation. The isolated fixture does not exercise the seed KDF.

The forced-Pippenger variant disables the library's small-batch window shortcut in a temporary copy. Its signature-sum experiment changes algorithm; its `production_verify_distinct10` row still uses the unmodified sequential signature sum, so that row is intentionally equal to the chunk-4 baseline. The other variant names change the production caller's Miller chunk size. Repeated `final_exp_valid_batch` rows correspond to the immediately preceding Miller experiment.

The Nutroot early-success variant and speculative first-pair mapping are experiments on the older local core. A production implementation must first preserve current-proposal parsing and policy rules, validate mandatory trailing syntax, and bound fallback work. The four fixtures are insufficient to establish those properties.

## Rebuild the workbook

Requires Python's `openpyxl` package:

```sh
python3 docs/crypto-research/build_model.py
```

The script writes the workbook and sensitivity CSV beside itself. Workbook formulas recalculate when opened in a spreadsheet application; the CSV contains independently calculated numeric values. Changing workbook assumption cells updates its formula sheet but does not mutate the original observation sheets or CSV.

Interpretation limits: field-operation reductions are not timing reductions, compiler frames are not measured stack high-water marks, and host arithmetic agreement does not verify ESP32 peripheral behavior. See the assessment for the hardware measurement plan and sources.
