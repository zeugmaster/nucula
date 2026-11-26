# Keyset v3 wallet compatibility

This implementation targets [cashubtc/nuts PR #443](https://github.com/cashubtc/nuts/pull/443), pinned to [b6c07bdc198ff95461bda3f5cb9483c34861efaa](https://github.com/cashubtc/nuts/tree/b6c07bdc198ff95461bda3f5cb9483c34861efaa) on 2026-11-26. The proposal is still open. PR #371 is superseded; the existing `feat/keyset-v3` implementation was based on earlier BLS/nutroot drafts.

## Implemented scope

- Binary-framed v3 keyset commitments: keys, unit and input fee; `final_expiry` is no longer committed. Legacy v1/v2 commitments remain unchanged.
- BLS signatures over the decoded 33-byte secp256k1 secret, with intrinsic verification of mint responses and received proofs.
- Mandatory bare-secret signing for each v3 transaction input. Transcripts commit to proof `Y`, hashed blinded outputs, mint lock keys and starting issued amounts, and melt quote amounts including fee reserves. The core also handles the optional melt fee index, including zero.
- Latest NUT-13 length framing, 64-bit counters, rejection sampling and per-proof branches 0–3. Counter reservations are durable before outputs are created; existing 32-bit NVS counters are read and upgraded. Quote branch 4 was removed upstream.
- Locked mint quotes, mint, swap, bearer token export, receive, melt and change. Quote lock keys are randomly generated and saved before requesting payment. They survive reboot but are not recoverable from the mnemonic alone.
- Token/NVS preservation of `spend_info` (`k`, `E`, `K`, `u`, `tree`); private spend information is excluded from all mint requests. V3 token witnesses are dropped on both encoding and decoding. Unknown JSON spend-info members survive JSON round trips; unknown CBOR spend-info members are currently ignored.
- Key-path reception and signing for bearer and NUT-28 receiver outputs, including disclosed trees when receiving online. Offline acceptance is restricted to bare or empty-tree key paths. Offline checks cannot detect double-spending.
- Optional NUT-10 verification in the protocol core: threshold, after, hashlock and unspendable commit leaves; leaf-bound script digests; eight-leaf/512-byte limits; strict witness members. The production wallet does not construct script-path witnesses or a conditional-payment UI and refuses tokens it cannot spend. NUT-10 is optional in the latest proposal.

The separate proposals for unified transactions (#445), template leaves (#457), signing packages (#464), and HMAC quote keys (#495) are not part of this update. The wallet's existing signed 32-bit amount limit remains; larger amounts are rejected.

## Storage and recovery

Before submitting a mint, swap or melt request, the wallet saves its exact request, input proofs, output secrets, blinding factors and spend info in NVS. It saves verified replacement proofs before clearing that record. New spending and export are blocked while an operation remains unresolved. A successful `Wallet::swap` now persists all returned proofs; code exporting its send proofs must subsequently call `remove_proofs`.

Recovery runs once at connected startup and is also available through the console's `recover` command. Mint/swap recovery first requests NUT-09 signatures for the original outputs. Melt recovery checks the quote and its change. Otherwise it retries the exact saved request; a mint's NUT-19 response cache can resolve that retry. Failed or ambiguous recovery retains the record and blocks new spending. Mints without usable recovery endpoints may require operator assistance. After recovery, retry the original command using fresh quote/wallet state; recovered swap outputs are credited to this wallet.

NVS contains bearer keys and recovery material. Preserve the device backup as well as the mnemonic. Old experimental v3 proofs/keysets do not automatically migrate to this incompatible draft. Redeem them with their original firmware/mint before upgrading. Unreadable stored proofs block writes instead of being replaced with an empty wallet. Do not erase NVS to clear an unresolved operation.

## Validation

The host suites use ASan/UBSan and the portable 32-bit BLS representation. Current vectors are copied from the pinned upstream NUT-00/02/10/13/28 fixtures. The wallet harness compiles the real wallet, JSON/CBOR codecs and crypto against a simulated mint and NVS.

```sh
python3 tools/run_crypto_host.py --only current --output /tmp/nucula-current
python3 tools/run_crypto_host.py --only nutroot --output /tmp/nucula-nutroot
python3 tools/run_crypto_host.py --only legacy --output /tmp/nucula-legacy
python3 tools/run_crypto_host.py --only bls --workspace-only --output /tmp/nucula-bls
IDF_PATH=/path/to/esp-idf python3 tools/run_wallet_host.py --output /tmp/nucula-wallet
idf.py -B /tmp/nucula-build -D IDF_TARGET=esp32c3 build
```

Use a fresh output directory for each host run. The runners require Clang, OpenSSL and cJSON (default prefix `/opt/homebrew`; override with `--prefix`). The wallet runner additionally uses TinyCBOR from `managed_components`, provisioned by an ESP-IDF build, and mbedTLS from `IDF_PATH`.

Coverage includes valid and malformed witnesses, quote/transaction binding, receiver keys, mint/send/receive/melt, private-data isolation, token round trips, JSON allocation failures, counter migration/overflow, lost responses, proof-save failures, invalid mint signatures and recovery across reload. Firmware flashing, Wi-Fi connection, restored storage and on-device crypto/protocol self-tests were checked on Nucula v2 Rev B. NFC payment timing, hardware power-cut testing and interoperability with a deployed PR #443 mint still require validation.

## Rev B and Wi-Fi compatibility

The original v3 branch still had XIAO prototype pins and compiled Wi-Fi credentials. It now uses Nucula v2 Rev B wiring (I²C 4/5, NFC IRQ/VEN 6/7, OLED boost/reset 3/10), external I²C pull-ups, the existing Rev B display power sequence, and native USB without occupying keypad GPIO20.

Wi-Fi settings and the private USB setup protocol come from `perf/esp32c3-optimizations` (`ae10a2f`). Saved `web_wifi/station` settings take precedence over legacy driver settings, and firmware no longer overwrites saved settings with a header file. SSIDs retain leading/trailing spaces. The related HTTP radio wake holds and buffer sizing are included; the separate secp256k1/codec optimizations have not been merged into the v3 cryptography.

The OLED driver and its failure tests were carried from the Rev B work in the original workspace. The console retains the v3 branch's 24 KB stack for BLS verification. Startup preserves unreadable NVS instead of erasing it.

Rev B uses DIO flash mode. An application built for QIO must not be flashed over a DIO bootloader: runtime flash reads return invalid data and NVS can reinitialize pages. The defaults now explicitly select DIO for app-only updates.
