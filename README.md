# nucula

A Cashu ecash wallet for the ESP32-C3 with NFC tap-to-pay.

Nucula can store ecash from multiple mints, receive payments over NFC, mint new tokens via Lightning invoices, and melt tokens to pay Lightning invoices — all from a device that fits in your pocket. Tokens received while offline are stashed and redeemed automatically once WiFi returns.

This branch implements the v3 proposal pinned in [the compatibility notes](docs/keyset-v3.md), including wallet flows and interrupted-request recovery.

## Hardware

Reference board: Nucula v2 Rev B (ESP32-C3-MINI-1-H4X). All three peripherals share one I2C bus; each is probed at boot and the firmware runs fine (console + wallet) with any or all of them absent.

| Component | Role | Interface |
|-----------|------|-----------|
| ESP32-C3 | MCU (WiFi) | — |
| PN7160 | NFC controller (card emulation) | I2C `0x28` |
| SSD1309 | 128x64 OLED display | I2C `0x3C` |
| PCF8574 | 3x4 matrix keypad expander | I2C `0x20` |

### Pin Map

| Signal | GPIO | Note |
|--------|------|----------|
| I2C SDA (shared) | 4 | — |
| I2C SCL (shared) | 5 | — |
| PN7160 IRQ | 6 | — |
| PN7160 VEN | 7 | — |
| PN7160 DWL | Strapped low | — |
| SSD1309 boost enable | 3 | Active high |
| SSD1309 reset | 10 | Active high through Q5 |

Pins and addresses live in `main/board.h` (PN7160 control pins in `components/pn7160/include/nci.h`).

## Build

Requires [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/get-started/) v5.x.

```bash
# 1. Configure WiFi credentials
# Wi-Fi credentials are stored in NVS; builds contain no credentials.
# Existing USB setup settings take precedence over legacy driver settings.

# 2. Build, flash, and open serial monitor
idf.py build flash monitor
```

Only use the following commands for an intentionally blank device — **they wipe the wallet and Wi-Fi settings**:

```bash
idf.py erase-flash
idf.py build flash monitor
```

A plain `idf.py flash` with the same partition table preserves NVS, including proofs, seed and Wi-Fi settings. Configure Wi-Fi through [USB setup](https://nucula.dev/setup); SSID spaces are preserved. This branch targets Rev B, including its inverted OLED reset and switched boost supply.

## Getting Started

Once flashed and connected to WiFi:

```
nucula> mint add https://your-mint-url.com
nucula> invoice 100
# Pay the displayed Lightning invoice, then:
nucula> claim <quote_id>
nucula> balance
```

## Commands

| Command | Description |
|---------|-------------|
| `help` | Show available commands |
| `status` | System and wallet status |
| `balance` | Show wallet balance per mint |
| `mint list` | List configured mints |
| `mint add <url>` | Add a mint |
| `mint remove <index>` | Remove a mint |
| `invoice <amount> [mint_idx]` | Get a Lightning invoice to fund the wallet |
| `claim <quote_id> [mint_idx]` | Claim minted tokens after paying the invoice |
| `melt <bolt11> [mint_idx]` | Pay a Lightning invoice with wallet funds |
| `receive <token>` | Receive a cashuA or cashuB token |
| `nfc request <amount>` | Start an NFC payment request |
| `nfc stop` | Stop NFC |
| `stickup [mint_idx]` | Export one mint's funds as V4 tokens, or all mints when omitted |
| `recover` | Recover interrupted mint, swap, or melt requests |
| `seed [show\|generate\|restore\|wipe]` | Manage the BIP-39 wallet seed |
| `keypad scan` | Probe PCF8574 keypad wiring |
| `heap` / `tasks` | Heap and task-stack telemetry |
| `log <e\|w\|i\|d> [tag]` | Set runtime log level |
| `bench` | Benchmark crypto primitives |
| `selftest` | Run crypto/keyset self-tests |
| `reboot` | Restart the device |

## Protocol

Nucula implements the following [Cashu NUTs](https://github.com/cashubtc/nuts):

- **NUT-00** Cryptography (BDHKE), token serialization (V3/V4)
- **NUT-02** Keysets and input fees
- **NUT-03** Swap
- **NUT-04** Mint tokens
- **NUT-05** Melt tokens
- **NUT-10/11** Spending conditions, P2PK (offline receive)
- **NUT-12** DLEQ proofs (required from mints)
- **NUT-13** Deterministic secrets from the BIP-39 seed
- **NUT-18** Payment requests (NFC)
- **NUT-23** Bolt11 Lightning
