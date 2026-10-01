# nucula

A Cashu ecash wallet for the ESP32-C3 with NFC tap-to-pay.

Nucula can store ecash from multiple mints, receive payments over NFC, mint new tokens via Lightning invoices, and melt tokens to pay Lightning invoices — all from a device that fits in your pocket. Tokens received while offline are stashed and redeemed automatically once WiFi returns.

## Hardware

Target board: **Nucula v2, ESP32-C3-WROOM-02-N4**, with native USB console.
This configuration supports prototype bring-up with the display and keyboard
disconnected. NFC and the keypad expander are probed at boot; console and wallet
remain usable when they are absent. The OLED boost is held off and reset asserted.
Display power/reset sequencing must be implemented before enabling the panel.

| Component | Role | Interface |
|-----------|------|-----------|
| ESP32-C3 | MCU (WiFi) | — |
| PN7160 | NFC controller (card emulation) | I2C `0x28` |
| SSD1309 | 128x64 OLED display | I2C `0x3C` |
| PCF8574 | 3x4 matrix keypad expander | I2C `0x20` |

### Pin Map

| Signal | GPIO | Notes |
|--------|------|-------|
| I2C SDA (shared) | 4 | External pull-up to 3.0 V |
| I2C SCL (shared) | 5 | External pull-up to 3.0 V |
| PN7160 IRQ | 6 | Active high |
| PN7160 VEN | 7 | High enables NFC |
| OLED power | 3 | High enables boost input; held low |
| OLED reset | 10 | High asserts through Q5; held high |
| Keyboard INT_N | 20 | Active low; driver currently polls I2C |

PN7160 DWL is strapped low on the PCB and has no MCU GPIO. The shared I2C bus
runs at 100 kHz with ESP internal pull-ups disabled. These assignments differ
from the older Seeed XIAO wiring.

Pins and addresses live in `main/board.h` (PN7160 control pins in `components/pn7160/include/nci.h`).

## Build

Requires [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/get-started/) v5.x.

```bash
# 1. Configure WiFi credentials
cp main/wifi_config.example.h main/wifi_config.h
# Edit main/wifi_config.h with your SSID and password

# 2. Build, flash, and open serial monitor
idf.py build flash monitor
```

When reusing an existing `sdkconfig`, select **USB Serial/JTAG Controller** as
the console output in `idf.py menuconfig` (Component config → ESP System
Settings). `sdkconfig.defaults` selects it for fresh configurations; defaults
do not override an existing config. UART0 RX shares GPIO20 with keyboard INT_N.

On the very first flash (or after changing the partition table), erase flash first — **this wipes the wallet**, so never do it on a device holding funds:

```bash
idf.py erase-flash
idf.py build flash monitor
```

A plain `idf.py flash` preserves the NVS partition, so reflashing firmware keeps your proofs and seed.

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
| `stickup` | Drain all funds as V4 tokens |
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
