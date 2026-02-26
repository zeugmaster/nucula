# nucula

A Cashu ecash wallet for the ESP32-C6 with NFC tap-to-pay.

Nucula can store ecash from multiple mints, receive payments over NFC, mint new tokens via Lightning invoices, and melt tokens to pay Lightning invoices — all from a device that fits in your pocket.

## Hardware

| Component | Role | Interface |
|-----------|------|-----------|
| ESP32-C6 | MCU (WiFi, BLE, 802.15.4) | — |
| PN532 | NFC controller | SPI |
| SSD1306 | 128x64 OLED display | I2C |

### Pin Map

| Signal | GPIO |
|--------|------|
| PN532 SCK | 19 |
| PN532 MISO | 20 |
| PN532 MOSI | 18 |
| PN532 SS | 17 |
| SSD1306 SDA | 22 |
| SSD1306 SCL | 23 |

## Build

Requires [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/get-started/) v5.x.

```bash
# 1. Configure WiFi credentials
cp main/wifi_config.example.h main/wifi_config.h
# Edit main/wifi_config.h with your SSID and password

# 2. Build, flash, and open serial monitor
idf.py build flash monitor
```

On first flash (or after changing the partition table), erase flash first:

```bash
idf.py erase-flash
idf.py build flash monitor
```

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
| `reboot` | Restart the device |

## Protocol

Nucula implements the following [Cashu NUTs](https://github.com/cashubtc/nuts):

- **NUT-00** Cryptography (BDHKE), token serialization (V3/V4)
- **NUT-02** Keysets and input fees
- **NUT-03** Swap
- **NUT-04** Mint tokens
- **NUT-05** Melt tokens
- **NUT-18** Payment requests (NFC)
- **NUT-23** Bolt11 Lightning
