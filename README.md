# nucula

Nucula is the firmware for [Nucula Board](https://github.com/zeugmaster/nucula-board).
It runs on the ESP32-C3 and provides a Cashu wallet, NFC, and a USB serial console.

## Build and flash

Use ESP-IDF 5.5.1 with its environment activated.

For normal setup, open [nucula.dev/setup](https://nucula.dev/setup) in desktop
Chrome or Edge, connect a USB-C data cable, and select the Espressif USB serial
port. The site installs firmware, saves Wi-Fi credentials over USB, and provides
the same serial console. Save Wi-Fi settings and restart; the page reconnects automatically to check
the network connection. Use a 2.4 GHz personal or open network.

Public firmware builds contain no compiled-in credentials. `main/wifi_config.h`
is no longer included. Wi-Fi settings saved by older firmware's Wi-Fi driver are
migrated automatically; subsequent settings are stored in the `web_wifi` NVS
namespace and applied at the next boot. Wallet storage is separate. On an NVS
initialization error, the firmware preserves storage and stops wallet startup
instead of automatically erasing it.

For firmware development:

```sh
git submodule update --init --recursive
```

```sh
idf.py build
idf.py -p /dev/cu.usbmodem101 flash monitor
```

Replace the port as needed. Exit the monitor with `Ctrl+]`.
Use `help` to list console commands and `status` to check the device.
Do not erase flash on a device holding funds: NVS stores the wallet seed and proofs.

## Rev-A prototypes

`main` contains the firmware used for Rev-A bring-up. The display is held off;
the keyboard can remain disconnected. With a battery attached, tap RESET after
reconnecting USB if the serial port does not appear.

The verified firmware image is recorded in [docs/rev-a-firmware.json](docs/rev-a-firmware.json).
That record describes the earlier on-device build, not the USB setup preview.

## USB setup protocol

`web_setup.cpp` implements protocol 1 on the existing USB serial console.
Requests are one line, for example `web {"id":"1","op":"info"}`. Replies are
JSON prefixed with `@NUCULA `, with the same `id` and an `ok` boolean. Operations:

- `info`: board, protocol, firmware version, storage availability, configured
  network name, Wi-Fi connection/IP and whether a restart is required. No password.
- `wifi.set`: `ssid_hex` and `password_hex`, lowercase hex encoding of UTF-8 bytes.
  SSID: 1–32 bytes; password: 8–63 bytes or empty for an open network. Control
  characters are rejected. A successful reply means settings are committed to NVS,
  not that the network connection has succeeded. Restart to apply them.
- `reboot`: acknowledge, then restart after allowing the USB response to drain.

Console echo stops at the `web ` prefix, before any credentials arrive. The
command buffer is cleared after processing. Anyone with physical USB console
access can configure the board and use its wallet commands, as before.

Pushing a version tag builds and packages a draft GitHub Release. See
[the release guide](docs/releases.md) for publication and local packaging.
The website only performs application updates on a matching storage layout; a
first installation requires blank partition-table and NVS regions. Never publish
an older local firmware binary containing compiled Wi-Fi credentials.

## Automated releases

See [the firmware release guide](docs/releases.md) for tag-driven builds, draft
releases, hardware acceptance, and publication to the website’s version picker.
