# nucula

Nucula is the firmware for [Nucula Board](https://github.com/zeugmaster/nucula-board).
It runs on the ESP32-C3 and provides a Cashu wallet, NFC, and a USB serial console.

## Build and flash

Use ESP-IDF 5.5.1 with its environment activated.

```sh
git submodule update --init --recursive
cp main/wifi_config.example.h main/wifi_config.h
```

Edit `main/wifi_config.h` with your Wi-Fi credentials. This file stays local.

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
