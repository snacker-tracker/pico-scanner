# Pico-Scanner

This is a micropython port of the [original scanner code](https://github.com/snacker-tracker/scanner)

It offers the same functionality, but only requires a raspberry-pi pico. Chances are, this could run perfectly well on any ESP devices as well, but this is what I wanted to work with, and I didn't test anything else.

Tests run under desktop CPython via `pytest`, with hand-written stubs (`tests/stubs/`) standing in for MicroPython-only modules like `machine`, `network`, `ujson`, and `urequests`. A separate MicroPython-in-Docker smoke test (see `auto/test`) confirms the real source modules still import cleanly under the actual runtime. Run `uv sync && uv run pytest tests/ -v` to execute the suite.

Device configuration is split across four files, each with its own load/save pair in `src/config.py`: `wifi.json` (ssid/password, gitignored), `app.json` (backend API url/token + heartbeat interval, gitignored), `device.json` (device name, location, hardware wiring), and `ota.json` (update channel, check interval, installed version, source repo). `wifi.json.template` and `app.json.template` show the expected shape for the two gitignored ones.

OTA updates pull from GitHub Releases on this repo via `mip` (see `src/ota.py`, `package.json`). By default a device tracks the `stable` channel (the newest non-prerelease, non-draft release). Set `"channel": "canary"` in a device's `ota.json` to have it track the very latest release instead, prerelease or not — handy for a canary device you want to validate a build on before promoting it to a full release.

The one big change is that now the barcode scanner needs to support UART/TTL. Some barcodes will say they support UART/TTL, but what they might mean is that it has a USB-TTL chip on-board, without you being able to access the actual TTL signal from some of the pins.

[This scanner](https://www.aliexpress.com/item/33036582612.html?spm=a2g0o.order_list.order_list_main.16.3338180282L2i6) from AliExpress is just the ticket. It has TTL pins, and I was able to fit a rpi-pico-w into the case, hook up the USB data lines to the MCU.

Additionally, it supports having the wifi connection re-configured by scanning the wifi sharing QR codes, so the box doesn't need to be opened to change basic configuration.


KEY="WuBhAUoTo1amIQbE3pquT1kSEZOzQWRl8ghX4Zzh"

curl -H 'content-type: application/json' https://reporter-dev.khanom.xyz/scans/ -d '{"code":"321321321","location":"montreal","scanned_at":"2026-06-21T22:46:49+07"}' -H "X-API-Key: ${KEY}"
