import time
import gc
import os
import sys
import ubinascii
import machine
import network
from machine import Pin, UART

import config as config_module
import api
import qr_config
import ota
import log

logger = log.getLogger("main")

# Not every MicroPython port defines the same reset-cause constants, so build
# the lookup from whatever the running port actually exposes.
_RESET_CAUSE_NAMES = {
    getattr(machine, name): name
    for name in ("PWRON_RESET", "HARD_RESET", "WDT_RESET", "DEEPSLEEP_RESET", "SOFT_RESET")
    if hasattr(machine, name)
}


def _reset_cause_name():
    reset_cause = getattr(machine, "reset_cause", None)
    if reset_cause is None:
        return "unknown"
    return _RESET_CAUSE_NAMES.get(reset_cause(), "unknown")


def _build_identity(device, ota_data):
    uname = os.uname()
    return {
        "device": {
            "id": ubinascii.hexlify(machine.unique_id()).decode(),
            "name": device.get("device_name", "unknown"),
            "location": device.get("location", "unknown:unknown:unknown"),
            "board": uname.machine,
        },
        "app": {
            "name": ota_data.get("github_repo", "unknown"),
            "version": ota_data.get("version", "unknown"),
        },
        "platform": {
            "name": sys.implementation.name,
            "version": uname.release,
        },
    }


class Periodic:
    """Runs `action` at most once every `interval_ms`, tracking its own last-run time."""

    def __init__(self, interval_ms, action, run_immediately=False):
        self.interval_ms = interval_ms
        self.action = action
        now = time.ticks_ms()
        self.last_run = time.ticks_add(now, -interval_ms) if run_immediately else now

    def tick(self):
        if time.ticks_diff(time.ticks_ms(), self.last_run) >= self.interval_ms:
            self.last_run = time.ticks_ms()
            self.action()


def _make_uart(uart_cfg):
    uart = UART(
        uart_cfg.get("device", 1),
        baudrate=uart_cfg.get("baud_rate", 9600),
        tx=Pin(uart_cfg.get("tx_pin", 4)),
        rx=Pin(uart_cfg.get("rx_pin", 5)),
    )
    uart.init(
        bits=uart_cfg.get("bits", 8),
        parity=uart_cfg.get("parity"),
        stop=uart_cfg.get("stop", 1),
    )
    return uart


def _handle_uart(uart, wifi, app, ota_data, device, location):
    if not uart.any():
        return

    try:
        value = uart.read().decode("utf-8").strip()
        if not value:
            return

        if qr_config.is_config_qr(value):
            logger.info("Config QR: " + value[:40])
            qr_config.handle(value, wifi, app)
        else:
            logger.info("Scan: " + value)
            scan = api.post_scan(value, location, app, ota_data, device)
            logger.info(
                "  -> " + scan.get("id", "?") + " at " + scan.get("scanned_at", "?")
            )
    except Exception as e:
        logger.error("Error: " + str(e))


def _check_ota(ota_data):
    try:
        if ota.check_and_apply(ota_data):
            machine.reset()
    except Exception as e:
        logger.error("OTA check failed: " + str(e))


def _send_heartbeat(app, ota_data, device, boot_ticks, identity):
    try:
        # ticks_ms wraps every ~12 days; ticks_diff handles one wrap correctly,
        # so uptime stays accurate as long as reboots happen more often than that.
        uptime_ms = time.ticks_diff(time.ticks_ms(), boot_ticks)
        wlan = network.WLAN(network.STA_IF)
        telemetry = {
            "uptime": uptime_ms // 1000,
            "mem_free": gc.mem_free(),
            "reset_cause": _reset_cause_name(),
            "wifi_ssid": str(wlan.config("ssid")),
            "wifi_rssi": wlan.status("rssi"),
        }
        api.send_heartbeat(app, ota_data, device, identity, telemetry)
    except Exception as e:
        logger.error("Heartbeat failed: " + str(e))


def run():
    wifi = config_module.load("wifi")
    device = config_module.load("device")
    app = config_module.load("app")
    ota_data = config_module.load("ota")

    uart_cfg = device.get("hardware", {}).get("uart", {})
    location = device.get("location", "unknown:unknown:unknown")

    uart = _make_uart(uart_cfg)
    boot_ticks = time.ticks_ms()
    identity = _build_identity(device, ota_data)

    ota_task = Periodic(
        ota_data.get("check_interval_seconds", 1800) * 1000,
        lambda: _check_ota(ota_data),
    )
    heartbeat_task = Periodic(
        app.get("heartbeat", {}).get("interval_seconds", 300) * 1000,
        lambda: _send_heartbeat(app, ota_data, device, boot_ticks, identity),
        run_immediately=True,
    )

    logger.info("Scanner ready at " + location)

    while True:
        ota_task.tick()
        heartbeat_task.tick()
        _handle_uart(uart, wifi, app, ota_data, device, location)
        gc.collect()
        time.sleep_ms(100)


run()
