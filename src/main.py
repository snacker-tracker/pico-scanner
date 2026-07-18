import time
import machine
from machine import Pin, UART

import config as config_module
import api
import qr_config
import ota
import log

logger = log.getLogger("main")


class Periodic:
    """Runs `action` at most once every `interval_ms`, tracking its own last-run time."""

    def __init__(self, interval_ms, action):
        self.interval_ms = interval_ms
        self.action = action
        self.last_run = time.ticks_ms()

    def tick(self):
        if time.ticks_diff(time.ticks_ms(), self.last_run) >= self.interval_ms:
            self.last_run = time.ticks_ms()
            self.action()


def _make_uart(uart_cfg):
    uart = UART(
        uart_cfg.get('device', 1),
        baudrate=uart_cfg.get('baud_rate', 9600),
        tx=Pin(uart_cfg.get('tx_pin', 4)),
        rx=Pin(uart_cfg.get('rx_pin', 5))
    )
    uart.init(
        bits=uart_cfg.get('bits', 8),
        parity=uart_cfg.get('parity'),
        stop=uart_cfg.get('stop', 1)
    )
    return uart


def _handle_uart(uart, config, manifest, location):
    if not uart.any():
        return

    try:
        value = uart.read().decode('utf-8').strip()
        if not value:
            return

        if qr_config.is_config_qr(value):
            logger.info("Config QR: " + value[:40])
            qr_config.handle(value, config)
        else:
            logger.info("Scan: " + value)
            scan = api.post_scan(value, location, config, manifest)
            logger.info("  -> " + scan.get('id', '?') + " at " + scan.get('scanned_at', '?'))
    except Exception as e:
        logger.error("Error: " + str(e))


def _check_ota(config, manifest):
    try:
        if ota.check_and_apply(config, manifest):
            machine.reset()
    except Exception as e:
        logger.error("OTA check failed: " + str(e))


def _send_heartbeat(config, manifest, location, boot_ticks):
    try:
        # ticks_ms wraps every ~12 days; ticks_diff handles one wrap correctly,
        # so uptime stays accurate as long as reboots happen more often than that.
        uptime_ms = time.ticks_diff(time.ticks_ms(), boot_ticks)
        api.send_heartbeat(location, config, manifest, uptime_ms)
    except Exception as e:
        logger.error("Heartbeat failed: " + str(e))


def run():
    config = config_module.load_config()
    manifest = config_module.load_manifest()

    uart_cfg = manifest.get('hardware', {}).get('uart', {})
    location = manifest.get('scanner', {}).get('location', 'unknown:unknown:unknown')

    uart = _make_uart(uart_cfg)
    boot_ticks = time.ticks_ms()

    ota_task = Periodic(
        config.get('ota', {}).get('check_interval_seconds', 1800) * 1000,
        lambda: _check_ota(config, manifest)
    )
    heartbeat_task = Periodic(
        config.get('heartbeat', {}).get('interval_seconds', 300) * 1000,
        lambda: _send_heartbeat(config, manifest, location, boot_ticks)
    )

    logger.info("Scanner ready at " + location)

    while True:
        _handle_uart(uart, config, manifest, location)
        ota_task.tick()
        heartbeat_task.tick()
        time.sleep_ms(100)


run()
