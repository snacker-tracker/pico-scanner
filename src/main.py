import time
import machine
from machine import Pin, UART

import config as config_module
import api
import qr_config
import ota


_config = config_module.load_config()
_manifest = config_module.load_manifest()

_uart_cfg = _manifest.get('hardware', {}).get('uart', {})
_location = _manifest.get('scanner', {}).get('location', 'unknown:unknown:unknown')

OTA_CHECK_INTERVAL_MS = _config.get('ota', {}).get('check_interval_seconds', 1800) * 1000

uart = UART(
    _uart_cfg.get('device', 1),
    baudrate=_uart_cfg.get('baud_rate', 9600),
    tx=Pin(_uart_cfg.get('tx_pin', 4)),
    rx=Pin(_uart_cfg.get('rx_pin', 5))
)
uart.init(
    bits=_uart_cfg.get('bits', 8),
    parity=_uart_cfg.get('parity'),
    stop=_uart_cfg.get('stop', 1)
)

print("Scanner ready at " + _location)

_last_ota_check = time.ticks_ms()

while True:
    if uart.any():
        try:
            value = uart.read().decode('utf-8').strip()
            if not value:
                pass
            elif qr_config.is_config_qr(value):
                print("Config QR: " + value[:40])
                qr_config.handle(value, _config)
            else:
                print("Scan: " + value)
                scan = api.post_scan(value, _location, _config, _manifest)
                print("  -> " + scan.get('id', '?') + " at " + scan.get('scanned_at', '?'))
        except Exception as e:
            print("Error: " + str(e))

    if time.ticks_diff(time.ticks_ms(), _last_ota_check) >= OTA_CHECK_INTERVAL_MS:
        _last_ota_check = time.ticks_ms()
        try:
            if ota.check_and_apply(_config, _manifest):
                machine.reset()
        except Exception as e:
            print("OTA check failed: " + str(e))

    time.sleep_ms(100)
