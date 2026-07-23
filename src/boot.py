import network
import machine
import time
import log

import config as config_module

logger = log.getLogger("boot")


def connect_wifi(wifi):
    ssid = wifi.get('ssid')
    if not ssid:
        logger.warning("No WiFi config found")
        return False

    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)

    if wlan.isconnected():
        logger.info("WiFi already connected: " + str(wlan.ifconfig()[0]))
        return True

    password = wifi.get('password', '')
    wlan.connect(ssid, password)

    for _ in range(20):
        if wlan.isconnected():
            logger.info("WiFi connected: " + str(wlan.ifconfig()[0]))
            return True
        time.sleep(1)

    logger.warning("WiFi connection timed out")
    return False


_wifi = config_module.load('wifi')
_ota_data = config_module.load('ota')

if connect_wifi(_wifi):
    try:
        import ota
        if ota.check_and_apply(_ota_data):
            machine.reset()
    except Exception as e:
        logger.error("OTA check failed: " + str(e))
