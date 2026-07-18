import network
import machine
import time
import ujson
import log

logger = log.getLogger("boot")


def connect_wifi(config):
    wifi = config.get('wifi', {})
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


try:
    with open('config.json') as f:
        _config = ujson.load(f)
except OSError:
    logger.warning("No config.json found — create one from config.json.template")
    _config = {}

try:
    with open('manifest.json') as f:
        _manifest = ujson.load(f)
except OSError:
    _manifest = {}

if connect_wifi(_config):
    try:
        import ota
        logger.debug(str(dir(ota)))
        if ota.check_and_apply(_config, _manifest):
            machine.reset()
    except Exception as e:
        logger.error("OTA check failed: " + str(e))
