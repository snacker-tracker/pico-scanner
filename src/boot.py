import network
import machine
import time
import ujson


def connect_wifi(config):
    wifi = config.get('wifi', {})
    ssid = wifi.get('ssid')
    if not ssid:
        print("No WiFi config found")
        return False

    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)

    if wlan.isconnected():
        print("WiFi already connected: " + str(wlan.ifconfig()[0]))
        return True

    password = wifi.get('password', '')
    wlan.connect(ssid, password)

    for _ in range(20):
        if wlan.isconnected():
            print("WiFi connected: " + str(wlan.ifconfig()[0]))
            return True
        time.sleep(1)

    print("WiFi connection timed out")
    return False


try:
    with open('config.json') as f:
        _config = ujson.load(f)
except OSError:
    print("No config.json found — create one from config.json.template")
    _config = {}

try:
    with open('manifest.json') as f:
        _manifest = ujson.load(f)
except OSError:
    _manifest = {}

if connect_wifi(_config):
    try:
        import ota
        print(dir(ota))
        if ota.check_and_apply(_config, _manifest):
            machine.reset()
    except Exception as e:
        print("OTA check failed: " + str(e))
