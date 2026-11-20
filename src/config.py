import ujson
import log

logger = log.getLogger("config")

_FILENAMES = {
    "wifi": "wifi.json",
    "device": "device.json",
    "app": "app.json",
    "ota": "ota.json",
}

# Written by remote.sync() from the repo's devices.json, never by hand. It
# holds only the keys listed here, per config type, and load() lets them win
# over the local file. Anything not listed (Wi-Fi, the API token, hardware
# pins) can only come from the device's own files.
OVERLAY_FILENAME = "remote.json"
REMOTE_KEYS = {
    "device": ("location", "device_name"),
    "ota": ("channel", "check_interval_seconds"),
}


def load_local(config_type):
    """The config type's own file, without the remote overlay."""
    filename = _FILENAMES[config_type]
    try:
        with open(filename) as f:
            data = ujson.load(f)
            logger.debug("read " + filename + " " + str(data))
            return data
    except OSError:
        logger.warning(filename + " not found, using {}")
        return {}


def load(config_type):
    """The effective config: the local file, with any remote overlay applied."""
    data = load_local(config_type)
    overlay = load_overlay().get(config_type, {})
    for key in REMOTE_KEYS.get(config_type, ()):
        if key in overlay:
            data[key] = overlay[key]
    return data


def save(config_type, data):
    filename = _FILENAMES[config_type]
    with open(filename, "w") as f:
        f.write(ujson.dumps(data))
    logger.debug("wrote " + filename + " " + str(data))


def load_overlay():
    try:
        with open(OVERLAY_FILENAME) as f:
            data = ujson.load(f)
    except (OSError, ValueError):
        # A missing or corrupt overlay must never stop boot: fall back to local.
        return {}
    return data if isinstance(data, dict) else {}


def save_overlay(overlay):
    with open(OVERLAY_FILENAME, "w") as f:
        f.write(ujson.dumps(overlay))
    logger.debug("wrote " + OVERLAY_FILENAME + " " + str(overlay))
