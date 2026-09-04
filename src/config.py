import ujson
import log

logger = log.getLogger("config")

_FILENAMES = {
    "wifi": "wifi.json",
    "device": "device.json",
    "app": "app.json",
    "ota": "ota.json",
}


def load(config_type):
    filename = _FILENAMES[config_type]
    try:
        with open(filename) as f:
            data = ujson.load(f)
            logger.debug("read " + filename + " " + str(data))
            return data
    except OSError:
        logger.warning(filename + " not found, using {}")
        return {}


def save(config_type, data):
    filename = _FILENAMES[config_type]
    with open(filename, "w") as f:
        f.write(ujson.dumps(data))
    logger.debug("wrote " + filename + " " + str(data))
