import binascii
import machine
import urequests as requests
import config
import log
import ota

logger = log.getLogger("remote")


def _devices_url(github_repo):
    # Read from master, not a release, so changing a device doesn't need a release.
    return "https://raw.githubusercontent.com/" + github_repo + "/master/devices.json"


def _device_id():
    return binascii.hexlify(machine.unique_id()).decode()


def _non_empty_str(value):
    return isinstance(value, str) and value.strip() != ""


def _positive_int(value):
    # type() rather than isinstance(): bool is a subclass of int.
    return type(value) is int and value > 0


VALIDATORS = {
    "location": _non_empty_str,
    "device_name": _non_empty_str,
    "channel": lambda value: value in ota.CHANNELS,
    "check_interval_seconds": _positive_int,
}


def _fetch_entry(github_repo):
    """Return (ok, entry). ok is False when the lookup failed, and nothing should change."""
    res = None
    try:
        res = requests.get(
            _devices_url(github_repo), headers={"user-agent": "pico-scanner-ota"}
        )
        if res.status_code != 200:
            logger.warning("remote config fetch failed: " + str(res.status_code))
            return False, None
        devices = res.json().get("devices")
        if not isinstance(devices, dict):
            logger.warning("remote config: devices is not an object")
            return False, None
    except Exception as e:
        logger.warning("remote config fetch error: " + type(e).__name__ + ": " + str(e))
        return False, None
    finally:
        if res is not None:
            res.close()
    return True, devices.get(_device_id())


def _build_overlay(entry):
    """The overlay this device's entry asks for. None means the entry is malformed."""
    overlay = {}
    if entry is None:
        return overlay
    if not isinstance(entry, dict):
        logger.warning("remote config: entry is not an object")
        return None

    for section in entry:
        if section not in config.REMOTE_KEYS:
            logger.warning("remote config: ignoring unknown section " + repr(section))

    for section, keys in config.REMOTE_KEYS.items():
        values = entry.get(section, {})
        if not isinstance(values, dict):
            logger.warning("remote config: section " + section + " is not an object")
            continue
        for key in keys:
            if key not in values:
                continue
            if VALIDATORS[key](values[key]):
                overlay.setdefault(section, {})[key] = values[key]
            else:
                logger.warning("remote config: ignoring invalid " + section + "." + key)
    return overlay


def sync(github_repo=ota.DEFAULT_GITHUB_REPO):
    """Make remote.json match this device's entry in the repo's devices.json.

    Returns True when the overlay changed, so the caller reboots and the new
    config is read at boot. A failed lookup or a malformed entry changes
    nothing. Removing this device's entry reverts it to its local config.
    """
    ok, entry = _fetch_entry(github_repo)
    if not ok:
        return False
    overlay = _build_overlay(entry)
    if overlay is None:
        return False

    current = config.load_overlay()
    if overlay == current:
        return False

    logger.info("remote config: " + str(current) + " -> " + str(overlay))
    config.save_overlay(overlay)
    return True
