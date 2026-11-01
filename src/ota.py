import binascii
import machine
import urequests as requests
import mip
import log

logger = log.getLogger("ota")

DEFAULT_GITHUB_REPO = "snacker-tracker/pico-scanner"
CHANNELS = ("stable", "canary")

logger.debug("importing OTA")


def _release_url(ota_data, github_repo):
    # /releases/latest only ever returns the newest non-prerelease, non-draft release.
    # Canary devices instead list all releases (newest first) and take the very
    # latest one, prerelease or not, so they can pick up a build before it's promoted.
    api = "https://api.github.com/repos/" + github_repo + "/releases"
    channel = ota_data.get("channel", "stable")
    return api if channel == "canary" else api + "/latest"


def _channels_url(github_repo):
    # Read from master, not a release, so moving a device doesn't need a release.
    return "https://raw.githubusercontent.com/" + github_repo + "/master/channels.json"


def _device_id():
    return binascii.hexlify(machine.unique_id()).decode()


def _sync_channel(ota_data, github_repo):
    """Adopt the channel channels.json in the repo assigns to this device.

    Devices that aren't listed keep their channel, and so does every device if
    the file can't be fetched or parsed: a broken file never changes anything.
    """
    res = None
    try:
        res = requests.get(
            _channels_url(github_repo), headers={"user-agent": "pico-scanner-ota"}
        )
        if res.status_code != 200:
            logger.warning("OTA channel lookup failed: " + str(res.status_code))
            return
        wanted = res.json().get("devices", {}).get(_device_id())
    except Exception as e:
        logger.warning("OTA channel lookup error: " + type(e).__name__ + ": " + str(e))
        return
    finally:
        if res is not None:
            res.close()

    if wanted is None:
        return
    if wanted not in CHANNELS:
        logger.warning("OTA: ignoring unknown channel " + repr(wanted))
        return
    current = ota_data.get("channel", "stable")
    if wanted == current:
        return

    logger.info("OTA: channel " + current + " -> " + wanted)
    ota_data["channel"] = wanted
    import config

    config.save("ota", ota_data)


def check_and_apply(ota_data):
    github_repo = ota_data.get("github_repo", DEFAULT_GITHUB_REPO)
    _sync_channel(ota_data, github_repo)
    res = None
    try:
        url = _release_url(ota_data, github_repo)
        logger.debug("OTA URL: " + url)
        res = requests.get(url, headers={"user-agent": "pico-scanner-ota"})
        if res.status_code != 200:
            logger.warning("OTA release fetch failed: " + str(res.status_code))
            return False
        body = res.json()
        release = body[0] if isinstance(body, list) else body
        if not release:
            logger.info("OTA: no releases available")
            return False
    except Exception as e:
        logger.error("OTA release error: " + str(e))
        return False
    finally:
        if res is not None:
            res.close()

    current_version = ota_data.get("version", "")
    remote_version = release.get("tag_name", "")

    if not remote_version or remote_version == current_version:
        logger.info("OTA: up to date (" + current_version + ")")
        return False

    logger.info("OTA: updating " + current_version + " -> " + remote_version)
    return _apply(remote_version, ota_data, github_repo)


def _apply(remote_version, ota_data, github_repo):
    try:
        mip.install("github:" + github_repo, version=remote_version, target="/")

        import config

        new_ota_data = dict(ota_data)
        new_ota_data["version"] = remote_version
        config.save("ota", new_ota_data)

        logger.info("OTA: applied " + remote_version)
        return True

    except Exception as e:
        logger.error("OTA apply failed: " + str(e))
        return False
