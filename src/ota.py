import urequests as requests
import mip
import log

logger = log.getLogger("ota")

DEFAULT_GITHUB_REPO = "snacker-tracker/pico-scanner"

logger.debug("importing OTA")


def _release_url(ota_data, github_repo):
    # /releases/latest only ever returns the newest non-prerelease, non-draft release.
    # Canary devices instead list all releases (newest first) and take the very
    # latest one, prerelease or not, so they can pick up a build before it's promoted.
    api = "https://api.github.com/repos/" + github_repo + "/releases"
    channel = ota_data.get('channel', 'stable')
    return api if channel == 'canary' else api + "/latest"


def check_and_apply(ota_data):
    github_repo = ota_data.get('github_repo', DEFAULT_GITHUB_REPO)
    res = None
    try:
        url = _release_url(ota_data, github_repo)
        logger.debug("OTA URL: " + url)
        res = requests.get(url, headers={'user-agent': 'pico-scanner-ota'})
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

    current_version = ota_data.get('version', '')
    remote_version = release.get('tag_name', '')

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
        new_ota_data['version'] = remote_version
        config.save('ota', new_ota_data)

        logger.info("OTA: applied " + remote_version)
        return True

    except Exception as e:
        logger.error("OTA apply failed: " + str(e))
        return False
