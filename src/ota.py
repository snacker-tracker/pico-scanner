import urequests as requests
import mip

GITHUB_REPO = "snacker-tracker/pico-scanner"
GITHUB_RELEASES_API = "https://api.github.com/repos/" + GITHUB_REPO + "/releases"
# /releases/latest only ever returns the newest non-prerelease, non-draft release.
# Canary devices instead list all releases (newest first) and take the very
# latest one, prerelease or not, so they can pick up a build before it's promoted.
STABLE_RELEASE_URL = GITHUB_RELEASES_API + "/latest"
CANARY_RELEASE_URL = GITHUB_RELEASES_API

print("importing OTA")


def _release_url(config):
    channel = config.get('ota', {}).get('channel', 'stable')
    return CANARY_RELEASE_URL if channel == 'canary' else STABLE_RELEASE_URL


def check_and_apply(config, manifest):
    try:
        res = requests.get(_release_url(config), headers={'user-agent': 'pico-scanner-ota'})
        if res.status_code != 200:
            print("OTA release fetch failed: " + str(res.status_code))
            return False
        body = res.json()
        release = body[0] if isinstance(body, list) else body
        if not release:
            print("OTA: no releases available")
            return False
    except Exception as e:
        print("OTA release error: " + str(e))
        return False

    current_version = manifest.get('version', '')
    remote_version = release.get('tag_name', '')

    if not remote_version or remote_version == current_version:
        print("OTA: up to date (" + current_version + ")")
        return False

    print("OTA: updating " + current_version + " -> " + remote_version)
    return _apply(remote_version, manifest)


def _apply(remote_version, manifest):
    try:
        mip.install("github:" + GITHUB_REPO, version=remote_version, target="/")

        from config import save_manifest
        new_manifest = dict(manifest)
        new_manifest['version'] = remote_version
        save_manifest(new_manifest)

        print("OTA: applied " + remote_version)
        return True

    except Exception as e:
        print("OTA apply failed: " + str(e))
        return False
