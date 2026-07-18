import urequests as requests
import ujson
import utarfile
import os

# Base URL where {device_name}.json manifests are served from
OTA_BASE = "https://micropython-continuous-delivery.s3-ap-southeast-1.amazonaws.com"

print("importing OTA")


def check_and_apply(config, manifest):
    device_name = config.get('device_name', 'unknown')
    manifest_url = OTA_BASE + "/" + device_name + ".json"

    try:
        res = requests.get(manifest_url)
        if res.status_code != 200:
            print("OTA manifest fetch failed: " + str(res.status_code))
            return False
        remote = res.json()
    except Exception as e:
        print("OTA manifest error: " + str(e))
        return False

    current_version = manifest.get('version', '')
    remote_version = remote.get('version', '')

    if remote_version == current_version:
        print("OTA: up to date (" + current_version + ")")
        return False

    print("OTA: updating " + current_version + " -> " + remote_version)
    return _apply(remote)


def _apply(remote_manifest):
    try:
        res = requests.get(remote_manifest['package_url'])
        with open('update.tar', 'wb') as f:
            f.write(res.content)

        tar = utarfile.TarFile('update.tar')
        for info in tar:
            if info.type == utarfile.DIRTYPE:
                try:
                    os.mkdir(info.name)
                except OSError:
                    pass
            else:
                extracted = tar.extractfile(info)
                with open(info.name, 'wb') as dst:
                    while True:
                        buf = extracted.read(512)
                        if not buf:
                            break
                        dst.write(buf)

        from config import save_manifest
        save_manifest(remote_manifest)

        try:
            os.remove('update.tar')
        except OSError:
            pass

        print("OTA: applied " + remote_manifest.get('version', '?'))
        return True

    except Exception as e:
        print("OTA apply failed: " + str(e))
        return False
