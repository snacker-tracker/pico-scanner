import json

import pytest


OTA_DATA = {"version": "1.0.0-abc-app"}
CANARY_OTA_DATA = {"version": "1.0.0-abc-app", "channel": "canary"}

RELEASES_URL = (
    "https://api.github.com/repos/snacker-tracker/pico-scanner/releases/latest"
)
CANARY_RELEASES_URL = (
    "https://api.github.com/repos/snacker-tracker/pico-scanner/releases"
)


def test_no_update_when_versions_match(requests_mock):
    requests_mock.get(RELEASES_URL, json={"tag_name": "1.0.0-abc-app"}, status_code=200)

    from ota import check_and_apply

    result = check_and_apply(OTA_DATA)
    assert result is False


def test_returns_false_on_release_fetch_failure(requests_mock):
    requests_mock.get(RELEASES_URL, status_code=404)

    from ota import check_and_apply

    result = check_and_apply(OTA_DATA)
    assert result is False


def test_returns_false_on_network_error(requests_mock):
    import requests

    requests_mock.get(RELEASES_URL, exc=requests.exceptions.ConnectionError)

    from ota import check_and_apply

    result = check_and_apply(OTA_DATA)
    assert result is False


def test_update_triggered_on_version_mismatch(requests_mock, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    requests_mock.get(RELEASES_URL, json={"tag_name": "2.0.0-def-app"}, status_code=200)

    import ota

    installs = []
    monkeypatch.setattr(
        ota.mip,
        "install",
        lambda package, version=None, target=None: installs.append(
            (package, version, target)
        ),
    )

    result = ota.check_and_apply(OTA_DATA)

    assert result is True
    assert installs == [("github:snacker-tracker/pico-scanner", "2.0.0-def-app", "/")]

    with open(tmp_path / "ota.json") as f:
        saved = json.load(f)
    assert saved["version"] == "2.0.0-def-app"


def test_returns_false_when_mip_install_fails(requests_mock, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    requests_mock.get(RELEASES_URL, json={"tag_name": "2.0.0-def-app"}, status_code=200)

    import ota

    def boom(package, version=None, target=None):
        raise RuntimeError("network died mid-install")

    monkeypatch.setattr(ota.mip, "install", boom)

    result = ota.check_and_apply(OTA_DATA)
    assert result is False
    assert not (tmp_path / "ota.json").exists()


def test_canary_channel_uses_releases_list_not_latest(requests_mock):
    latest_adapter = requests_mock.get(RELEASES_URL, json={"tag_name": "1.0.0-abc-app"})
    list_adapter = requests_mock.get(
        CANARY_RELEASES_URL, json=[{"tag_name": "1.0.0-abc-app", "prerelease": False}]
    )

    from ota import check_and_apply

    check_and_apply(CANARY_OTA_DATA)

    assert list_adapter.called
    assert not latest_adapter.called


def test_canary_channel_picks_up_prerelease(requests_mock, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    requests_mock.get(
        CANARY_RELEASES_URL, json=[{"tag_name": "2.0.0-rc1", "prerelease": True}]
    )

    import ota

    installs = []
    monkeypatch.setattr(
        ota.mip,
        "install",
        lambda package, version=None, target=None: installs.append(
            (package, version, target)
        ),
    )

    result = ota.check_and_apply(CANARY_OTA_DATA)

    assert result is True
    assert installs == [("github:snacker-tracker/pico-scanner", "2.0.0-rc1", "/")]


def test_canary_channel_returns_false_when_no_releases(requests_mock):
    requests_mock.get(CANARY_RELEASES_URL, json=[], status_code=200)

    from ota import check_and_apply

    result = check_and_apply(CANARY_OTA_DATA)
    assert result is False


def test_uses_github_repo_from_ota_data(requests_mock, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    ota_data = dict(OTA_DATA)
    ota_data["github_repo"] = "someorg/somerepo"

    requests_mock.get(
        "https://api.github.com/repos/someorg/somerepo/releases/latest",
        json={"tag_name": "2.0.0-def-app"},
        status_code=200,
    )

    import ota

    installs = []
    monkeypatch.setattr(
        ota.mip,
        "install",
        lambda package, version=None, target=None: installs.append(
            (package, version, target)
        ),
    )

    result = ota.check_and_apply(ota_data)

    assert result is True
    assert installs == [("github:someorg/somerepo", "2.0.0-def-app", "/")]


CHANNELS_URL = "https://raw.githubusercontent.com/snacker-tracker/pico-scanner/master/channels.json"
# hexlify of the machine stub's unique_id()
DEVICE_ID = "e6614103e7574d23"


def _saved_ota(tmp_path):
    path = tmp_path / "ota.json"
    return json.loads(path.read_text()) if path.exists() else None


def test_listed_device_switches_channel_and_checks_new_channel(
    requests_mock, monkeypatch, tmp_path
):
    monkeypatch.chdir(tmp_path)
    requests_mock.get(CHANNELS_URL, json={"devices": {DEVICE_ID: "canary"}})
    canary = requests_mock.get(
        CANARY_RELEASES_URL, json=[{"tag_name": "1.0.0-abc-app"}]
    )

    from ota import check_and_apply

    ota_data = dict(OTA_DATA)
    assert check_and_apply(ota_data) is False
    assert ota_data["channel"] == "canary"
    assert _saved_ota(tmp_path)["channel"] == "canary"
    assert canary.called


def test_switch_to_stable(requests_mock, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    requests_mock.get(CHANNELS_URL, json={"devices": {DEVICE_ID: "stable"}})
    stable = requests_mock.get(RELEASES_URL, json={"tag_name": "1.0.0-abc-app"})

    from ota import check_and_apply

    ota_data = dict(CANARY_OTA_DATA)
    check_and_apply(ota_data)
    assert ota_data["channel"] == "stable"
    assert _saved_ota(tmp_path)["channel"] == "stable"
    assert stable.called


def test_same_channel_is_not_rewritten(requests_mock, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    requests_mock.get(CHANNELS_URL, json={"devices": {DEVICE_ID: "canary"}})
    requests_mock.get(CANARY_RELEASES_URL, json=[{"tag_name": "1.0.0-abc-app"}])

    from ota import check_and_apply

    check_and_apply(dict(CANARY_OTA_DATA))
    assert _saved_ota(tmp_path) is None


@pytest.mark.parametrize(
    "channels_response",
    [
        {"json": {"devices": {"someotherdevice0": "canary"}}},
        {"json": {"devices": {DEVICE_ID: "beta"}}},
        {"json": {"devices": {DEVICE_ID: None}}},
        {"json": {"devices": ["not", "a", "dict"]}},
        {"json": ["not", "a", "dict"]},
        {"json": {}},
        {"text": "{not json"},
        {"status_code": 404},
        {"exc": __import__("requests").exceptions.ConnectionError},
    ],
    ids=[
        "not-listed",
        "unknown-channel",
        "null-channel",
        "devices-not-a-dict",
        "file-not-a-dict",
        "empty-file",
        "malformed-json",
        "missing-file",
        "network-error",
    ],
)
def test_bad_or_missing_channel_entry_keeps_channel_and_still_checks(
    requests_mock, monkeypatch, tmp_path, channels_response
):
    monkeypatch.chdir(tmp_path)
    requests_mock.get(CHANNELS_URL, **channels_response)
    stable = requests_mock.get(RELEASES_URL, json={"tag_name": "1.0.0-abc-app"})

    from ota import check_and_apply

    ota_data = dict(OTA_DATA)
    assert check_and_apply(ota_data) is False
    assert "channel" not in ota_data
    assert _saved_ota(tmp_path) is None
    assert stable.called


def test_repo_channels_file_is_valid():
    from pathlib import Path

    from ota import CHANNELS

    data = json.loads((Path(__file__).parent.parent / "channels.json").read_text())
    assert set(data) == {"devices"}
    for device_id, channel in data["devices"].items():
        assert len(device_id) == 16 and int(device_id, 16) >= 0, device_id
        assert channel in CHANNELS, (device_id, channel)
