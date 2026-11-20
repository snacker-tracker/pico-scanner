import json
from pathlib import Path

import pytest

DEVICES_URL = (
    "https://raw.githubusercontent.com/snacker-tracker/pico-scanner/master/devices.json"
)
RELEASES_URL = (
    "https://api.github.com/repos/snacker-tracker/pico-scanner/releases/latest"
)
CANARY_RELEASES_URL = (
    "https://api.github.com/repos/snacker-tracker/pico-scanner/releases"
)
# hexlify of the machine stub's unique_id()
DEVICE_ID = "e6614103e7574d23"
LOCAL_DEVICE = {
    "device_name": "rpi-pico-w-02",
    "location": "thailand:bangkok:home",
    "hardware": {"uart": {"device": 1, "tx_pin": 4, "rx_pin": 5}},
}


@pytest.fixture
def local_device(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "device.json").write_text(json.dumps(LOCAL_DEVICE))
    return tmp_path


def _overlay(tmp_path):
    path = tmp_path / "remote.json"
    return json.loads(path.read_text()) if path.exists() else {}


def _serve(requests_mock, devices):
    requests_mock.get(DEVICES_URL, json={"devices": devices})


def test_listed_device_gets_overlay(requests_mock, local_device):
    _serve(
        requests_mock,
        {
            DEVICE_ID: {
                "device": {"location": "montreal:bar:till"},
                "ota": {"channel": "canary"},
            }
        },
    )

    import remote

    assert remote.sync() is True
    assert _overlay(local_device) == {
        "device": {"location": "montreal:bar:till"},
        "ota": {"channel": "canary"},
    }
    # The local file is never rewritten by remote config.
    assert json.loads((local_device / "device.json").read_text()) == LOCAL_DEVICE


def test_unchanged_overlay_is_not_rewritten(requests_mock, local_device, monkeypatch):
    _serve(requests_mock, {DEVICE_ID: {"device": {"location": "montreal:bar:till"}}})

    import config
    import remote

    assert remote.sync() is True
    saves = []
    monkeypatch.setattr(config, "save_overlay", lambda o: saves.append(o))
    assert remote.sync() is False
    assert saves == []


def test_removing_entry_reverts_to_local_config(requests_mock, local_device):
    import config
    import remote

    _serve(requests_mock, {DEVICE_ID: {"device": {"location": "montreal:bar:till"}}})
    remote.sync()
    assert config.load("device")["location"] == "montreal:bar:till"

    _serve(requests_mock, {"someotherdevice0": {"device": {"location": "x:y:z"}}})
    assert remote.sync() is True
    assert _overlay(local_device) == {}
    assert config.load("device")["location"] == "thailand:bangkok:home"


def test_channel_overlay_reaches_the_ota_config(requests_mock, local_device):
    import config
    import remote

    _serve(requests_mock, {DEVICE_ID: {"ota": {"channel": "canary"}}})
    remote.sync()
    assert config.load("ota")["channel"] == "canary"


@pytest.mark.parametrize(
    "response",
    [
        {"status_code": 404},
        {"exc": __import__("requests").exceptions.ConnectionError},
        {"text": "{not json"},
        {"json": ["not", "an", "object"]},
        {"json": {"devices": ["not", "a", "dict"]}},
        {"json": {"devices": {DEVICE_ID: "not-an-object"}}},
    ],
    ids=[
        "missing-file",
        "network-error",
        "malformed-json",
        "file-not-an-object",
        "devices-not-an-object",
        "entry-not-an-object",
    ],
)
def test_failed_or_malformed_lookup_keeps_current_overlay(
    requests_mock, local_device, response
):
    import remote

    (local_device / "remote.json").write_text(
        json.dumps({"device": {"location": "montreal:bar:till"}})
    )
    requests_mock.get(DEVICES_URL, **response)

    assert remote.sync() is False
    assert _overlay(local_device) == {"device": {"location": "montreal:bar:till"}}


def test_invalid_values_are_dropped_and_valid_ones_kept(requests_mock, local_device):
    import remote

    _serve(
        requests_mock,
        {
            DEVICE_ID: {
                "device": {"location": "", "device_name": "scanner-7"},
                "ota": {
                    "channel": "beta",
                    "check_interval_seconds": True,
                },
            }
        },
    )

    remote.sync()
    assert _overlay(local_device) == {"device": {"device_name": "scanner-7"}}


@pytest.mark.parametrize(
    "value",
    [0, -5, 1.5, "600", None],
    ids=["zero", "negative", "float", "string", "null"],
)
def test_bad_check_interval_is_rejected(requests_mock, local_device, value):
    import remote

    _serve(requests_mock, {DEVICE_ID: {"ota": {"check_interval_seconds": value}}})
    remote.sync()
    assert _overlay(local_device) == {}


def test_good_check_interval_is_kept(requests_mock, local_device):
    import remote

    _serve(requests_mock, {DEVICE_ID: {"ota": {"check_interval_seconds": 600}}})
    remote.sync()
    assert _overlay(local_device) == {"ota": {"check_interval_seconds": 600}}


def test_wifi_app_and_unknown_keys_are_never_applied(requests_mock, local_device):
    import remote

    _serve(
        requests_mock,
        {
            DEVICE_ID: {
                "wifi": {"ssid": "attacker", "password": "x"},
                "app": {"api": {"url": "https://evil", "token": "x"}},
                "device": {
                    "location": "a:b:c",
                    "hardware": {"uart": {"tx_pin": 0}},
                    "token": "x",
                },
            }
        },
    )

    remote.sync()
    assert _overlay(local_device) == {"device": {"location": "a:b:c"}}


def test_release_update_does_not_copy_overlay_into_ota_json(
    requests_mock, local_device, monkeypatch
):
    import config
    import ota

    (local_device / "ota.json").write_text(json.dumps({"version": "1.0.0-abc-app"}))
    (local_device / "remote.json").write_text(
        json.dumps({"ota": {"channel": "canary", "check_interval_seconds": 600}})
    )
    requests_mock.get(
        CANARY_RELEASES_URL, json=[{"tag_name": "2.0.0-rc1", "prerelease": True}]
    )
    installs = []
    monkeypatch.setattr(
        ota.mip,
        "install",
        lambda package, version=None, target=None: installs.append(version),
    )

    assert ota.check_and_apply(config.load("ota")) is True
    assert installs == ["2.0.0-rc1"]
    saved = json.loads((local_device / "ota.json").read_text())
    assert saved == {"version": "2.0.0-rc1"}


def test_repo_devices_file_is_valid():
    from remote import VALIDATORS

    import config

    data = json.loads((Path(__file__).parent.parent / "devices.json").read_text())
    assert set(data) == {"devices"}
    for device_id, entry in data["devices"].items():
        assert len(device_id) == 16 and int(device_id, 16) >= 0, device_id
        assert set(entry) <= set(config.REMOTE_KEYS), device_id
        for section, values in entry.items():
            assert set(values) <= set(config.REMOTE_KEYS[section]), (device_id, section)
            for key, value in values.items():
                assert VALIDATORS[key](value), (device_id, section, key, value)
