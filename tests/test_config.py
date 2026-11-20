import json

import pytest


@pytest.fixture(autouse=True)
def in_tmp_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)


@pytest.mark.parametrize(
    "config_type,filename",
    [
        ("wifi", "wifi.json"),
        ("device", "device.json"),
        ("app", "app.json"),
        ("ota", "ota.json"),
    ],
)
class TestLoadSave:
    def test_load_returns_empty_when_missing(self, config_type, filename):
        import config

        assert config.load(config_type) == {}

    def test_save_then_load_round_trips(self, config_type, filename):
        import config

        data = {"k": "v"}
        config.save(config_type, data)
        assert config.load(config_type) == data

    def test_save_writes_to_the_right_file(self, tmp_path, config_type, filename):
        import config

        config.save(config_type, {"k": "v"})
        assert (tmp_path / filename).exists()


def test_load_unknown_type_raises():
    import config

    with pytest.raises(KeyError):
        config.load("nonsense")


def test_save_unknown_type_raises():
    import config

    with pytest.raises(KeyError):
        config.save("nonsense", {})


DEVICE = {
    "device_name": "rpi-pico-w-02",
    "location": "thailand:bangkok:home",
    "hardware": {"uart": {"device": 1, "tx_pin": 4, "rx_pin": 5}},
}


class TestRemoteOverlay:
    @pytest.fixture(autouse=True)
    def local_files(self, tmp_path):
        (tmp_path / "device.json").write_text(json.dumps(DEVICE))

    def _overlay(self, data):
        import config

        config.save_overlay(data)

    def test_overlay_wins_for_allowed_keys_only(self):
        import config

        self._overlay({"device": {"location": "montreal:bar:till"}})
        loaded = config.load("device")
        assert loaded["location"] == "montreal:bar:till"
        assert loaded["device_name"] == DEVICE["device_name"]
        assert loaded["hardware"] == DEVICE["hardware"]

    def test_overlay_cannot_replace_hardware(self):
        import config

        self._overlay({"device": {"hardware": {"uart": {"tx_pin": 0}}}})
        assert config.load("device")["hardware"] == DEVICE["hardware"]

    def test_load_local_ignores_overlay(self):
        import config

        self._overlay({"device": {"location": "montreal:bar:till"}})
        assert config.load_local("device")["location"] == DEVICE["location"]

    def test_overlay_for_another_config_type_is_ignored(self):
        import config

        self._overlay({"wifi": {"ssid": "attacker"}})
        assert config.load("wifi") == {}

    def test_corrupt_overlay_falls_back_to_local(self, tmp_path):
        import config

        (tmp_path / "remote.json").write_text("{not json")
        assert config.load("device") == DEVICE

    def test_save_does_not_persist_overlay_values(self):
        import config

        self._overlay({"device": {"location": "montreal:bar:till"}})
        config.save("device", config.load_local("device"))
        assert config.load_local("device")["location"] == DEVICE["location"]
