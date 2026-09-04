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
