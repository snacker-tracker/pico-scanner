import pytest
from machine import ResetCalled


def test_is_config_qr_wifi():
    from qr_config import is_config_qr

    assert is_config_qr("WIFI:T:WPA;S:MyNet;P:pass;;")


def test_is_config_qr_snacker():
    from qr_config import is_config_qr

    assert is_config_qr("SNACKER:URL:https://example.com;TOKEN:abc;;")


def test_is_config_qr_rejects_barcode():
    from qr_config import is_config_qr

    assert not is_config_qr("1234567890128")
    assert not is_config_qr("https://example.com")
    assert not is_config_qr("")


def test_parse_kv_wifi():
    from qr_config import _parse_kv

    result = _parse_kv("WIFI:T:WPA;S:MyNetwork;P:MyPassword;;", "WIFI:")
    assert result == {"T": "WPA", "S": "MyNetwork", "P": "MyPassword"}


def test_parse_kv_wifi_no_password():
    from qr_config import _parse_kv

    result = _parse_kv("WIFI:T:nopass;S:OpenNet;;", "WIFI:")
    assert result == {"T": "nopass", "S": "OpenNet"}


def test_parse_kv_backend_url_with_colons():
    from qr_config import _parse_kv

    result = _parse_kv(
        "SNACKER:URL:https://reporter.example.com;TOKEN:abc123;;", "SNACKER:"
    )
    assert result["URL"] == "https://reporter.example.com"
    assert result["TOKEN"] == "abc123"


def test_handle_wifi_updates_ssid_and_password(monkeypatch):
    saved = {}

    import qr_config

    def fake_save(config_type, data):
        assert config_type == "wifi"
        saved.update(data)

    monkeypatch.setattr(qr_config.config, "save", fake_save)

    wifi = {"ssid": "old", "password": "old"}

    with pytest.raises(ResetCalled):
        qr_config._handle_wifi("WIFI:T:WPA;S:NewNet;P:NewPass;;", wifi)

    assert saved["ssid"] == "NewNet"
    assert saved["password"] == "NewPass"


def test_handle_wifi_open_network_drops_password(monkeypatch):
    saved = {}

    import qr_config

    def fake_save(config_type, data):
        assert config_type == "wifi"
        saved.update(data)

    monkeypatch.setattr(qr_config.config, "save", fake_save)

    wifi = {"ssid": "old", "password": "old"}

    with pytest.raises(ResetCalled):
        qr_config._handle_wifi("WIFI:S:OpenNet;;", wifi)

    assert saved["ssid"] == "OpenNet"
    assert "password" not in saved


def test_handle_wifi_missing_ssid_raises(monkeypatch):
    import qr_config

    monkeypatch.setattr(qr_config.config, "save", lambda t, d: None)

    with pytest.raises(ValueError, match="SSID"):
        qr_config._handle_wifi("WIFI:T:WPA;P:pass;;", {})


def test_handle_backend_updates_api(monkeypatch):
    saved = {}

    import qr_config

    def fake_save(config_type, data):
        assert config_type == "app"
        saved.update(data)

    monkeypatch.setattr(qr_config.config, "save", fake_save)

    app = {"api": {"url": "old", "token": "old"}}

    with pytest.raises(ResetCalled):
        qr_config._handle_backend(
            "SNACKER:URL:https://new.example.com;TOKEN:newtoken;;", app
        )

    assert saved["api"]["url"] == "https://new.example.com"
    assert saved["api"]["token"] == "newtoken"


def test_handle_backend_missing_url_raises(monkeypatch):
    import qr_config

    monkeypatch.setattr(qr_config.config, "save", lambda t, d: None)

    with pytest.raises(ValueError, match="URL"):
        qr_config._handle_backend("SNACKER:TOKEN:abc;;", {})


def test_handle_backend_missing_token_raises(monkeypatch):
    import qr_config

    monkeypatch.setattr(qr_config.config, "save", lambda t, d: None)

    with pytest.raises(ValueError, match="TOKEN"):
        qr_config._handle_backend("SNACKER:URL:https://x;;", {})
