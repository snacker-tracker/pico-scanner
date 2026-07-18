import pytest
import json
import os


@pytest.fixture(autouse=True)
def in_tmp_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)


def test_load_config(tmp_path):
    (tmp_path / 'config.json').write_text(json.dumps({'wifi': {'ssid': 'test'}}))

    from config import load_config
    result = load_config()
    assert result['wifi']['ssid'] == 'test'


def test_load_config_missing_file_raises():
    from config import load_config
    with pytest.raises(OSError):
        load_config()


def test_save_config_then_reload(tmp_path):
    from config import save_config, load_config

    data = {'device_name': 'pico-01', 'api': {'url': 'https://x', 'token': 'tok'}}
    (tmp_path / 'config.json').write_text('{}')  # needs to exist first

    save_config(data)
    assert load_config() == data


def test_load_manifest_returns_empty_when_missing():
    from config import load_manifest
    result = load_manifest()
    assert result == {}


def test_load_manifest(tmp_path):
    manifest = {'version': '1.0.0', 'package': 'scanner'}
    (tmp_path / 'manifest.json').write_text(json.dumps(manifest))

    from config import load_manifest
    assert load_manifest() == manifest


def test_save_manifest_then_reload(tmp_path):
    from config import save_manifest, load_manifest

    data = {'version': '2.0.0', 'hardware': {'uart': {'device': 1}}}
    save_manifest(data)
    assert load_manifest() == data
