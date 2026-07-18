import pytest
import json


CONFIG = {'device_name': 'rpi-pico-w-01'}
CURRENT_MANIFEST = {'version': '1.0.0-abc-app', 'package': 'scanner'}


def test_no_update_when_versions_match(requests_mock):
    requests_mock.get(
        'https://micropython-continuous-delivery.s3-ap-southeast-1.amazonaws.com/rpi-pico-w-01.json',
        json={'version': '1.0.0-abc-app', 'package_url': 'https://x/pkg.tar'},
        status_code=200
    )

    from ota import check_and_apply
    result = check_and_apply(CONFIG, CURRENT_MANIFEST)
    assert result is False


def test_returns_false_on_manifest_fetch_failure(requests_mock):
    requests_mock.get(
        'https://micropython-continuous-delivery.s3-ap-southeast-1.amazonaws.com/rpi-pico-w-01.json',
        status_code=404
    )

    from ota import check_and_apply
    result = check_and_apply(CONFIG, CURRENT_MANIFEST)
    assert result is False


def test_returns_false_on_network_error(requests_mock):
    import requests
    requests_mock.get(
        'https://micropython-continuous-delivery.s3-ap-southeast-1.amazonaws.com/rpi-pico-w-01.json',
        exc=requests.exceptions.ConnectionError
    )

    from ota import check_and_apply
    result = check_and_apply(CONFIG, CURRENT_MANIFEST)
    assert result is False


def test_manifest_url_uses_device_name(requests_mock):
    adapter = requests_mock.get(
        'https://micropython-continuous-delivery.s3-ap-southeast-1.amazonaws.com/my-device.json',
        json={'version': '1.0.0-abc-app'},
        status_code=200
    )

    from ota import check_and_apply
    check_and_apply({'device_name': 'my-device'}, CURRENT_MANIFEST)
    assert adapter.called


def test_update_triggered_on_version_mismatch(requests_mock, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    remote = {
        'version': '2.0.0-def-app',
        'package_url': 'https://example.com/pkg.tar',
    }
    requests_mock.get(
        'https://micropython-continuous-delivery.s3-ap-southeast-1.amazonaws.com/rpi-pico-w-01.json',
        json=remote
    )

    # Return a minimal valid tar (empty, just enough to not crash)
    requests_mock.get('https://example.com/pkg.tar', content=b'')

    import ota
    monkeypatch.setattr(ota, '_apply', lambda manifest: True)

    result = ota.check_and_apply(CONFIG, CURRENT_MANIFEST)
    assert result is True
