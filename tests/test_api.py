import pytest
import json


OTA_DATA = {
    "github_repo": "snacker-tracker/pico-scanner",
    "version": "1.0.0-abc-app",
}

DEVICE = {
    "device_name": "rpi-pico-w-01",
}

APP = {
    "api": {
        "url": "https://reporter.example.com",
        "token": "test-token",
    }
}


def test_user_agent_contains_github_repo_and_version():
    from api import _user_agent

    ua = _user_agent(OTA_DATA, DEVICE)
    assert "snacker-tracker/pico-scanner" in ua
    assert "1.0.0-abc-app" in ua
    assert "rpi-pico-w-01" in ua


def test_user_agent_handles_missing_data():
    from api import _user_agent

    ua = _user_agent({}, {})
    assert "unknown" in ua


def test_post_scan_sends_correct_payload(requests_mock):
    requests_mock.post(
        "https://reporter.example.com/scans",
        json={
            "id": "scan-123",
            "code": "1234567890128",
            "scanned_at": "2026-07-16T00:00:00Z",
        },
        status_code=201,
    )

    from api import post_scan

    result = post_scan("1234567890128", "building:room:spot", APP, OTA_DATA, DEVICE)

    assert result["id"] == "scan-123"
    assert result["code"] == "1234567890128"

    history = requests_mock.last_request
    body = json.loads(history.text)
    assert body["code"] == "1234567890128"
    assert body["location"] == "building:room:spot"
    assert history.headers["X-API-Key"] == "test-token"
    assert history.headers["Content-Type"] == "application/json"


def test_post_scan_raises_on_4xx(requests_mock):
    requests_mock.post(
        "https://reporter.example.com/scans",
        json={"error": "unauthorized"},
        status_code=401,
    )

    from api import post_scan

    with pytest.raises(RuntimeError, match="401"):
        post_scan("1234567890128", "loc", APP, OTA_DATA, DEVICE)


def test_post_scan_raises_on_5xx(requests_mock):
    requests_mock.post("https://reporter.example.com/scans", status_code=500)

    from api import post_scan

    with pytest.raises(RuntimeError, match="500"):
        post_scan("1234567890128", "loc", APP, OTA_DATA, DEVICE)


def test_send_heartbeat_sends_correct_payload(requests_mock):
    requests_mock.post(
        "https://reporter.example.com/heartbeat", json={"ok": True}, status_code=200
    )

    from api import send_heartbeat

    result = send_heartbeat("building:room:spot", APP, OTA_DATA, DEVICE, 123)

    assert result["ok"] is True

    history = requests_mock.last_request
    body = json.loads(history.text)
    assert body["location"] == "building:room:spot"
    assert body["version"] == "1.0.0-abc-app"
    assert body["device_name"] == "rpi-pico-w-01"
    assert body["uptime"] == 123
    assert history.headers["X-API-Key"] == "test-token"
    assert history.headers["Content-Type"] == "application/json"


def test_send_heartbeat_includes_telemetry(requests_mock):
    requests_mock.post(
        "https://reporter.example.com/heartbeat", json={"ok": True}, status_code=200
    )

    from api import send_heartbeat

    send_heartbeat(
        "building:room:spot",
        APP,
        OTA_DATA,
        DEVICE,
        123,
        telemetry={"mem_free": "12345", "reset_cause": "power_on"},
    )

    history = requests_mock.last_request
    body = json.loads(history.text)
    assert body["telemetry"] == {"mem_free": "12345", "reset_cause": "power_on"}


def test_send_heartbeat_includes_device_identity(requests_mock):
    requests_mock.post(
        "https://reporter.example.com/heartbeat", json={"ok": True}, status_code=200
    )

    from api import send_heartbeat

    send_heartbeat(
        "building:room:spot",
        APP,
        OTA_DATA,
        DEVICE,
        123,
        device_identity={
            "board_model": "Raspberry Pi Pico W with RP2040",
            "micropython_version": "1.22.0",
            "serial_number": "e6614c775f7a2b34",
        },
    )

    history = requests_mock.last_request
    body = json.loads(history.text)
    assert body["board_model"] == "Raspberry Pi Pico W with RP2040"
    assert body["micropython_version"] == "1.22.0"
    assert body["serial_number"] == "e6614c775f7a2b34"


def test_send_heartbeat_raises_on_4xx(requests_mock):
    requests_mock.post(
        "https://reporter.example.com/heartbeat",
        json={"error": "unauthorized"},
        status_code=401,
    )

    from api import send_heartbeat

    with pytest.raises(RuntimeError, match="401"):
        send_heartbeat("loc", APP, OTA_DATA, DEVICE, 0)


def test_send_heartbeat_raises_on_5xx(requests_mock):
    requests_mock.post("https://reporter.example.com/heartbeat", status_code=500)

    from api import send_heartbeat

    with pytest.raises(RuntimeError, match="500"):
        send_heartbeat("loc", APP, OTA_DATA, DEVICE, 0)


def test_health_check_returns_true_on_success(requests_mock):
    requests_mock.get("https://reporter.example.com/v1/scans", json=[], status_code=200)

    from api import health_check

    assert health_check(APP, OTA_DATA, DEVICE) is True


def test_health_check_returns_false_on_error(requests_mock):
    requests_mock.get("https://reporter.example.com/v1/scans", status_code=500)

    from api import health_check

    assert health_check(APP, OTA_DATA, DEVICE) is False


def test_health_check_returns_false_on_network_error(requests_mock):
    import requests

    requests_mock.get(
        "https://reporter.example.com/v1/scans", exc=requests.exceptions.ConnectionError
    )

    from api import health_check

    assert health_check(APP, OTA_DATA, DEVICE) is False
