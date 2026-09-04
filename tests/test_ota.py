import json


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
