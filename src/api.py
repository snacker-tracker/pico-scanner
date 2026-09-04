import sys
import urequests as requests
import ujson
import log

logger = log.getLogger("api")


def _user_agent(ota_data, device):
    return "".join(
        [
            sys.platform,
            "/",
            sys.implementation.name,
            "-",
            ".".join(map(str, list(sys.implementation.version))),
            "/",
            ota_data.get("github_repo", "unknown"),
            "-",
            ota_data.get("version", "unknown"),
            "/",
            device.get("device_name", "unknown"),
        ]
    )


def post_scan(code, location, app, ota_data, device):
    headers = {
        "content-type": "application/json",
        "X-API-Key": app["api"]["token"],
        "user-agent": _user_agent(ota_data, device),
    }

    data = ujson.dumps({"code": code, "location": location})
    url = app["api"]["url"] + "/scans"

    logger.debug(url)
    logger.debug(str(headers) + " " + data)

    res = requests.post(url, headers=headers, data=data)

    try:
        logger.debug(str(res.status_code))

        if res.status_code >= 400:
            raise RuntimeError("API error " + str(res.status_code))
        return res.json()
    finally:
        res.close()


def send_heartbeat(location, app, ota_data, device, uptime):
    headers = {
        "content-type": "application/json",
        "X-API-Key": app["api"]["token"],
        "user-agent": _user_agent(ota_data, device),
    }

    data = ujson.dumps(
        {
            "location": location,
            "version": ota_data.get("version", "unknown"),
            "device_name": device.get("device_name", "unknown"),
            "uptime": uptime,
        }
    )
    url = app["api"]["url"] + "/heartbeat"

    logger.debug(url)
    logger.debug(str(headers) + " " + data)

    res = requests.post(url, headers=headers, data=data)

    try:
        logger.debug(str(res.status_code))

        if res.status_code >= 400:
            logger.error("Heartbeat error body: " + res.text)
            raise RuntimeError("API error " + str(res.status_code))
        return res.json()
    finally:
        res.close()


def health_check(app, ota_data, device):
    res = None
    try:
        res = requests.get(
            app["api"]["url"] + "/v1/scans",
            headers={"user-agent": _user_agent(ota_data, device)},
        )
        return res.status_code < 400
    except Exception:
        return False
    finally:
        if res is not None:
            res.close()
