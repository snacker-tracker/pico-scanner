import sys
import urequests as requests
import ujson


def _user_agent(manifest):
    return "".join([
        sys.platform, "/",
        sys.implementation.name, "-",
        ".".join(map(str, list(sys.implementation.version))),
        "/", manifest.get('package', 'unknown'), "-", manifest.get('version', 'unknown')
    ])


def post_scan(code, location, config, manifest):
    headers = {
        'content-type': 'application/json',
        #'authorization': "Bearer " + config['api']['token'],
        'X-API-Key': config['api']['token'],
        'user-agent': _user_agent(manifest)
    }

    data = ujson.dumps({'code': code, 'location': location})
    url = config['api']['url'] + "/scans"

    print(url)
    print(headers, data)

    res = requests.post(
        url,
        headers=headers,
        data=data
    )

    print(res.status_code)

    if res.status_code >= 400:
        raise RuntimeError("API error " + str(res.status_code))
    return res.json()


def health_check(config, manifest):
    try:
        res = requests.get(
            config['api']['url'] + "/v1/scans",
            headers={'user-agent': _user_agent(manifest)}
        )
        return res.status_code < 400
    except Exception:
        return False
