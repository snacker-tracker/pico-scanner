import ujson


def load_config():
    with open('config.json') as f:
        return ujson.load(f)


def save_config(config):
    with open('config.json', 'w') as f:
        f.write(ujson.dumps(config))


def load_manifest():
    try:
        with open('manifest.json') as f:
            return ujson.load(f)
    except OSError:
        return {}


def save_manifest(manifest):
    with open('manifest.json', 'w') as f:
        f.write(ujson.dumps(manifest))
