import machine
import config


def is_config_qr(value):
    return value.startswith('WIFI:') or value.startswith('SNACKER:')


def handle(value, wifi, app):
    if value.startswith('WIFI:'):
        _handle_wifi(value, wifi)
    elif value.startswith('SNACKER:'):
        _handle_backend(value, app)


def _parse_kv(value, prefix):
    result = {}
    for part in value[len(prefix):].split(';'):
        if ':' in part:
            k, v = part.split(':', 1)
            if k and v:
                result[k] = v
    return result


def _handle_wifi(value, wifi):
    parsed = _parse_kv(value, 'WIFI:')
    if 'S' not in parsed:
        raise ValueError('WIFI QR missing SSID')
    wifi['ssid'] = parsed['S']
    if 'P' in parsed:
        wifi['password'] = parsed['P']
    elif 'password' in wifi:
        del wifi['password']
    config.save('wifi', wifi)
    machine.reset()


def _handle_backend(value, app):
    parsed = _parse_kv(value, 'SNACKER:')
    if 'URL' not in parsed:
        raise ValueError('SNACKER QR missing URL')
    if 'TOKEN' not in parsed:
        raise ValueError('SNACKER QR missing TOKEN')
    app['api'] = {'url': parsed['URL'], 'token': parsed['TOKEN']}
    config.save('app', app)
    machine.reset()
