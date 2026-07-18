import machine
from config import save_config


def is_config_qr(value):
    return value.startswith('WIFI:') or value.startswith('SNACKER:')


def handle(value, config):
    if value.startswith('WIFI:'):
        _handle_wifi(value, config)
    elif value.startswith('SNACKER:'):
        _handle_backend(value, config)


def _parse_kv(value, prefix):
    result = {}
    for part in value[len(prefix):].split(';'):
        if ':' in part:
            k, v = part.split(':', 1)
            if k and v:
                result[k] = v
    return result


def _handle_wifi(value, config):
    parsed = _parse_kv(value, 'WIFI:')
    if 'S' not in parsed:
        raise ValueError('WIFI QR missing SSID')
    config['wifi'] = {'ssid': parsed['S']}
    if 'P' in parsed:
        config['wifi']['password'] = parsed['P']
    save_config(config)
    machine.reset()


def _handle_backend(value, config):
    parsed = _parse_kv(value, 'SNACKER:')
    if 'URL' not in parsed:
        raise ValueError('SNACKER QR missing URL')
    if 'TOKEN' not in parsed:
        raise ValueError('SNACKER QR missing TOKEN')
    config['api'] = {'url': parsed['URL'], 'token': parsed['TOKEN']}
    save_config(config)
    machine.reset()
