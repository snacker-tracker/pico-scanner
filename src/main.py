import time
import network
import urequests as requests
import ujson
from machine import Pin, UART


if config is None:
    config = {}

if manifest is None:
    manifest = {}

UART_BAUD_RATE = manifest.get('UART', {}).get('BAUD_RATE', 9600)
UART_DEVICE = manifest.get('UART', {}).get('DEVICE', 1)
UART_RX_PIN = manifest.get('UART', {}).get('RX_PIN', 5)
UART_TX_PIN = manifest.get('UART', {}).get('TX_PIN', 4)
UART_BITS = manifest.get('UART', {}).get('BITS', 8)
UART_PARITY = manifest.get('UART', {}).get('PARITY')
UART_STOP = manifest.get('UART', {}).get('STOP', 1)

TOKEN_URL = manifest.get('OAUTH', {}).get('token_url')
CLIENT_ID = manifest.get('OAUTH', {}).get('client_id')
AUDIENCE = manifest.get('OAUTH', {}).get('audience')
CLIENT_SECRET = config.get('secrets', {}).get('CLIENT_SECRET')

REPORTER_URL = config.get('scanner', {}).get('url', "https://reporter.snacker-tracker.qa.k8s.fscker.org/v1/scans")
SCANNER_LOCATION = ":".join([
    manifest.get('location', {}).get('building', "lake-avenue"),
    manifest.get('location', {}).get('room', "home"),
    manifest.get('location', {}).get('spot', "desk"),
])


def get_oauth_token():
    print("getting token")
    response = requests.post(
        TOKEN_URL,
        headers = {
            'content-type': 'application/json'
        },

        data = ujson.dumps({
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "client_credentials",
            "audience": AUDIENCE
        })
    )

    token = response.json()

    return token['access_token']


def post_code(code, token):
    post_data = {
        'code': code,
        'location': SCANNER_LOCATION
    }

    try:
        print("posting code")
        res = requests.post(
            REPORTER_URL,
            headers = {
                'content-type': 'application/json',
                'authorization': "Bearer %s" % token
            },
            data = ujson.dumps(post_data)
        )
        print("posted")
        return res
    except OSError as e:
        print(e)
        raise e


is_wifi_configuration = lambda code: code.startswith("WIFI:")

def parse_wifi_configuration(configuration):
    # example: WIFI:T:WPA;S:MyNetwork;P:MyPassword;H:;;
    # ; in the values should be escaped w/ a \
    # but clearly, we're being naive here
    # because who puts a ; in a wifi network name or password?!
    # Later ...
    return dict(
        list(
            filter(
                # drop empty config items
                lambda x: len(x) > 1 and x[1] != '',
                list(
                    # Naive!
                    map(
                        lambda x: x.split(":"),
                        configuration[5:].split(";")
                    )
                )
            )
        )
    )

def validate_wifi_configuration(config):
    print(config)

    if 'T' in config and config['T'] in ["WPA", "WEP"]:
        if 'P' not in config:
            raise RuntimeError("WIFI Passphrase must be supplied when T is not 'no Encryption'")

    if 'S' not in config:
        raise RuntimeError("WIFI SSID must be supplied")

    return True

def save_wifi_configuration(config):
    pass

def handle_wifi_configuration(configuration):
    print("handling as WIFI configuration")
    config = parse_wifi_configuration(configuration)
    validate_wifi_configuration(config)
    save_wifi_configuration(config)

def handle_code_scan(code):
    token = get_oauth_token()

    response = post_code(code, token)
    print(response.json())

def the_loop(uart, time):
    if uart.any(): 
        try:
            value = uart.read().decode("utf-8").strip()
            print(value)

            if is_wifi_configuration(value):
                handle_wifi_configuration(value)

            else:
                handle_code_scan(value)

        except OSError as e:
            print(e)

    time.sleep_ms(50)

uart = UART(
    UART_DEVICE,
    baudrate=UART_BAUD_RATE,
    tx=Pin(UART_TX_PIN),
    rx=Pin(UART_RX_PIN)
)

uart.init(
    bits=UART_BITS,
    parity=UART_PARITY,
    stop=UART_STOP
)


i = 0
while True:
    the_loop(uart, time)

    if i % 1000 == 0:
        OTA.update()
        i = i + 1
