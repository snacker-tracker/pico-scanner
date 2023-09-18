import time
import urequests as requests
import ujson
import sys
from machine import Pin, UART


if config is None:
    config = {}

if manifest is None:
    manifest = {}

try:
    import logging

    logging.basicConfig(level=logging.INFO)

except ImportError as error:
    class LoggingStub:
        def debug(self, msg):
            print(msg)

        def info(self, msg):
            print(msg)

        def warning(self, msg):
            print(msg)

        def error(self, msg):
            print(msg)

        def critical(self, msg):
            print(msg)

        def getLogger(self, context):
            return self

    logging = LoggingStub()

logger = logging.getLogger("main")

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

REPORTER_URL = config.get('scanner', {}).get(
    'url', "https://reporter.snacker-tracker.qa.k8s.fscker.org"
)
SCANNER_LOCATION = ":".join([
    manifest.get('location', {}).get('building', "lake-avenue"),
    manifest.get('location', {}).get('room', "home"),
    manifest.get('location', {}).get('spot', "desk"),
])

USER_AGENT = "".join([
    sys.platform,
    "/",
    sys.implementation.name,
    "-",
    ".".join(map(str, list(sys.implementation.version))),
    "/",
    manifest['package'],
    "-",
    manifest['version']
])


def cacheable(ttl=60):
    def wrapper(func):
        cache = {True: {}}

        def caching_function(*args):
            now = time.time()
            reasons = [
                cache[True].get('value') is None,
                cache[True].get('until', 0) < now
            ]

            if True in reasons:
                cache[True]['value'] = func(*args)
                cache[True]['until'] = time.time() + ttl

            return cache[True]['value']

        return caching_function

    return wrapper


@cacheable(3600)
def get_oauth_token():
    logger.debug("Getting token")
    response = requests.post(
        TOKEN_URL,
        headers={
            'content-type': 'application/json',
            'user-agent': USER_AGENT
        },
        data=ujson.dumps({
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "client_credentials",
            "audience": AUDIENCE
        })
    )

    token = response.json()

    logger.info("Got TOKEN")

    return token['access_token']


def post_code(code, token):
    post_data = {
        'code': code,
        'location': SCANNER_LOCATION
    }

    try:
        logger.debug("Posting CODE")
        res = requests.post(
            REPORTER_URL + "/v1/scans",
            headers={
                'content-type': 'application/json',
                'authorization': "Bearer %s" % token,
                'user-agent': USER_AGENT
            },
            data=ujson.dumps(post_data)
        )
        scan = res.json()
        logger.info("Posted CODE: " + scan['code'] + " - " + scan['id'] + "@" + scan['scanned_at'])
        return res
    except OSError as e:
        print(e)
        logger.warning("Got exception in post_code")
        logger.info(str(e))
        raise e


def get_scans():
    return requests.get(
        REPORTER_URL + "/v1/scans",
        headers={
            'user-agent': USER_AGENT
        }
    )


def can_talk_to_reporter():
    try:
        logger.debug("Checking if we can talk to the internet")
        response = get_scans()
        logger.info("Can do a GET /v1/scans")
        logger.debug(ujson.dumps(response.json()))
        return True
    except Exception as e:
        logger.warning("Got exception when doing can_talk_to_reporter")
        logger.info(str(e))
        return False


def is_wifi_configuration(code):
    return code.startswith("WIFI:")


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
    if 'T' in config and config['T'] in ["WPA", "WEP"]:
        if 'P' not in config:
            error = "WIFI Passphrase is missing"
            raise RuntimeError(
                error
            )

    if 'S' not in config:
        raise RuntimeError("WIFI SSID must be supplied")

    return True


def save_wifi_configuration(config):
    current_config = ujson.load(open("device.json"))

    logger.debug("Current WIFI config: " + ujson.dumps(current_config['wifi']))

    current_config['wifi']['ssid'] = config['S']
    current_config['wifi']['password'] = config['P']

    current_config = ujson.dumps(current_config)
    logger.debug("New config: " + current_config)

    with open("device.json", 'w') as fp:
        fp.write(current_config)
        logger.info("Updated whole config for wifi settings")

    time.sleep(1)
    machine.reset()


def handle_wifi_configuration(configuration):
    logger.info("Handling as WIFI reconfiguration: " + str(configuration))
    config = parse_wifi_configuration(configuration)
    validate_wifi_configuration(config)
    save_wifi_configuration(config)


def handle_code_scan(code):
    logger.info("Handling as scanned code: " + str(code))
    token = get_oauth_token()

    response = post_code(code, token)
    logger.debug(ujson.dumps(response.json()))

    return True


def the_loop(uart, time):
    if uart.any():
        try:
            value = uart.read().decode("utf-8").strip()

            logger.debug("Scanned: '" + value + "'")

            if is_wifi_configuration(value):
                handle_wifi_configuration(value)

            else:
                handle_code_scan(value)

        except OSError as e:
            logger.warn("Got an OSError in the_loop")
            logger.info(str(e))

    time.sleep_ms(1000)


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

can_talk_to_reporter()

i = 0
while True:
    the_loop(uart, time)

    if i % 3600 == 0:
        i = 0
        if not can_talk_to_reporter():
            print("Stop and restart it again, maybe it'll fix internet issues")
            machine.reset()

    if i % 300 == 0:
        OTA.update()

    i = i + 1
